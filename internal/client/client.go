// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Package client verifies tokens against a REMOTE localiam server.
//
// # Why this exists
//
// The credential store has to be central — agents issue credentials per pod,
// but tokens are presented at the shared stores, so one Kafka broker sees
// tokens signed by every pod's agent. The auth TERMINATORS, though, belong in
// the store's own pod: co-located, the plaintext hop from proxy to backend is
// over loopback inside the pod and never touches the network, so the backend
// can bind 127.0.0.1 and the proxy becomes the only way in.
//
// That split is what this package serves. A proxy sidecar holds no credentials
// and no secret keys; it asks the central server whether a presented token is
// good, and the server is the only component that can answer.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/blairham/localiam/internal/proxy"
	"github.com/blairham/localiam/internal/server"
)

// DefaultTimeout bounds a verification call. It sits on the connection path for
// every new client connection, so it is short: a hung verifier should refuse
// connections quickly rather than making every client hang with it.
const DefaultTimeout = 5 * time.Second

// Verifier implements proxy's three Verifier interfaces over HTTP.
type Verifier struct {
	http    *http.Client
	baseURL string
}

// New builds a Verifier pointed at a localiam server's base URL.
func New(baseURL string) *Verifier {
	return &Verifier{
		baseURL: baseURL,
		http:    &http.Client{Timeout: DefaultTimeout},
	}
}

// VerifyRDS implements proxy.PostgresVerifier.
func (v *Verifier) VerifyRDS(
	ctx context.Context, token, host string, port int, dbUser string,
) (proxy.Identity, error) {
	return v.call(ctx, "rds", server.VerifyRequest{
		Token: token, Host: host, Port: port, DBUser: dbUser,
	})
}

// VerifyMSK implements proxy.KafkaVerifier.
func (v *Verifier) VerifyMSK(
	ctx context.Context, mechanism string, payload []byte, signedHost string,
) (proxy.Identity, error) {
	return v.call(ctx, "msk", server.VerifyRequest{
		Token: string(payload), Mechanism: mechanism, Host: signedHost,
	})
}

// VerifyElastiCache implements proxy.Verifier.
func (v *Verifier) VerifyElastiCache(
	ctx context.Context, token, replicationGroupID, user string,
) (proxy.Identity, error) {
	return v.call(ctx, "elasticache", server.VerifyRequest{
		Token: token, Group: replicationGroupID, User: user,
	})
}

func (v *Verifier) call(
	ctx context.Context, kind string, req server.VerifyRequest,
) (proxy.Identity, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return proxy.Identity{}, fmt.Errorf("localiam client: marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost, v.baseURL+server.PathVerify+kind, bytes.NewReader(body),
	)
	if err != nil {
		return proxy.Identity{}, fmt.Errorf("localiam client: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := v.http.Do(httpReq)
	if err != nil {
		// A verifier the proxy cannot reach must DENY, never allow. Failing open
		// here would turn one unreachable pod into a cluster with no authentication
		// at all, which is worse than a cluster that refuses connections loudly.
		return proxy.Identity{}, fmt.Errorf("localiam client: verifier unreachable: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("localiam client: closing response", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return proxy.Identity{}, fmt.Errorf("localiam client: verifier returned %s", resp.Status)
	}

	var out server.VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return proxy.Identity{}, fmt.Errorf("localiam client: decoding response: %w", err)
	}
	if !out.OK {
		// The server's reason is carried through verbatim so the proxy's log
		// line still says WHY — expired, forged, or minted for someone else.
		return proxy.Identity{}, errors.New(out.Error)
	}

	return proxy.Identity{
		Service:     out.Service,
		Principal:   out.Principal,
		AccessKeyID: out.AccessKeyID,
		ExpiresAt:   out.ExpiresAt,
	}, nil
}

// AuthorizeKafka asks the remote server one per-operation Kafka policy
// question (POST /v1/authorize), so a `localiam proxy` sidecar enforces the
// same per-topic, group and transactional-id grants as the server.
func (v *Verifier) AuthorizeKafka(ctx context.Context, service, action, resource string) (bool, error) {
	body, err := json.Marshal(server.AuthorizeRequest{Service: service, Action: action, Resource: resource})
	if err != nil {
		return false, fmt.Errorf("localiam client: marshaling request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL+server.PathAuthorize, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("localiam client: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		// Fail closed: an unreachable server must deny, never allow.
		return false, fmt.Errorf("localiam client: authorizer unreachable: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("localiam client: closing response", "error", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("localiam client: authorizer returned %s", resp.Status)
	}
	var out struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("localiam client: decoding response: %w", err)
	}
	return out.Allowed, nil
}
