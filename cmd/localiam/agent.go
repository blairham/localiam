// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/blairham/localiam/internal/issuer"
	"github.com/blairham/localiam/internal/server"
	"github.com/blairham/localiam/verify"
)

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	var (
		listen = fs.String("listen", "127.0.0.1:1338",
			"address to serve the Pod Identity contract on; MUST be loopback — the AWS SDK "+
				"refuses AWS_CONTAINER_CREDENTIALS_FULL_URI over plain http anywhere else")
		service   = fs.String("service", "", "workload name, e.g. api (required)")
		roleARN   = fs.String("role-arn", "", "role the issued credentials authenticate as (required)")
		accountID = fs.String("account-id", "000000000000", "account id echoed to the SDK")
		ttl       = fs.Duration("ttl", issuer.DefaultTTL,
			"credential lifetime; shortening this compresses the mint-once-never-refresh bug window")
		tokenFile   = fs.String("token-file", "", "file whose contents the Authorization header must match")
		registerURL = fs.String("register", envOr("LOCALIAM_REGISTER_URL", ""),
			"central localiam server base URL to push issued credentials to (env: LOCALIAM_REGISTER_URL)")
		registerToken = fs.String("register-token", envOr("LOCALIAM_REGISTER_TOKEN", ""),
			"bearer token for the central server (env: LOCALIAM_REGISTER_TOKEN)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *service == "" || *roleARN == "" {
		return errors.New("agent: -service and -role-arn are required")
	}

	expected := ""
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("agent: reading token file: %w", err)
		}
		expected = string(bytes.TrimSpace(raw))
	}

	store := verify.NewStore()
	opts := issuer.Options{
		Identity: issuer.Identity{
			Service:   *service,
			RoleARN:   *roleARN,
			AccountID: *accountID,
		},
		Store:         store,
		TTL:           *ttl,
		ExpectedToken: expected,
	}
	if *registerURL != "" {
		opts.OnIssue = registrar(*registerURL, *registerToken)
	}

	agent, err := issuer.New(opts)
	if err != nil {
		return err
	}

	slog.Info("localiam agent listening",
		"addr", *listen, "service", *service, "roleArn", *roleARN, "ttl", ttl.String(),
		"registerTo", *registerURL,
		"fullUri", "http://"+*listen+issuer.CredentialsPath,
	)
	return serve(*listen, agent)
}

// registrar pushes each freshly minted credential to the central server. An
// error fails the credential request on purpose: handing a workload a
// credential the verifier has never heard of turns into an unexplainable
// signature rejection at the store minutes later.
func registrar(baseURL, token string) func(verify.Principal) error {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(p verify.Principal) error {
		body, err := json.Marshal(server.RegisterRequest{Principal: p})
		if err != nil {
			return fmt.Errorf("marshaling principal: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(
			ctx, http.MethodPost, baseURL+server.PathRegister, bytes.NewReader(body),
		)
		if err != nil {
			return fmt.Errorf("building register request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("registering credential: %w", err)
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				slog.Warn("localiam: closing register response", "error", closeErr)
			}
		}()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("registering credential: server said %s", resp.Status)
		}
		return nil
	}
}
