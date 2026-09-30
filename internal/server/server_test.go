// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/blairham/localiam/internal/policy"
	"github.com/blairham/localiam/internal/server"
	"github.com/blairham/localiam/verify"
)

const (
	accessKey  = "AKIDEXAMPLE"
	secretKey  = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	region     = "us-east-1"
	cacheGroup = "localiam-redis"
	cacheUser  = "localiam-iam"
	regToken   = "test-registration-token"

	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// apiSpec mirrors testdata/api.yaml: elastiCache on, MSK
// cluster plus a topic list, and deliberately NO rds block.
func apiSpec() map[string]*policy.Spec {
	return map[string]*policy.Spec{
		"api": {
			Name: "api",
			PodIdentity: &policy.PodIdentity{
				Permissions: &policy.Permissions{
					ElastiCache: true,
					MSK: &policy.MSK{
						Cluster: true,
						Topics:  []string{"requests"},
						Groups:  []string{"api-*"},
					},
				},
			},
		},
	}
}

func harness(t *testing.T, specs map[string]*policy.Spec) string {
	t.Helper()
	srv, err := server.New(server.Options{
		Store: verify.NewStore(), Specs: specs, Token: regToken, Region: region,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts.URL
}

func post(t *testing.T, url, token string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func registerAPI(t *testing.T, base string) {
	t.Helper()
	status, _ := post(t, base+server.PathRegister, regToken, server.RegisterRequest{
		Principal: verify.Principal{
			AccessKeyID: accessKey,
			SecretKey:   secretKey,
			Service:     "api",
			ARN:         "arn:aws:iam::000000000000:role/api",
			Expiration:  time.Now().UTC().Add(time.Hour),
		},
	})
	if status != http.StatusOK {
		t.Fatalf("register: status %d", status)
	}
}

func elastiCacheToken(t *testing.T, user string) string {
	t.Helper()
	q := url.Values{"Action": {"connect"}, "User": {user}, "X-Amz-Expires": {"900"}}
	u := url.URL{Scheme: "https", Host: cacheGroup, Path: "/", RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	signed, _, err := v4.NewSigner().PresignHTTP(
		context.Background(), creds, req, emptyPayloadHash, "elasticache", region, time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("presigning: %v", err)
	}
	return strings.TrimPrefix(signed, "https://")
}

// TestRegisterThenVerify is the sidecar-to-adapter path: an agent pushes a
// credential it minted, and an adapter later verifies a token signed with it.
func TestRegisterThenVerify(t *testing.T) {
	t.Parallel()
	base := harness(t, apiSpec())
	registerAPI(t, base)

	status, body := post(t, base+server.PathVerify+"elasticache", "", server.VerifyRequest{
		Token: elastiCacheToken(t, cacheUser), Group: cacheGroup, User: cacheUser,
	})
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("verification denied: %v", body["error"])
	}
	if body["service"] != "api" {
		t.Errorf("service = %v", body["service"])
	}
}

// TestAnAuthenticatedIdentityCanStillBeDenied is the wholesale-role-swap
// shape at the API boundary: the token is perfectly valid and the caller is
// exactly who it claims to be, but the service spec never declared the grant.
// Authentication and authorization are different answers and the API has to be
// able to say so.
func TestAnAuthenticatedIdentityCanStillBeDenied(t *testing.T) {
	t.Parallel()
	specs := apiSpec() // api declares elastiCache + msk, but no rds
	base := harness(t, specs)
	registerAPI(t, base)

	status, body := post(t, base+server.PathVerify+"rds", "", server.VerifyRequest{
		Token:  elastiCacheToken(t, cacheUser), // shape is irrelevant; policy denies first
		Host:   "postgres",
		Port:   5432,
		DBUser: "app",
	})
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if ok, _ := body["ok"].(bool); ok {
		t.Fatal("an undeclared rds grant was allowed")
	}
}

func TestAuthorizeAnswersPerResource(t *testing.T) {
	t.Parallel()
	base := harness(t, apiSpec())

	tests := []struct {
		action   string
		resource string
		want     bool
	}{
		{action: "Connect", resource: "", want: true},
		{action: "WriteData", resource: "requests", want: true},
		{action: "ReadData", resource: "requests", want: true},
		{action: "WriteData", resource: "not-granted", want: false},
		{action: "Group", resource: "api-consumers-1", want: true},
		{action: "Group", resource: "someone-elses-group", want: false},
		// cluster: true must not imply a transactional id grant.
		{action: "TransactionalId", resource: "api-txn-1", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.action+"/"+tc.resource, func(t *testing.T) {
			t.Parallel()
			_, body := post(t, base+server.PathAuthorize, "", server.AuthorizeRequest{
				Service: "api", Action: tc.action, Resource: tc.resource,
			})
			if got, _ := body["allowed"].(bool); got != tc.want {
				t.Errorf("allowed = %v, want %v (%v)", got, tc.want, body["reason"])
			}
		})
	}
}

func TestRegistrationRequiresTheToken(t *testing.T) {
	t.Parallel()
	base := harness(t, apiSpec())

	status, _ := post(t, base+server.PathRegister, "wrong-token", server.RegisterRequest{
		Principal: verify.Principal{AccessKeyID: accessKey, SecretKey: secretKey},
	})
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
}

// TestAnUnregisteredCredentialIsRejected proves the store is the authority: a
// perfectly well-formed token signed by a key nobody issued must fail.
func TestAnUnregisteredCredentialIsRejected(t *testing.T) {
	t.Parallel()
	base := harness(t, apiSpec())
	// Deliberately no registerAPI.

	_, body := post(t, base+server.PathVerify+"elasticache", "", server.VerifyRequest{
		Token: elastiCacheToken(t, cacheUser), Group: cacheGroup, User: cacheUser,
	})
	if ok, _ := body["ok"].(bool); ok {
		t.Fatal("a token from an unissued credential was accepted")
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "unknown access key") {
		t.Errorf("error = %q, want an unknown-access-key rejection", msg)
	}
}

// TestAnEmptyRegistrationTokenIsRefused pins the fail-closed default: a server
// with no registration token would let anyone who can reach it plant
// credentials that then verify, so it refuses to start unless open
// registration is asked for by name.
func TestAnEmptyRegistrationTokenIsRefused(t *testing.T) {
	t.Parallel()
	opts := server.Options{Store: verify.NewStore(), Region: region}
	if _, err := server.New(opts); err == nil {
		t.Fatal("server.New accepted an empty registration token")
	}
	opts.OpenRegistration = true
	if _, err := server.New(opts); err != nil {
		t.Fatalf("server.New refused OpenRegistration: %v", err)
	}
}
