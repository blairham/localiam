// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package issuer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"

	"github.com/blairham/localiam/internal/issuer"
	"github.com/blairham/localiam/verify"
)

const (
	testService = "api"
	testRoleARN = "arn:aws:iam::000000000000:role/api"
	testAccount = "000000000000"
	testToken   = "a-projected-service-account-token"
	testRegion  = "us-east-1"
	cacheGroup  = "localiam-redis"
	cacheUser   = "localiam-iam"
)

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// harness stands up an issuer over httptest and returns it with its store.
func harness(t *testing.T, ttl time.Duration, now func() time.Time) (*issuer.Server, *verify.Store, string) {
	t.Helper()
	store := verify.NewStore()
	srv, err := issuer.New(issuer.Options{
		Identity: issuer.Identity{
			Service:   testService,
			RoleARN:   testRoleARN,
			AccountID: testAccount,
		},
		Store:         store,
		TTL:           ttl,
		ExpectedToken: testToken,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("issuer.New: %v", err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return srv, store, ts.URL + issuer.CredentialsPath
}

// fetch retrieves credentials through the REAL aws-sdk-go-v2 container
// credentials provider — the same provider a pod uses when Pod Identity sets
// AWS_CONTAINER_CREDENTIALS_FULL_URI. If the JSON field names are wrong, this
// fails; a test that unmarshalled with the issuer's own struct could not tell.
func fetch(t *testing.T, endpoint string) aws.Credentials {
	t.Helper()
	provider := endpointcreds.New(endpoint, func(o *endpointcreds.Options) {
		o.AuthorizationToken = testToken
	})
	creds, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("SDK could not retrieve credentials: %v", err)
	}
	return creds
}

func TestTheSdkAcceptsOurWireShape(t *testing.T) {
	t.Parallel()
	_, _, endpoint := harness(t, issuer.DefaultTTL, nil)

	creds := fetch(t, endpoint)

	switch {
	case !strings.HasPrefix(creds.AccessKeyID, "ASIA"):
		t.Errorf("AccessKeyID = %q, want an ASIA-prefixed session key", creds.AccessKeyID)
	case creds.SecretAccessKey == "":
		t.Error("SecretAccessKey is empty")
	case creds.SessionToken == "":
		t.Error("SessionToken is empty")
	case !creds.CanExpire:
		// Without a parseable Expiration the SDK caches the credential as static
		// and never refreshes — which would hide the very bug class this exists
		// to expose.
		t.Error("SDK treated the credential as static; Expiration did not parse")
	}
}

// TestAnIssuedCredentialSignsATokenTheVerifierAccepts closes the whole loop:
// issue through the SDK, sign the way a service's own production code does,
// and verify. If any layer disagrees about the credential, this is what catches
// it.
func TestAnIssuedCredentialSignsATokenTheVerifierAccepts(t *testing.T) {
	t.Parallel()
	_, store, endpoint := harness(t, issuer.DefaultTTL, nil)

	creds := fetch(t, endpoint)
	now := time.Now().UTC()
	token := presignWith(t, creds, cacheGroup, "elasticache",
		url.Values{"Action": {"connect"}, "User": {cacheUser}}, now)

	res, err := verify.ElastiCache(token, cacheGroup, cacheUser, testRegion, store, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Principal != testRoleARN {
		t.Errorf("Principal = %q, want %q", res.Principal, testRoleARN)
	}
	if res.AccessKeyID != creds.AccessKeyID {
		t.Errorf("AccessKeyID = %q, want %q", res.AccessKeyID, creds.AccessKeyID)
	}
}

// TestALapsedCredentialStopsVerifying is the credential-level twin of the
// token-level expiry test in verify: a token can be well inside its own window
// and still be rejected because the CREDENTIAL that signed it has lapsed. AWS
// behaves this way, so a cluster that remembered issued keys forever would accept
// what production rejects.
func TestALapsedCredentialStopsVerifying(t *testing.T) {
	t.Parallel()
	issued := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	_, store, endpoint := harness(t, time.Minute, func() time.Time { return issued })

	creds := fetch(t, endpoint)
	// Sign right away — the token's own 15-minute window is wide open.
	token := presignWith(t, creds, cacheGroup, "elasticache",
		url.Values{"Action": {"connect"}, "User": {cacheUser}}, issued)

	// Two minutes later the one-minute credential has lapsed.
	_, err := verify.ElastiCache(token, cacheGroup, cacheUser, testRegion, store, issued.Add(2*time.Minute))
	if err == nil {
		t.Fatal("a token signed with a lapsed credential was accepted")
	}
	if !strings.Contains(err.Error(), "credential expired") {
		t.Fatalf("got %v, want a credential-expired rejection", err)
	}
}

func TestTheAgentContract(t *testing.T) {
	t.Parallel()
	_, _, endpoint := harness(t, issuer.DefaultTTL, nil)

	tests := []struct {
		name   string
		path   string
		method string
		token  string
		want   int
	}{
		{name: "a valid request", path: endpoint, method: http.MethodGet, token: testToken, want: http.StatusOK},
		{name: "no authorization token", path: endpoint, method: http.MethodGet, want: http.StatusUnauthorized},
		{name: "the wrong token", path: endpoint, method: http.MethodGet, token: "not-it", want: http.StatusUnauthorized},
		{
			name:   "a path the agent does not serve",
			path:   endpoint + "-nope",
			method: http.MethodGet,
			token:  testToken,
			want:   http.StatusNotFound,
		},
		{
			name:   "a write method",
			path:   endpoint,
			method: http.MethodPost,
			token:  testToken,
			want:   http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(context.Background(), tc.method, tc.path, http.NoBody)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			if tc.token != "" {
				req.Header.Set("Authorization", tc.token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// TestTheAgentServesOneStableCredentialThenRefreshes pins BOTH halves of the
// Pod Identity contract, which an earlier version got half right.
//
// It used to mint on every fetch, on the theory that fresh material is what the
// mint-once-never-refresh bug is about. It is not: that bug is a CLIENT holding one
// TOKEN past its window, and what catches it is the credential genuinely
// EXPIRING — asserted below — not the agent refusing to repeat itself.
//
// 🚨 Minting per fetch actively breaks clients. botocore's
// RefreshableCredentials re-reads the endpoint on every attribute access while
// inside its refresh windows, so `access_key`, `secret_key` and `token` came
// from three different credentials and every presigned URL was internally
// inconsistent — `session token mismatch` at the proxy, Python and Node locked
// out, Go unaffected because it snapshots once. The real agent is stable, so
// this is the faithful behavior as well as the working one.
func TestTheAgentServesOneStableCredentialThenRefreshes(t *testing.T) {
	t.Parallel()
	clock := time.Now().UTC()
	srv, store, endpoint := harness(t, issuer.DefaultTTL, func() time.Time { return clock })

	first := fetch(t, endpoint)
	second := fetch(t, endpoint)
	if first.AccessKeyID != second.AccessKeyID {
		t.Error("two fetches inside the window returned different access keys")
	}
	if got := srv.Issued(); got != 1 {
		t.Errorf("Issued() = %d, want 1 — the credential should be cached", got)
	}

	// Past the refresh margin the agent must produce NEW material, or a workload
	// would ride one credential to expiry and beyond.
	clock = clock.Add(issuer.DefaultTTL)
	third := fetch(t, endpoint)
	if third.AccessKeyID == first.AccessKeyID {
		t.Error("the agent replayed a credential that had reached expiry")
	}
	if store.Len() < 2 {
		t.Errorf("store holds %d credentials, want both mints", store.Len())
	}
}

func TestNewRejectsAnIncompleteIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts issuer.Options
	}{
		{name: "no store", opts: issuer.Options{Identity: issuer.Identity{Service: "x", RoleARN: "y"}}},
		{name: "no service", opts: issuer.Options{Store: verify.NewStore(), Identity: issuer.Identity{RoleARN: "y"}}},
		{name: "no role ARN", opts: issuer.Options{Store: verify.NewStore(), Identity: issuer.Identity{Service: "x"}}},
		{
			name: "a TTL below the floor",
			opts: issuer.Options{
				Store:    verify.NewStore(),
				Identity: issuer.Identity{Service: "x", RoleARN: "y"},
				TTL:      time.Second,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := issuer.New(tc.opts); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// presignWith mints a token the way a SERVICE does — through aws-sdk-go-v2's
// presigner, with credentials the issuer handed out.
func presignWith(
	t *testing.T, creds aws.Credentials, host, service string, extra url.Values, at time.Time,
) string {
	t.Helper()
	q := url.Values{"X-Amz-Expires": {"900"}}
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u := url.URL{Scheme: "https", Host: host, Path: "/", RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	signed, _, err := v4.NewSigner().PresignHTTP(
		context.Background(), creds, req, emptyPayloadHash, service, testRegion, at,
	)
	if err != nil {
		t.Fatalf("presigning: %v", err)
	}
	return strings.TrimPrefix(signed, "https://")
}
