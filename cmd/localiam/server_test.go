// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
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

// AWS's published SigV4 example credentials — never anything real.
const (
	testAccessKey = "AKIDEXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	testRegion    = "us-east-1"
	testGroup     = "localiam-redis"
	testUser      = "localiam-iam"
)

func elastiCacheToken(t *testing.T) string {
	t.Helper()
	q := url.Values{"Action": {"connect"}, "User": {testUser}, "X-Amz-Expires": {"900"}}
	u := url.URL{Scheme: "https", Host: testGroup, Path: "/", RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	signed, _, err := v4.NewSigner().PresignHTTP(context.Background(),
		aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
		req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"elasticache", testRegion, time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("presigning: %v", err)
	}
	return strings.TrimPrefix(signed, "https://")
}

// TestServerHostedProxiesApplyPolicy pins the bug where a proxy hosted inside
// `localiam server` (-redis-proxy-listen and friends) verified tokens directly
// against the credential store and never consulted the service's spec: a
// service with no elastiCache grant could still authenticate to Redis, as long
// as the proxy ran in-process rather than as a `localiam proxy` sidecar.
func TestServerHostedProxiesApplyPolicy(t *testing.T) {
	t.Parallel()

	store := verify.NewStore()
	store.Add(verify.Principal{
		AccessKeyID: testAccessKey, SecretKey: testSecretKey,
		ARN: "arn:aws:iam::000000000000:role/api", Service: "api",
	})

	tests := []struct {
		name    string
		spec    *policy.Spec
		wantErr string
	}{
		{
			name: "a spec granting elastiCache is accepted",
			spec: &policy.Spec{PodIdentity: &policy.PodIdentity{Permissions: &policy.Permissions{ElastiCache: true}}},
		},
		{
			name:    "a spec without elastiCache is refused",
			spec:    &policy.Spec{PodIdentity: &policy.PodIdentity{Permissions: &policy.Permissions{}}},
			wantErr: "api is authenticated but not permitted",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, err := server.New(server.Options{
				Store:  store,
				Specs:  map[string]*policy.Spec{"api": tc.spec},
				Region: testRegion,
				Token:  "t",
			})
			if err != nil {
				t.Fatalf("server.New: %v", err)
			}

			id, err := localVerifier{srv: srv}.VerifyElastiCache(
				context.Background(), elastiCacheToken(t), testGroup, testUser,
			)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				if id.Service != "api" {
					t.Errorf("Service = %q, want api", id.Service)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
		})
	}
}
