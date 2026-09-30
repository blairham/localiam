// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"

	"github.com/blairham/localiam/verify"
)

// TestRDSAcceptsTheRealSignersToken mints through
// aws-sdk-go-v2/feature/rds/auth — the function pgx actually calls in
// production — rather than through the generic presigner.
//
// 🚨 This is the test that caught the parser rejecting every Go service's
// token. The RDS signer emits `host:port?Action=...` with NO "/" before the
// query, while the C# and Node minters emit `host:port/?Action=...`. The
// original cross-check presigned through the GENERIC signer, which produces the
// slash form, so it was green while the shape real services actually send was
// rejected outright.
//
// The lesson generalizes: cross-check against the exact function real services
// calls, not a cousin of it that happens to sign the same request.
func TestRDSAcceptsTheRealSignersToken(t *testing.T) {
	t.Parallel()
	const host, port, dbUser = "postgres", 5432, "app"

	provider := credentials.NewStaticCredentialsProvider(testAccessKey, testSecretKey, "")
	token, err := auth.BuildAuthToken(
		context.Background(), "postgres:5432", testRegion, dbUser, provider,
	)
	if err != nil {
		t.Fatalf("BuildAuthToken: %v", err)
	}
	if strings.Contains(token, "/?") {
		t.Fatalf("expected the slash-less RDS form, got %q", token)
	}

	res, err := verify.RDS(token, host, port, dbUser, testRegion, testStore(t), time.Now().UTC())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Principal != testARN {
		t.Errorf("Principal = %q", res.Principal)
	}
}

// TestBothTokenShapesParse pins the two formats explicitly, so a future
// "simplification" of the parser fails here with an obvious message rather than
// silently locking out half the clients.
func TestBothTokenShapesParse(t *testing.T) {
	t.Parallel()
	const query = "Action=connect&X-Amz-Signature=abc"

	tests := []struct {
		name  string
		token string
	}{
		{name: "the slash-less RDS-signer form", token: "postgres:5432?" + query},
		{name: "the C#/Node path form", token: "postgres:5432/?" + query},
		{name: "with a scheme", token: "https://postgres:5432/?" + query},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := verify.ParsePresigned(tc.token)
			if err != nil {
				t.Fatalf("ParsePresigned: %v", err)
			}
			if p.Host != "postgres:5432" {
				t.Errorf("Host = %q", p.Host)
			}
			// The signed canonical path is "/" whichever way the token was
			// formatted — the minters sign the same request and differ only in
			// how they render it.
			if p.Path != "/" {
				t.Errorf("Path = %q, want /", p.Path)
			}
			if p.Signature != "abc" {
				t.Errorf("Signature = %q", p.Signature)
			}
		})
	}
}
