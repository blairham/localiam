// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"testing"
	"time"

	"github.com/blairham/localiam/verify"
)

// The seeds are real token shapes, so the fuzzer starts from inputs that reach
// deep into the parsers rather than failing on the first byte.
var tokenSeeds = []string{
	"localiam-redis/?Action=connect&User=localiam-iam&X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIDEXAMPLE%2F20260917%2Fus-east-1%2Felasticache%2Faws4_request" +
		"&X-Amz-Date=20260917T120000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef",
	"postgres:5432?Action=connect&DBUser=app&X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIDEXAMPLE%2F20260917%2Fus-east-1%2Frds-db%2Faws4_request" +
		"&X-Amz-Date=20260917T120000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef",
	"https://kafka.us-east-1.amazonaws.com/?Action=kafka-cluster%3AConnect&X-Amz-Algorithm=AWS4-HMAC-SHA256",
	"", "?", "/", "host/?", "://", "%zz",
}

// FuzzParsePresigned: no input may panic the parser, and a successful parse
// must have found what every later check depends on.
func FuzzParsePresigned(f *testing.F) {
	for _, s := range tokenSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := verify.ParsePresigned(raw)
		if err != nil {
			return
		}
		if p.Host == "" || p.Signature == "" {
			t.Fatalf("parsed %q with Host=%q Signature=%q", raw, p.Host, p.Signature)
		}
	})
}

// FuzzNothingVerifiesAgainstAnEmptyStore is the security invariant: with no
// credentials registered there is no key to sign with, so no token of any
// shape may ever verify. An input that does is a path that skipped the key
// lookup or the signature check.
func FuzzNothingVerifiesAgainstAnEmptyStore(f *testing.F) {
	for _, s := range tokenSeeds {
		f.Add(s)
	}
	f.Add(`{"version":"2020_10_22","host":"kafka.us-east-1.amazonaws.com","action":"kafka-cluster:Connect"}`)

	store := verify.NewStore()
	now := time.Date(2026, 9, 17, 12, 1, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, token string) {
		if _, err := verify.ElastiCache(token, "localiam-redis", "localiam-iam", "us-east-1", store, now); err == nil {
			t.Fatalf("ElastiCache accepted %q against an empty store", token)
		}
		if _, err := verify.RDS(token, "postgres", 5432, "app", "us-east-1", store, now); err == nil {
			t.Fatalf("RDS accepted %q against an empty store", token)
		}
		if _, err := verify.MSKOAuthBearer(token, "us-east-1", "", store, now); err == nil {
			t.Fatalf("MSKOAuthBearer accepted %q against an empty store", token)
		}
		if _, err := verify.MSKAWSMSKIAM([]byte(token), "us-east-1", "", store, now); err == nil {
			t.Fatalf("MSKAWSMSKIAM accepted %q against an empty store", token)
		}
	})
}
