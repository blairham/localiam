// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/blairham/localiam/verify"
)

// elastiCacheTokenExpiring presigns like elastiCacheToken, but with the
// X-Amz-Expires a caller chooses — the field is part of the signed query, so it
// has to be set before signing rather than edited into a token afterwards.
func elastiCacheTokenExpiring(t *testing.T, expires string, at time.Time) string {
	t.Helper()
	q := url.Values{"Action": {"connect"}, "User": {cacheUser}, "X-Amz-Expires": {expires}}
	u := url.URL{Scheme: "https", Host: cacheGroup, Path: "/", RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	creds := aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}
	signed, _, err := v4.NewSigner().PresignHTTP(
		context.Background(), creds, req, emptyPayloadHash, "elasticache", testRegion, at,
	)
	if err != nil {
		t.Fatalf("presigning: %v", err)
	}
	return strings.TrimPrefix(signed, "https://")
}

// TestAFractionalExpiresIsAWindowNotAMalformedToken pins what the Node MSK
// signer actually sends: a lifetime capped at the credential's remaining life,
// with a fraction. It must verify inside its window and expire at the WHOLE
// second below it — rounding up would let a token outlive what it was signed for.
func TestAFractionalExpiresIsAWindowNotAMalformedToken(t *testing.T) {
	t.Parallel()
	token := elastiCacheTokenExpiring(t, "869.667", frozen)

	res, err := verify.ElastiCache(token, cacheGroup, cacheUser, testRegion, testStore(t), frozen.Add(14*time.Minute))
	if err != nil {
		t.Fatalf("a fractional X-Amz-Expires inside its window was rejected: %v", err)
	}
	if got, want := res.ExpiresAt, frozen.Add(869*time.Second); !got.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v (869.667 rounded DOWN)", got, want)
	}

	_, err = verify.ElastiCache(
		token,
		cacheGroup,
		cacheUser,
		testRegion,
		testStore(t),
		frozen.Add(869*time.Second+time.Millisecond),
	)
	if !errors.Is(err, verify.ErrExpired) {
		t.Fatalf("past the rounded-down window: got %v, want ErrExpired", err)
	}
}

// TestANonsenseExpiresIsStillMalformed keeps the parser honest: accepting a
// fraction must not accept everything ParseFloat does.
func TestANonsenseExpiresIsStillMalformed(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"0", "-5", "0.5", "NaN", "Inf", "1e99", "abc", ""} {
		token := elastiCacheTokenExpiring(t, v, frozen)
		_, err := verify.ElastiCache(token, cacheGroup, cacheUser, testRegion, testStore(t), frozen.Add(time.Second))
		if !errors.Is(err, verify.ErrMalformed) {
			t.Errorf("X-Amz-Expires=%q: got %v, want ErrMalformed", v, err)
		}
	}
}
