// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	fraws "github.com/twmb/franz-go/pkg/sasl/aws"

	"github.com/blairham/localiam/verify"
)

// AWS's own published SigV4 test credentials. Public example values from the
// signing documentation — deliberately used instead of anything minted against
// a real account, so a golden vector can be committed without a secret in it.
const (
	testAccessKey = "AKIDEXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	testRegion    = "us-east-1"
	testARN       = "arn:aws:sts::000000000000:assumed-role/test/session"
)

// emptyPayloadHash duplicates the constant under test on purpose: a test that
// imports the value it is checking cannot catch the value being wrong.
const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// frozen is the signing instant every golden vector is pinned to.
var frozen = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

func testStore(t *testing.T) *verify.Store {
	t.Helper()
	s := verify.NewStore()
	s.Add(verify.Principal{AccessKeyID: testAccessKey, SecretKey: testSecretKey, ARN: testARN})
	return s
}

// presign mints a token the way real services do — through aws-sdk-go-v2's
// presigner, the same path go-redis and pgx take. This is what makes
// the test a cross-check rather than a tautology: the bytes under verification
// were produced by a third-party implementation, never by the verifier's own
// canonicalization.
func presign(t *testing.T, host, service string, extra url.Values, at time.Time) string {
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
	creds := aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}
	signed, _, err := v4.NewSigner().PresignHTTP(
		context.Background(), creds, req, emptyPayloadHash, service, testRegion, at,
	)
	if err != nil {
		t.Fatalf("presigning: %v", err)
	}
	return strings.TrimPrefix(signed, "https://")
}

func TestElastiCacheAcceptsASdkMintedToken(t *testing.T) {
	t.Parallel()
	const group, user = "localiam-redis", "localiam-iam"

	token := presign(t, group, "elasticache",
		url.Values{"Action": {"connect"}, "User": {user}}, frozen)

	res, err := verify.ElastiCache(token, group, user, testRegion, testStore(t), frozen.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.AccessKeyID != testAccessKey || res.Principal != testARN {
		t.Errorf("got %+v", res)
	}
	if want := frozen.Add(900 * time.Second); !res.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %s, want %s", res.ExpiresAt, want)
	}
	// Frozen signature for the pinned instant and the published test key. It
	// catches drift in EITHER implementation: a change in the verifier's
	// canonical form, or a change in what aws-sdk-go-v2 presigns.
	const golden = "f2772b320f822c514860d8731349b2f1d1baadd21d3413ee4e353769ed3ae566"
	if got := signatureOf(t, token); got != golden {
		t.Errorf("signature drifted:\n got  %s\n want %s", got, golden)
	}
}

func TestRDSAcceptsASdkMintedToken(t *testing.T) {
	t.Parallel()
	const host, port, dbUser = "postgres", 5432, "app"

	token := presign(t, host+":"+strconv.Itoa(port), "rds-db",
		url.Values{"Action": {"connect"}, "DBUser": {dbUser}}, frozen)

	res, err := verify.RDS(token, host, port, dbUser, testRegion, testStore(t), frozen.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Principal != testARN {
		t.Errorf("Principal = %q", res.Principal)
	}
	const golden = "c6c71f85625b1828cca2ee5d745755430eb5cd98e49247bcb8b043f8c79e3acf"
	if got := signatureOf(t, token); got != golden {
		t.Errorf("signature drifted:\n got  %s\n want %s", got, golden)
	}
}

func TestMSKOAuthBearerAcceptsASdkMintedToken(t *testing.T) {
	t.Parallel()
	raw := presign(t, verify.MSKHost(testRegion), "kafka-cluster",
		url.Values{"Action": {verify.MSKAction}}, frozen)
	token := base64.RawURLEncoding.EncodeToString([]byte("https://" + raw))

	res, err := verify.MSKOAuthBearer(token, testRegion, "", testStore(t), frozen.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Principal != testARN {
		t.Errorf("Principal = %q", res.Principal)
	}
}

// TestMSKOAuthBearerAcceptsTheRegionalEndpointOnAClusterBroker is a cluster
// failure made executable. A cluster fronts its OWN broker, so it passes that
// address as signedHost — but aws-msk-iam-sasl-signer-py/-js sign the REGIONAL
// endpoint unconditionally (ENDPOINT_URL_TEMPLATE), never the broker address.
// Before AltHost this rejected every Python and Node client on the cluster with
// `unexpected host`, while franz-go — which signs the address it dialed —
// passed, so the tests looked green for Go clients only.
func TestMSKOAuthBearerAcceptsTheRegionalEndpointOnAClusterBroker(t *testing.T) {
	t.Parallel()
	const clusterBroker = "kafka.kafka.svc.cluster.local"

	// Minted the way the librdkafka signers do it: against the regional
	// endpoint, with no knowledge of the broker the client will dial.
	raw := presign(t, verify.MSKHost(testRegion), "kafka-cluster",
		url.Values{"Action": {verify.MSKAction}}, frozen)
	token := base64.RawURLEncoding.EncodeToString([]byte("https://" + raw))

	res, err := verify.MSKOAuthBearer(token, testRegion, clusterBroker, testStore(t), frozen.Add(time.Minute))
	if err != nil {
		t.Fatalf("a regional-endpoint token was rejected by an in-cluster broker: %v", err)
	}
	if res.Principal != testARN {
		t.Errorf("Principal = %q", res.Principal)
	}
}

// TestMSKOAuthBearerToleratesThePostSigningUserAgent is the second half of the
// same cluster failure. aws-msk-iam-sasl-signer-py/-js presign the URL and
// then APPEND `User-Agent=` to it, so the parameter is in the token but was
// never in the canonical query. Folding it back in makes every librdkafka
// client fail with `signature mismatch` and no other clue — the exact trap
// mskJSONToCanonical documents for the AWS_MSK_IAM envelope, which the URL path
// did not account for because no cross-check went through those signers.
func TestMSKOAuthBearerToleratesThePostSigningUserAgent(t *testing.T) {
	t.Parallel()
	raw := presign(t, verify.MSKHost(testRegion), "kafka-cluster",
		url.Values{"Action": {verify.MSKAction}}, frozen)
	// Appended AFTER signing, exactly as the signers do it.
	raw += "&User-Agent=" + url.QueryEscape("aws-msk-iam-sasl-signer-python/1.0.0")
	token := base64.RawURLEncoding.EncodeToString([]byte("https://" + raw))

	res, err := verify.MSKOAuthBearer(token, testRegion, "", testStore(t), frozen.Add(time.Minute))
	if err != nil {
		t.Fatalf("a token carrying the signers' User-Agent was rejected: %v", err)
	}
	if res.Principal != testARN {
		t.Errorf("Principal = %q", res.Principal)
	}
}

// TestMSKOAuthBearerStillRejectsAnUnrelatedHost pins that AltHost widened the
// accepted set by exactly one known host and did not disable the check.
func TestMSKOAuthBearerStillRejectsAnUnrelatedHost(t *testing.T) {
	t.Parallel()
	raw := presign(t, "kafka.someone-elses-cluster.internal", "kafka-cluster",
		url.Values{"Action": {verify.MSKAction}}, frozen)
	token := base64.RawURLEncoding.EncodeToString([]byte("https://" + raw))

	_, err := verify.MSKOAuthBearer(token, testRegion, "kafka.kafka.svc.cluster.local",
		testStore(t), frozen.Add(time.Minute))
	if !errors.Is(err, verify.ErrWrongHost) {
		t.Fatalf("got %v, want ErrWrongHost", err)
	}
}

// TestMSKAWSMSKIAMCrossCheck is the pin for mskJSONToCanonical. The payload is
// produced by franz-go — an independent implementation of the AWS_MSK_IAM
// mechanism — so if the canonical-casing reconstruction is wrong, this fails.
//
// franz-go signs at time.Now() and does not accept an injected clock, so this
// verifies against the real current time rather than the frozen instant.
func TestMSKAWSMSKIAMCrossCheck(t *testing.T) {
	t.Parallel()
	mech := fraws.ManagedStreamingIAM(func(context.Context) (fraws.Auth, error) {
		return fraws.Auth{AccessKey: testAccessKey, SecretKey: testSecretKey}, nil
	})
	_, payload, err := mech.Authenticate(context.Background(), verify.MSKHost(testRegion)+":9098")
	if err != nil {
		t.Fatalf("franz-go authenticate: %v", err)
	}
	t.Logf("AWS_MSK_IAM payload: %s", payload)

	res, err := verify.MSKAWSMSKIAM(payload, testRegion, "", testStore(t), time.Now().UTC())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Principal != testARN {
		t.Errorf("Principal = %q", res.Principal)
	}
}

func signatureOf(t *testing.T, token string) string {
	t.Helper()
	p, err := verify.ParsePresigned(token)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	return p.Signature
}
