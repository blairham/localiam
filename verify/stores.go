// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ── ElastiCache ─────────────────────────────────────────────────────────────

// ElastiCache verifies the token a client presents as its Redis AUTH password.
//
// The token is a presigned GET of the `connect` action signed against the
// REPLICATION GROUP ID as its host — not a hostname — so replicationGroupID
// here is the same string the cluster configures the client with
// (Redis:ReplicationGroupId in .NET, Config.ReplicationGroupID in go-redis).
//
// user is the ElastiCache IAM user the token names; it must match the username
// the client sent on the AUTH command, which the adapter passes in. Without
// that cross-check a token minted for one user would authenticate another.
func ElastiCache(token, replicationGroupID, user, region string, store *Store, now time.Time) (Result, error) {
	p, err := ParsePresigned(token)
	if err != nil {
		return Result{}, err
	}
	if got := p.Query.Get("User"); got != user {
		return Result{}, fmt.Errorf("%w: token is for user %q, AUTH named %q", ErrWrongAction, got, user)
	}
	return Verify(p, Expectation{
		Service: "elasticache",
		Region:  region,
		Action:  "connect",
		Host:    replicationGroupID,
	}, store, now)
}

// ── RDS ─────────────────────────────────────────────────────────────────────

// RDS verifies the token a client presents as its Postgres password.
//
// The signed host is "hostname:port", so the adapter must pass the endpoint
// exactly as the client was configured with it. dbUser must match the Postgres
// user in the startup message.
func RDS(token, hostname string, port int, dbUser, region string, store *Store, now time.Time) (Result, error) {
	p, err := ParsePresigned(token)
	if err != nil {
		return Result{}, err
	}
	if got := p.Query.Get("DBUser"); got != dbUser {
		return Result{}, fmt.Errorf("%w: token is for DBUser %q, startup named %q", ErrWrongAction, got, dbUser)
	}
	return Verify(p, Expectation{
		Service: "rds-db",
		Region:  region,
		Action:  "connect",
		Host:    fmt.Sprintf("%s:%d", hostname, port),
	}, store, now)
}

// ── MSK ─────────────────────────────────────────────────────────────────────

// MSKAction is the action an MSK connect token names.
const MSKAction = "kafka-cluster:Connect"

// MSKHost returns the region-wide endpoint MSK tokens are signed against in
// AWS. It is not per-cluster, so unlike ElastiCache and RDS the host check
// cannot bind a token to a particular broker — only to a region.
//
// ⚠ It is the DEFAULT, not the rule. A client signs against the broker host it
// actually dialed, which in AWS is this endpoint and in a cluster is the cluster's own
// broker service. Hardcoding it rejected every in-cluster token with `unexpected host:
// signed against "kafka.kafka.svc.cluster.local"` — so callers pass the host
// they expect and this fills in only when they pass none.
func MSKHost(region string) string { return "kafka." + region + ".amazonaws.com" }

// mskHostOr resolves the expected signed host.
func mskHostOr(host, region string) string {
	if host == "" {
		return MSKHost(region)
	}
	return host
}

// MSKOAuthBearer verifies the token carried by the SASL/OAUTHBEARER mechanism —
// what Confluent.Kafka (.NET, via AWS.MSK.Auth) and the librdkafka-based clients
// send. The bearer token is the full presigned URL, base64url-encoded without
// padding.
func MSKOAuthBearer(token, region, signedHost string, store *Store, now time.Time) (Result, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
	if err != nil {
		return Result{}, fmt.Errorf("%w: base64url: %w", ErrMalformed, err)
	}
	p, err := ParsePresigned(string(raw))
	if err != nil {
		return Result{}, err
	}
	// ⚠ User-Agent is appended AFTER signing, exactly as in the AWS_MSK_IAM
	// envelope — aws-msk-iam-sasl-signer-py/-js build the presigned URL and then
	// tack `User-Agent=` on. Leaving it in the canonical query makes EVERY
	// librdkafka client fail with a signature mismatch and nothing else to go on.
	// The JSON path already knew this (see mskJSONToCanonical); the URL path did
	// not, because no cross-check minted a token through those signers.
	p.Query.Del(paramUserAgent)
	// ⚠ BOTH hosts are accepted here and that is not laxity: the librdkafka
	// signers sign the regional endpoint unconditionally, so a cluster that only
	// expected its own broker address rejected every Python and Node client
	// while franz-go sailed through. See Expectation.AltHost.
	return Verify(p, Expectation{
		Service: "kafka-cluster",
		Region:  region,
		Action:  MSKAction,
		Host:    mskHostOr(signedHost, region),
		AltHost: MSKHost(region),
	}, store, now)
}

// mskJSONToCanonical maps the lowercased JSON field names of the AWS_MSK_IAM
// payload back to the canonically-cased query parameters the signature was
// computed over.
//
// ⚠ This mapping is a reconstruction, not a spec reading: the AWS_MSK_IAM
// envelope lowercases every key, so the only way to know the restored casing is
// right is that a payload produced by a real third-party client verifies. That
// is what TestMSKAWSMSKIAMCrossCheck pins. Do not "tidy" this table without
// re-running that test — a wrong case here produces a signature mismatch on
// every connection, with no other symptom.
//
// "user-agent" is deliberately ABSENT. It travels in the payload but is added
// AFTER signing (the Java aws-msk-iam-auth behavior franz-go reproduces), so
// folding it into the canonical query makes every signature mismatch. That was
// this verifier's first wrong guess, and the cross-check is what caught it.
var mskJSONToCanonical = map[string]string{
	"action":               paramAction,
	"x-amz-algorithm":      paramAlgorithm,
	"x-amz-credential":     paramCredential,
	"x-amz-date":           paramDate,
	"x-amz-expires":        paramExpires,
	"x-amz-security-token": paramSecurityToken,
	"x-amz-signedheaders":  paramSignedHeaders,
}

// MSKAWSMSKIAM verifies the payload carried by the AWS_MSK_IAM SASL mechanism —
// what franz-go's aws.ManagedStreamingIAM sends, and therefore what every Go
// service in the wild (franz-go) presents.
//
// Real clients use BOTH MSK mechanisms: Go via franz-go speaks AWS_MSK_IAM, .NET
// via Confluent.Kafka speaks OAUTHBEARER. They carry the same SigV4 signature
// in different envelopes, so a broker adapter has to accept both or it will
// lock out half the services.
func MSKAWSMSKIAM(payload []byte, region, signedHost string, store *Store, now time.Time) (Result, error) {
	var fields map[string]string
	if err := json.Unmarshal(payload, &fields); err != nil {
		return Result{}, fmt.Errorf("%w: AWS_MSK_IAM payload: %w", ErrMalformed, err)
	}

	host, ok := fields["host"]
	if !ok {
		return Result{}, fmt.Errorf("%w: AWS_MSK_IAM payload has no host", ErrMalformed)
	}
	sig, ok := fields["x-amz-signature"]
	if !ok {
		return Result{}, fmt.Errorf("%w: AWS_MSK_IAM payload has no x-amz-signature", ErrMalformed)
	}

	q := url.Values{}
	for k, v := range fields {
		switch k {
		case "version", "host", "x-amz-signature", "user-agent":
			// Envelope framing and the post-signature user-agent, none of which
			// are part of the canonical query the signature covers.
			continue
		}
		canonical, known := mskJSONToCanonical[k]
		if !known {
			return Result{}, fmt.Errorf("%w: unknown AWS_MSK_IAM field %q", ErrMalformed, k)
		}
		q.Set(canonical, v)
	}

	p := Presigned{Host: host, Path: "/", Query: q, Signature: sig}
	// ⚠ BOTH hosts are accepted here and that is not laxity: the librdkafka
	// signers sign the regional endpoint unconditionally, so a cluster that only
	// expected its own broker address rejected every Python and Node client
	// while franz-go sailed through. See Expectation.AltHost.
	return Verify(p, Expectation{
		Service: "kafka-cluster",
		Region:  region,
		Action:  MSKAction,
		Host:    mskHostOr(signedHost, region),
		AltHost: MSKHost(region),
	}, store, now)
}
