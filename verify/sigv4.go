// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Package verify validates the AWS SigV4-presigned tokens that services
// present as data-plane credentials: the ElastiCache `connect` token used as a
// Redis AUTH password, the RDS `connect` token used as a Postgres password, and
// the MSK `kafka-cluster:Connect` token carried by either of the two SASL
// mechanisms real clients use.
//
// # Why this exists
//
// Local environments run plaintext Redis/Postgres/Kafka, so every IAM auth
// path is exercised for the first time after deploy. The classic bug that hides
// there: a service mints its ElastiCache token once at startup and reuses it
// forever, so the first Redis reconnect past the 15-minute TTL re-auths with an
// expired token and gets WRONGPASS. A cluster that actually rejects a stale token
// catches that class before it ships.
//
// # The independence rule
//
// This is a DELIBERATELY INDEPENDENT implementation of SigV4 canonicalization.
// It must never import aws-sdk-go-v2, franz-go, or any other code that MINTS
// these tokens, and it must not be refactored to share a
// canonicalization helper with them. A verifier that shares its canonical form
// with the minter cannot detect a canonicalization bug — both sides would be
// wrong in the same way and the tests would go green. The only thing that makes
// this verifier worth running is that it derives the canonical form separately
// and is pinned to bytes produced by third-party implementations (see the
// cross-check vectors in sigv4_test.go).
package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Algorithm is the only signature algorithm AWS uses for these tokens.
const Algorithm = "AWS4-HMAC-SHA256"

// emptyPayloadHash is hex(sha256("")) — the payload hash for the bodyless GET
// that every one of these tokens is a presigned form of.
const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// DefaultSkew is how far a token's X-Amz-Date may sit in the future before it
// is rejected. Container clocks drift against the host's, and a container that boots
// slightly ahead would otherwise present a token that is not yet valid.
const DefaultSkew = 5 * time.Minute

// Signed-query parameter names. AWS treats these case-sensitively.
const (
	paramAlgorithm     = "X-Amz-Algorithm"
	paramCredential    = "X-Amz-Credential"
	paramDate          = "X-Amz-Date"
	paramExpires       = "X-Amz-Expires"
	paramSignedHeaders = "X-Amz-SignedHeaders"
	paramSignature     = "X-Amz-Signature"
	paramSecurityToken = "X-Amz-Security-Token"
	// paramUserAgent is never part of a signature: both MSK signer families add
	// it after signing. See MSKOAuthBearer and mskJSONToCanonical.
	paramUserAgent = "User-Agent"
	paramAction    = "Action"
)

// timeFormat is the ISO8601 basic form AWS signs with.
const timeFormat = "20060102T150405Z"

// dateFormat is the yyyyMMdd form used in the credential scope.
const dateFormat = "20060102"

// Common rejection reasons. They are distinct errors because the adapters map
// them onto very different protocol-level responses (a Redis WRONGPASS, a
// Postgres auth failure, a Kafka SaslAuthenticationFailed) and because the
// localiam's whole value is telling "expired" apart from "forged".
var (
	ErrMalformed       = errors.New("localiam: malformed token")
	ErrUnknownKey      = errors.New("localiam: unknown access key")
	ErrExpired         = errors.New("localiam: token expired")
	ErrNotYetValid     = errors.New("localiam: token not yet valid")
	ErrBadSignature    = errors.New("localiam: signature mismatch")
	ErrWrongScope      = errors.New("localiam: credential scope mismatch")
	ErrWrongAction     = errors.New("localiam: unexpected action")
	ErrWrongHost       = errors.New("localiam: unexpected host")
	ErrSessionMismatch = errors.New("localiam: session token mismatch")
	ErrCredExpired     = errors.New("localiam: credential expired")
)

// Presigned is a parsed presigned-GET token: the host it was signed against,
// its query parameters, and the signature lifted out of them.
//
// Path is always "/" for every token shape we verify, but it is carried
// explicitly rather than assumed so the canonical request is built from parsed
// input rather than from a constant the parser never checked.
type Presigned struct {
	Host      string
	Path      string
	Query     url.Values
	Signature string
}

// ParsePresigned parses the scheme-less presigned token real minters
// produce. It tolerates a scheme if one is present.
//
// 🚨 TWO SHAPES ARE IN THE WILD AND BOTH MUST PARSE.
//
//	postgres:5432?Action=connect&...    aws-sdk-go-v2 feature/rds/auth
//	postgres:5432/?Action=connect&...   hand-rolled C# minters, and the Node minters
//
// aws-sdk-go-v2's RDS signer omits the "/" before the query delimiter; the
// hand-rolled C# minters and the Node `${host}/?${params}` builders include it.
// Requiring the slash rejected every token minted by every Go service — a bug
// that survived the original cross-check because that test presigned through
// the GENERIC signer rather than the RDS one real services actually call.
//
// The signed canonical path is "/" in both cases: the minters sign a request
// whose path is "/" and only differ in how they format the result. So the path
// is normalized to "/" here rather than inferred from the token text.
//
// Parameter ORDER is likewise never load-bearing — hand-rolled C# minters append
// X-Amz-Signature last while the SDKs sort it in among the rest — so the
// signature is lifted out by name and the remainder re-sorted canonically.
func ParsePresigned(raw string) (Presigned, error) {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if s == "" {
		return Presigned{}, fmt.Errorf("%w: empty token", ErrMalformed)
	}

	// Split on whichever delimiter comes first. A "?" before any "/" is the
	// slash-less RDS form; a "/" first is the path form.
	var host, rawQuery string
	slash, question := strings.Index(s, "/"), strings.Index(s, "?")
	switch {
	case question >= 0 && (slash < 0 || question < slash):
		host, rawQuery = s[:question], s[question+1:]
	case slash >= 0:
		host = s[:slash]
		_, rawQuery, _ = strings.Cut(s[slash+1:], "?")
	default:
		return Presigned{}, fmt.Errorf("%w: no query in %q", ErrMalformed, raw)
	}
	if host == "" {
		return Presigned{}, fmt.Errorf("%w: empty host", ErrMalformed)
	}

	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return Presigned{}, fmt.Errorf("%w: query: %w", ErrMalformed, err)
	}

	sig := q.Get(paramSignature)
	if sig == "" {
		return Presigned{}, fmt.Errorf("%w: no %s", ErrMalformed, paramSignature)
	}
	q.Del(paramSignature)

	return Presigned{Host: host, Path: "/", Query: q, Signature: sig}, nil
}

// Expectation is what a caller demands of a token beyond it being correctly
// signed: which AWS service and region it must be scoped to, which action it
// must name, and which host it must have been signed against.
//
// Host is checked because the signature alone does not bind a token to THIS
// store — a token minted for a different replication group is still validly
// signed by the same principal. Leaving Host empty skips that check, which is
// only appropriate for MSK, where the signed host is a region-wide endpoint
// rather than a per-cluster one.
type Expectation struct {
	Service string
	Region  string
	Action  string
	Host    string
	// AltHost is a SECOND acceptable signed host, and it exists because the two
	// MSK IAM minters in the wild disagree about what they sign against.
	// franz-go signs the broker address it was handed; the librdkafka signers
	// (aws-msk-iam-sasl-signer-py and -js) hardcode the REGIONAL endpoint
	// (ENDPOINT_URL_TEMPLATE = "https://kafka.{}.amazonaws.com/") and never see
	// the broker address at all. A cluster fronting its own broker must accept both
	// or it locks out one set of clients. Empty means "no second host".
	AltHost string
}

// Result is what a successful verification learned about the caller.
// IssuedAt and ExpiresAt bound the token's validity window, so an adapter can
// log how much life a presented token had left — the direct signal for the
// mint-once-never-refresh bug class. Principal is the ARN the key maps to;
// Service is the workload name the policy layer keys on, so a verified token
// can be authorized without a second lookup.
//
// Field order is fieldalignment's, not ours — govet reorders this struct and
// strips per-field comments, hence the block above.
type Result struct {
	IssuedAt    time.Time
	ExpiresAt   time.Time
	AccessKeyID string
	Principal   string
	Service     string
}

// Verify checks a parsed token against an expectation and a principal store.
//
// The order of checks is deliberate: everything cheap and non-cryptographic
// runs first, so a malformed or expired token never reaches the HMAC path, and
// the signature comparison is last and constant-time.
func Verify(p Presigned, exp Expectation, store *Store, now time.Time) (Result, error) {
	if got := p.Query.Get(paramAlgorithm); got != Algorithm {
		return Result{}, fmt.Errorf("%w: algorithm %q", ErrMalformed, got)
	}

	if err := checkTarget(p, exp); err != nil {
		return Result{}, err
	}

	cred, err := parseCredential(p.Query.Get(paramCredential))
	if err != nil {
		return Result{}, err
	}
	if cred.Service != exp.Service || cred.Region != exp.Region {
		return Result{}, fmt.Errorf("%w: %s/%s, want %s/%s",
			ErrWrongScope, cred.Region, cred.Service, exp.Region, exp.Service)
	}

	signedAt, expiresAt, err := validateWindow(p.Query, cred, now)
	if err != nil {
		return Result{}, err
	}

	principal, ok := store.Lookup(cred.AccessKeyID)
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownKey, cred.AccessKeyID)
	}
	// A token is only as good as the credential that signed it. AWS rejects one
	// signed with a lapsed session credential even while the token's own window
	// is open, and this is reported separately from ErrExpired because the two
	// say very different things: ErrExpired means the workload held its TOKEN
	// too long, this means it held its CREDENTIAL too long.
	if principal.Expired(now) {
		return Result{}, fmt.Errorf("%w: %s lapsed %s ago", ErrCredExpired,
			cred.AccessKeyID, now.Sub(principal.Expiration).Truncate(time.Second))
	}
	// A session credential must present the session token it was issued with.
	// Without this check a leaked long-lived key could be replayed as a session
	// principal, and more usefully for a cluster: it proves the workload is using
	// the credential the STS shim actually handed it.
	// Constant-time, like the signature below: hmac.Equal rather than
	// crypto/subtle only to keep this package's imports where they were.
	if principal.SessionToken != "" &&
		!hmac.Equal([]byte(p.Query.Get(paramSecurityToken)), []byte(principal.SessionToken)) {
		return Result{}, ErrSessionMismatch
	}

	want := sign(p, cred, principal.SecretKey, signedAt)
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(p.Signature))) {
		return Result{}, ErrBadSignature
	}

	return Result{
		AccessKeyID: cred.AccessKeyID,
		Principal:   principal.ARN,
		Service:     principal.Service,
		IssuedAt:    signedAt,
		ExpiresAt:   expiresAt,
	}, nil
}

// checkTarget checks what the token was signed FOR — the host and the action —
// before any credential is looked up. Split out of Verify to keep that
// function under the complexity bound; the order of checks is unchanged.
func checkTarget(p Presigned, exp Expectation) error {
	if exp.Host != "" && !strings.EqualFold(p.Host, exp.Host) &&
		(exp.AltHost == "" || !strings.EqualFold(p.Host, exp.AltHost)) {
		return fmt.Errorf("%w: signed against %q, want %q", ErrWrongHost, p.Host, exp.Host)
	}
	if exp.Action != "" {
		if got := p.Query.Get(paramAction); got != exp.Action {
			return fmt.Errorf("%w: %q, want %q", ErrWrongAction, got, exp.Action)
		}
	}
	return nil
}

// validateWindow resolves a token's validity window and checks now against it.
//
// It is split out of Verify both to keep that function under the complexity
// bound and because the window is the single most important thing this package
// decides: the mint-once-never-refresh bug was a token that was perfectly well-formed and
// correctly signed, and wrong only about the time.
func validateWindow(
	q url.Values, cred credential, now time.Time,
) (signedAt, expiresAt time.Time, err error) {
	signedAt, err = time.Parse(timeFormat, q.Get(paramDate))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: %s: %w", ErrMalformed, paramDate, err)
	}
	signedAt = signedAt.UTC()

	// The scope's date must match the signing date, or a token could be replayed
	// into a neighboring day's scope.
	if signedAt.Format(dateFormat) != cred.Date {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: scope date %s vs signing date %s",
			ErrWrongScope, cred.Date, signedAt.Format(dateFormat))
	}

	ttl, err := strconv.Atoi(q.Get(paramExpires))
	if err != nil || ttl <= 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: %s %q", ErrMalformed, paramExpires, q.Get(paramExpires))
	}
	expiresAt = signedAt.Add(time.Duration(ttl) * time.Second)

	switch {
	case now.After(expiresAt):
		return time.Time{}, time.Time{}, fmt.Errorf("%w: expired %s ago (ttl %ds)",
			ErrExpired, now.Sub(expiresAt).Truncate(time.Second), ttl)
	case signedAt.After(now.Add(DefaultSkew)):
		return time.Time{}, time.Time{}, fmt.Errorf("%w: signed %s in the future",
			ErrNotYetValid, signedAt.Sub(now).Truncate(time.Second))
	}

	return signedAt, expiresAt, nil
}

// credential is a parsed X-Amz-Credential value.
type credential struct {
	AccessKeyID string
	Date        string
	Region      string
	Service     string
}

func parseCredential(raw string) (credential, error) {
	parts := strings.Split(raw, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return credential{}, fmt.Errorf("%w: %s %q", ErrMalformed, paramCredential, raw)
	}
	return credential{AccessKeyID: parts[0], Date: parts[1], Region: parts[2], Service: parts[3]}, nil
}

// sign recomputes the expected signature for a parsed token.
func sign(p Presigned, cred credential, secretKey string, signedAt time.Time) string {
	canonicalRequest := strings.Join([]string{
		"GET",
		p.Path,
		canonicalQuery(p.Query),
		"host:" + p.Host + "\n",
		p.Query.Get(paramSignedHeaders),
		emptyPayloadHash,
	}, "\n")

	scope := strings.Join([]string{cred.Date, cred.Region, cred.Service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		Algorithm,
		signedAt.Format(timeFormat),
		scope,
		hexSHA256(canonicalRequest),
	}, "\n")

	key := hmacBytes([]byte("AWS4"+secretKey), cred.Date)
	key = hmacBytes(key, cred.Region)
	key = hmacBytes(key, cred.Service)
	key = hmacBytes(key, "aws4_request")

	return hex.EncodeToString(hmacRaw(key, stringToSign))
}

// canonicalQuery renders the query in SigV4 canonical form: every parameter
// RFC3986-escaped, sorted by encoded key then encoded value, joined with '&'.
//
// Go's url.Values.Encode is NOT usable here — it escapes a space as '+' where
// SigV4 requires "%20", and it would silently produce a valid-looking signature
// that AWS disagrees with.
func canonicalQuery(q url.Values) string {
	pairs := make([]string, 0, len(q))
	for k, vs := range q {
		ek := rfc3986Escape(k)
		for _, v := range vs {
			pairs = append(pairs, ek+"="+rfc3986Escape(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// rfc3986Escape percent-encodes everything outside the RFC3986 unreserved set,
// with uppercase hex digits. This is what AWS calls URI-encoding.
func rfc3986Escape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hexSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacRaw(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hmacBytes(key []byte, data string) []byte { return hmacRaw(key, data) }
