// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Package issuer serves AWS credentials to a pod over the EKS Pod Identity
// agent contract, so the workload's UNCHANGED production code can mint its own
// SigV4 tokens exactly as it does in production.
//
// # Why this shape
//
// On EKS, credentials arrive via Pod Identity: the agent injects
// AWS_CONTAINER_CREDENTIALS_FULL_URI plus
// AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE. Serving that same contract means the
// cluster exercises the same SDK credential provider, the same refresh machinery
// and the same failure modes — rather than a test-only path that happens to
// produce credentials.
//
// # Why a sidecar
//
// The SDK refuses AWS_CONTAINER_CREDENTIALS_FULL_URI over plain HTTP unless the
// host is loopback or an ECS/EKS link-local address. A sidecar listening on
// 127.0.0.1 satisfies that honestly — and a local credential agent reached over
// loopback is precisely what Pod Identity is. See
// docs/rfcs/0001-credential-issuance-topology.md.
//
// # What it does NOT do
//
// It does not mint SigV4 tokens. Those are minted by the workload, in its own
// production code, in whatever language it uses. Issuing credentials is the
// only thing missing in a cluster; a token minter here would mean localiam tested OUR minting
// rather than real services'.
package issuer

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blairham/localiam/verify"
)

// CredentialsPath is the Pod Identity agent's endpoint. The full URI a workload
// is configured with is http://127.0.0.1:<port>/v1/credentials.
const CredentialsPath = "/v1/credentials"

// DefaultTTL matches the ~15 minutes Pod Identity issues, which is also the
// ElastiCache and RDS token cap. Shortening it in a cluster is the cheapest way to
// compress the mint-once-never-refresh bug window from hours into minutes.
const DefaultTTL = 15 * time.Minute

// MinTTL guards against a TTL so short the SDK thrashes.
const MinTTL = 30 * time.Second

// Identity is who this sidecar issues for. One sidecar serves one workload, so
// identity is configuration, not something the request negotiates.
type Identity struct {
	// Service is the workload name, e.g. "api". Used for logging and to select
	// the workload's grants from its service spec.
	Service string
	// RoleARN is the identity tokens minted with these credentials authenticate
	// as, e.g. arn:aws:iam::000000000000:role/api.
	RoleARN string
	// AccountID is echoed back to the SDK; localiam uses the all-zero account.
	AccountID string
}

// Options configures a Server.
type Options struct {
	Store         *verify.Store
	OnIssue       func(verify.Principal) error
	Now           func() time.Time
	Logger        *slog.Logger
	Identity      Identity
	ExpectedToken string
	TTL           time.Duration
}

// Server serves the Pod Identity agent contract.
type Server struct {
	curExp time.Time
	now    func() time.Time
	log    *slog.Logger
	cur    credentialsResponse
	opts   Options
	ttl    time.Duration
	issued atomic.Int64
	mu     sync.Mutex
}

// New builds a Server. It fails rather than defaulting when the identity is
// incomplete: a credential that authenticates as nothing in particular is worse
// than no credential, because every downstream denial then looks like a bug.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Store == nil:
		return nil, fmt.Errorf("issuer: a Store is required")
	case opts.Identity.Service == "":
		return nil, fmt.Errorf("issuer: Identity.Service is required")
	case opts.Identity.RoleARN == "":
		return nil, fmt.Errorf("issuer: Identity.RoleARN is required")
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < MinTTL {
		return nil, fmt.Errorf("issuer: TTL %s is below the %s floor", ttl, MinTTL)
	}

	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	return &Server{opts: opts, ttl: ttl, now: now, log: log}, nil
}

// Issued reports how many credentials have been minted — the direct signal for
// whether a workload is refreshing at all. A pod that issued exactly once and
// then ran for hours is the mint-once-never-refresh shape.
func (s *Server) Issued() int64 { return s.issued.Load() }

// credentialsResponse is the ECS container-credentials JSON shape, which Pod
// Identity reuses — that reuse is why AWS_CONTAINER_CREDENTIALS_FULL_URI works
// for it at all.
//
// ⚠ The field names are the contract. The SDK's endpoint-credentials provider
// unmarshals exactly these keys and reports a useless "failed to refresh
// cached credentials" if they are wrong. TestTheSdkAcceptsOurWireShape pins
// them against the real provider rather than against this struct.
type credentialsResponse struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	AccountID       string `json:"AccountId"`
	Expiration      string `json:"Expiration"`
}

// ServeHTTP implements the agent contract.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != CredentialsPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		// The agent answers 401 on a bad token; matching it keeps the workload's
		// error identical to what it would see in production.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	now := s.now()
	cred, err := s.current(now)
	if err != nil {
		s.log.Error("localiam: minting credentials", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if swept := s.opts.Store.Sweep(now); swept > 0 {
		s.log.Debug("localiam: swept lapsed credentials", "count", swept)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(cred); err != nil {
		s.log.Error("localiam: writing credentials", "error", err)
	}
}

// authorized checks the Authorization header the SDK copies from the file named
// by AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE.
func (s *Server) authorized(r *http.Request) bool {
	got := strings.TrimSpace(r.Header.Get("Authorization"))
	if got == "" {
		return false
	}
	if s.opts.ExpectedToken == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.opts.ExpectedToken)) == 1
}

// refreshMargin is how long before expiry the agent starts handing out a fresh
// credential, so a workload that reads one never gets a credential with no
// usable life left.
const refreshMargin = time.Minute

// current returns the cached credential, minting a new one only when there is
// none or it is within refreshMargin of expiry.
//
// 🚨 CACHING IS REQUIRED FOR CORRECTNESS, NOT SPEED. botocore's
// RefreshableCredentials re-reads the endpoint on EVERY attribute access while
// the credential sits inside its refresh windows (advisory 15m, mandatory 10m).
// When the agent minted per GET, `access_key`, `secret_key` and `token` each
// came from a DIFFERENT credential, so the presigned URL carried one mint's key
// with another's session token, signed by a third's secret. The proxy reported
// `session token mismatch` and every Python and Node client was locked out
// while Go — which snapshots credentials once — was unaffected. The real Pod
// Identity agent returns a stable credential, so this is also the faithful
// behavior. Expiry still bites: the credential really does lapse, so a workload
// that caches its TOKEN past the window still fails, which is the bug class
// localiam exists to reproduce.
func (s *Server) current(now time.Time) (credentialsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.curExp.IsZero() && now.Before(s.curExp.Add(-refreshMargin)) {
		return s.cur, nil
	}
	cred, err := s.mint(now)
	if err != nil {
		return credentialsResponse{}, err
	}
	s.cur, s.curExp = cred, now.Add(s.ttl)
	return cred, nil
}

// mint creates a fresh credential and registers it for verification.
func (s *Server) mint(now time.Time) (credentialsResponse, error) {
	accessKeyID, err := randomID("ASIA", 16)
	if err != nil {
		return credentialsResponse{}, err
	}
	secretKey, err := randomID("", 40)
	if err != nil {
		return credentialsResponse{}, err
	}
	sessionToken, err := randomID("", 64)
	if err != nil {
		return credentialsResponse{}, err
	}

	expires := now.Add(s.ttl)
	principal := verify.Principal{
		AccessKeyID:  accessKeyID,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		Service:      s.opts.Identity.Service,
		ARN:          s.opts.Identity.RoleARN,
		Expiration:   expires,
	}
	if s.opts.OnIssue != nil {
		if err := s.opts.OnIssue(principal); err != nil {
			return credentialsResponse{}, fmt.Errorf("issuer: registering credential: %w", err)
		}
	}
	s.opts.Store.Add(principal)
	s.issued.Add(1)

	s.log.Info("localiam: issued credentials",
		"service", s.opts.Identity.Service,
		"accessKeyId", accessKeyID,
		"expiresAt", expires.Format(time.RFC3339),
		"issuedTotal", s.issued.Load(),
	)

	return credentialsResponse{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretKey,
		Token:           sessionToken,
		AccountID:       s.opts.Identity.AccountID,
		// RFC3339 is what the SDK parses; without a parseable Expiration it
		// caches the credential as static and never refreshes — which would
		// hide the exact bug class localiam exists to expose.
		Expiration: expires.Format(time.RFC3339),
	}, nil
}

// alphabet is the character set for generated credential material: uppercase
// and digits for the access key ID (AWS's own shape), mixed for the rest.
const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	mixed       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// randomID generates cryptographically random credential material. The values
// are never real AWS credentials, but they still gate access to the cluster's
// stores, so they come from crypto/rand rather than math/rand.
func randomID(prefix string, n int) (string, error) {
	set := mixed
	if prefix != "" {
		set = upperDigits
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("issuer: reading random bytes: %w", err)
	}
	var sb strings.Builder
	sb.WriteString(prefix)
	for _, c := range b {
		sb.WriteByte(set[int(c)%len(set)])
	}
	return sb.String(), nil
}
