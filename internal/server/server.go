// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Package server is localiam's central half: the store every pod's sidecar
// registers its issued credentials with, and the verification API the store
// adapters (Kafka broker callback, Redis and Postgres proxies) call.
//
// # Why a central half at all
//
// Credentials are issued per pod by a loopback sidecar, but they are VERIFIED
// at the shared stores — one Kafka broker sees tokens signed by every pod's
// agent. So the sidecar pushes each credential here as it mints it, and the
// adapters ask here.
//
// The alternative — deriving each secret key deterministically from a cluster
// master key so any verifier could re-derive it with no shared state — is
// tidier but puts bespoke key-derivation crypto on the critical path. A
// registration push is boring, and boring is the right call for the component
// whose failure mode is "everything can authenticate".
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/blairham/localiam/internal/policy"
	"github.com/blairham/localiam/verify"
)

// keyAllowed is the authorize response field. Named because the linter is right
// that three loose copies of a wire-contract key is how one of them drifts.
const keyAllowed = "allowed"

// Paths served.
const (
	PathRegister  = "/v1/credentials/register"
	PathVerify    = "/v1/verify/"
	PathAuthorize = "/v1/authorize"
	PathHealth    = "/healthz"
)

// Options configures a Server.
type Options struct {
	Store  *verify.Store
	Specs  map[string]*policy.Spec
	Now    func() time.Time
	Logger *slog.Logger
	// Token is the bearer token agents must present to register. Empty is
	// refused unless OpenRegistration is set: anyone who can reach an open
	// registration endpoint can plant credentials that then verify.
	Token  string
	Region string
	// OpenRegistration accepts registrations with no token. It exists for a
	// throwaway laptop run, and it has to be asked for by name.
	OpenRegistration bool
}

// Server implements the localiam HTTP API.
type Server struct {
	now  func() time.Time
	log  *slog.Logger
	opts Options
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errors.New("server: a Store is required")
	}
	if opts.Region == "" {
		return nil, errors.New("server: a Region is required")
	}
	if opts.Token == "" && !opts.OpenRegistration {
		return nil, errors.New("server: a registration Token is required (or set OpenRegistration to accept anyone)")
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{opts: opts, now: now, log: log}, nil
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathHealth, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "credentials": s.opts.Store.Len()})
	})
	mux.HandleFunc("POST "+PathRegister, s.handleRegister)
	mux.HandleFunc("POST "+PathVerify+"elasticache", s.handleVerifyElastiCache)
	mux.HandleFunc("POST "+PathVerify+"rds", s.handleVerifyRDS)
	mux.HandleFunc("POST "+PathVerify+"msk", s.handleVerifyMSK)
	mux.HandleFunc("POST "+PathAuthorize, s.handleAuthorize)
	return mux
}

// RegisterRequest is what a sidecar pushes on each mint.
type RegisterRequest struct {
	Principal verify.Principal `json:"principal"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if s.opts.Token != "" && r.Header.Get("Authorization") != "Bearer "+s.opts.Token {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: "+err.Error())
		return
	}
	if req.Principal.AccessKeyID == "" || req.Principal.SecretKey == "" {
		writeErr(w, http.StatusBadRequest, "accessKeyId and secretKey are required")
		return
	}
	s.opts.Store.Add(req.Principal)
	s.opts.Store.Sweep(s.now())
	s.log.Info("localiam: registered credential",
		"service", req.Principal.Service, "accessKeyId", req.Principal.AccessKeyID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// VerifyRequest carries a presented token and the context the adapter knows.
// Only the fields relevant to the endpoint are read.
type VerifyRequest struct {
	Token     string `json:"token"`
	Group     string `json:"replicationGroupId,omitempty"`
	User      string `json:"user,omitempty"`
	Host      string `json:"host,omitempty"`
	DBUser    string `json:"dbUser,omitempty"`
	Mechanism string `json:"mechanism,omitempty"`
	Port      int    `json:"port,omitempty"`
}

// VerifyResponse is the adapter's answer.
type VerifyResponse struct {
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
	Error       string    `json:"error,omitempty"`
	Service     string    `json:"service,omitempty"`
	Principal   string    `json:"principal,omitempty"`
	AccessKeyID string    `json:"accessKeyId,omitempty"`
	OK          bool      `json:"ok"`
}

func (s *Server) handleVerifyElastiCache(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[VerifyRequest](w, r)
	if !ok {
		return
	}
	res, err := s.VerifyElastiCache(r.Context(), req.Token, req.Group, req.User)
	writeVerify(w, res, err)
}

func (s *Server) handleVerifyRDS(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[VerifyRequest](w, r)
	if !ok {
		return
	}
	res, err := s.VerifyRDS(r.Context(), req.Token, req.Host, req.Port, req.DBUser)
	writeVerify(w, res, err)
}

func (s *Server) handleVerifyMSK(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[VerifyRequest](w, r)
	if !ok {
		return
	}
	res, err := s.VerifyMSK(r.Context(), req.Mechanism, []byte(req.Token), req.Host)
	if errors.Is(err, ErrUnknownMechanism) {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeVerify(w, res, err)
}

// ErrUnknownMechanism is a SASL mechanism the verifier does not speak.
var ErrUnknownMechanism = errors.New("unknown mechanism")

// VerifyElastiCache verifies a Redis AUTH token and applies the service's
// connect policy. It is the one path every Redis verification takes — the
// HTTP API and the proxies `localiam server` hosts in-process — so policy
// cannot be skipped by choosing where the proxy runs.
func (s *Server) VerifyElastiCache(_ context.Context, token, group, user string) (verify.Result, error) {
	res, err := verify.ElastiCache(token, group, user, s.opts.Region, s.opts.Store, s.now())
	return s.decide("redis", res, err, func(spec *policy.Spec) bool { return spec.MayConnectRedis() })
}

// VerifyRDS verifies a Postgres password token and applies the service's
// connect policy for dbUser.
func (s *Server) VerifyRDS(_ context.Context, token, host string, port int, dbUser string) (verify.Result, error) {
	res, err := verify.RDS(token, host, port, dbUser, s.opts.Region, s.opts.Store, s.now())
	return s.decide("postgres", res, err, func(spec *policy.Spec) bool { return spec.MayConnectPostgresAs(dbUser) })
}

// VerifyMSK verifies an MSK SASL payload and applies the service's connect
// policy. Real clients speak BOTH mechanisms — franz-go sends AWS_MSK_IAM, the
// .NET and Node clients OAUTHBEARER — so the adapter says which it received;
// empty means OAUTHBEARER.
func (s *Server) VerifyMSK(_ context.Context, mechanism string, payload []byte, host string) (verify.Result, error) {
	var (
		res verify.Result
		err error
	)
	switch mechanism {
	case "AWS_MSK_IAM":
		res, err = verify.MSKAWSMSKIAM(payload, s.opts.Region, host, s.opts.Store, s.now())
	case "OAUTHBEARER", "":
		res, err = verify.MSKOAuthBearer(string(payload), s.opts.Region, host, s.opts.Store, s.now())
	default:
		return verify.Result{}, fmt.Errorf("%w %s", ErrUnknownMechanism, mechanism)
	}
	return s.decide("kafka", res, err, func(spec *policy.Spec) bool { return spec.MayConnectKafka() })
}

// decide turns a verification into a verdict, applying the policy check when
// specs are loaded. Authentication and authorization fail through the same
// error on purpose: an adapter only ever needs allow or deny, and the message
// is what tells an operator which of the two it was.
func (s *Server) decide(
	store string, res verify.Result, err error, allowed func(*policy.Spec) bool,
) (verify.Result, error) {
	if err != nil {
		s.log.Info("localiam: verification denied", "store", store, "error", err)
		return verify.Result{}, err
	}
	if s.opts.Specs != nil {
		spec, ok := s.opts.Specs[res.Service]
		if !ok {
			return verify.Result{}, fmt.Errorf("localiam: no service spec for %q", res.Service)
		}
		if !allowed(spec) {
			s.log.Info("localiam: authenticated but not permitted",
				"store", store, "service", res.Service, "principal", res.Principal)
			return verify.Result{}, fmt.Errorf("localiam: %s is authenticated but not permitted", res.Service)
		}
	}
	// Successful verifications are logged HERE as well as at the proxy. The
	// server is the only component that sees every store and every workload, so
	// leaving it silent on the common case made the one pane of glass look dead:
	// a healthy cluster showed nothing but credential registrations.
	//
	// The remaining token life is included because a shrinking value across
	// repeated lines is the signature of a workload that is NOT refreshing.
	s.log.Info("localiam: verification accepted",
		"store", store,
		"service", res.Service,
		"principal", res.Principal,
		"accessKeyId", res.AccessKeyID,
		"tokenTTLRemaining", time.Until(res.ExpiresAt).Truncate(time.Second).String(),
	)
	return res, nil
}

// writeVerify writes a verdict. A rejected token is a 200 with ok:false, not
// an HTTP error: the request was fine, the token was not.
func writeVerify(w http.ResponseWriter, res verify.Result, err error) {
	if err != nil {
		writeJSON(w, http.StatusOK, VerifyResponse{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, VerifyResponse{
		OK:          true,
		Service:     res.Service,
		Principal:   res.Principal,
		AccessKeyID: res.AccessKeyID,
		ExpiresAt:   res.ExpiresAt,
	})
}

// AuthorizeRequest asks a per-operation policy question — what the Kafka
// adapter needs once a connection is up, since MSK authorizes per topic and
// group rather than only at connect.
type AuthorizeRequest struct {
	Service  string `json:"service"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[AuthorizeRequest](w, r)
	if !ok {
		return
	}
	if s.opts.Specs == nil {
		writeJSON(w, http.StatusOK, map[string]any{keyAllowed: true, "reason": "no specs loaded"})
		return
	}
	spec, found := s.opts.Specs[req.Service]
	if !found {
		writeJSON(w, http.StatusOK, map[string]any{
			keyAllowed: false, "reason": "no service spec for " + req.Service,
		})
		return
	}

	var allowed bool
	switch req.Action {
	case "ReadData":
		allowed = spec.MayReadTopic(req.Resource)
	case "WriteData":
		allowed = spec.MayWriteTopic(req.Resource)
	case "Group":
		allowed = spec.MayUseGroup(req.Resource)
	case "TransactionalId":
		allowed = spec.MayUseTransactionalID(req.Resource)
	case "Connect":
		allowed = spec.MayConnectKafka()
	default:
		writeErr(w, http.StatusBadRequest, "unknown action "+req.Action)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{keyAllowed: allowed})
}

func decode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body: "+err.Error())
		return v, false
	}
	return v, true
}

// writeJSON renders a response. A write failure means the client went away
// mid-response — there is no recovery and no second response to send, so it is
// logged and dropped rather than swallowed silently.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Warn("localiam: writing response", "error", err)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
