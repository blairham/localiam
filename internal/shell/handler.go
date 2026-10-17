// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Path is where Handler expects to be mounted.
const Path = "/debug/sh"

// runTimeout bounds one script. interp consults the context at every command,
// so a runaway loop stops here rather than holding a goroutine forever.
const runTimeout = 5 * time.Second

// Config is what the endpoint needs to exist.
type Config struct {
	// Policy overrides DefaultPolicy. Nil means the default.
	Policy *Policy
	// Log receives one line per run, so that the trail exists in the log
	// pipeline even when nobody keeps the response body. Nil means
	// slog.Default.
	Log *slog.Logger
	// Token is the bearer token. AN EMPTY TOKEN MEANS THE ENDPOINT IS NOT
	// REGISTERED AT ALL, see Register. That is the fail-closed direction: an
	// env that forgot to set the secret gets 404, not an open shell.
	Token string
	// Session names this pod in the audit trail.
	Session string
}

// Register mounts the endpoint on mux, and reports whether it did.
//
// It refuses to mount without a token. The alternative, mount it and check
// the token at request time, has the same runtime behavior and a much worse
// failure mode, because "is this endpoint present here" then cannot be
// answered by asking the pod. With this shape, `curl -s -o /dev/null -w '%{http_code}'
// localhost:8080/debug/sh` answering 404 is proof it is off.
func Register(mux *http.ServeMux, cfg Config) bool {
	if cfg.Token == "" {
		return false
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	h := &handler{
		cfg:   cfg,
		log:   log,
		shell: &Shell{Policy: cfg.Policy, Session: cfg.Session},
	}
	mux.Handle("POST "+Path, h)
	return true
}

type handler struct {
	log   *slog.Logger
	shell *Shell
	cfg   Config
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !h.authorized(req) {
		// No WWW-Authenticate header: this is not a login surface and a
		// challenge only tells a scanner what it found.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	src, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxScript+1))
	if err != nil {
		http.Error(w, "script too large", http.StatusRequestEntityTooLarge)
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), runTimeout)
	defer cancel()

	res, runErr := h.shell.Run(ctx, string(src))

	// The run is logged whether or not it succeeded, and the log carries the
	// denial count rather than the whole trail: the trail goes to the caller,
	// and what an on-call reader wants from CloudWatch six weeks later is
	// that somebody ran something and whether the gate refused any of it.
	h.log.Info("shell: run",
		"session", h.cfg.Session,
		"bytes", len(src),
		"status", res.Status,
		"records", len(res.Trail),
		"denied", res.Denied,
		"truncated", res.Truncated,
		"err", runErr,
	)

	w.Header().Set("Content-Type", "application/json")
	if runErr != nil {
		// A parse failure or a deadline is a 400/408-shaped thing, but the
		// result still carries the trail of whatever ran before it, so it is
		// returned with the body rather than replaced by an error string.
		w.WriteHeader(http.StatusBadRequest)
		// Keyed, not positional: this package's lint config reorders struct
		// fields for alignment, and a positional literal silently swaps its
		// values when that happens (it did, once, and stopped compiling).
		h.encode(w, struct {
			Error string `json:"error"`
			Result
		}{Result: res, Error: runErr.Error()})
		return
	}
	h.encode(w, res)
}

// encode writes the response body. The status line is already sent, so a
// failure here cannot change what the caller sees; it is logged so that a
// client that dropped mid-response is not indistinguishable from one that got
// the whole trail.
func (h *handler) encode(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.log.Warn("shell: write response", "session", h.cfg.Session, "err", err)
	}
}

// authorized compares in constant time. The token is a shared secret read from
// the pod's environment, and a timing-variable compare on a secret reachable
// from inside the cluster network is a real, if slow, oracle.
func (h *handler) authorized(req *http.Request) bool {
	got, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(h.cfg.Token)) == 1
}
