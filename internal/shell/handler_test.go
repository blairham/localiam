// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blairham/sh/gated"

	"github.com/blairham/localiam/internal/shell"
)

// The shell itself (the gate, the trail, the $0/$@ binding) is tested where it
// lives, in github.com/blairham/sh/gated. What is tested here is only what this
// package adds: the token, the mount, the body cap and the JSON response.

// readableRoot gives the tests a directory the policy allows, so that the
// allow-side case asserts on real content. /proc is not used: these tests run
// on a developer's macOS laptop as well as on a Linux runner, and a test whose
// verdict depends on which kernel it landed on is not a test.
func readableRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "status"), []byte("Name:\tsvc\nThreads:\t7\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return root
}

func post(mux *http.ServeMux, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, shell.Path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer right")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestTheEndpointIsAbsentWithoutAToken is the fail-closed direction, and it
// asserts the 404 rather than Register's bool, because 404 is what an operator
// checking a deployment actually sees.
func TestTheEndpointIsAbsentWithoutAToken(t *testing.T) {
	mux := http.NewServeMux()
	if shell.Register(mux, shell.Config{Token: ""}) {
		t.Fatal("registered with no token")
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, shell.Path, strings.NewReader("echo hi")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 with no token, got %d", rec.Code)
	}
}

func TestTheEndpointRefusesAWrongToken(t *testing.T) {
	mux := http.NewServeMux()
	if !shell.Register(mux, shell.Config{Token: "right"}) {
		t.Fatal("did not register with a token")
	}

	for name, auth := range map[string]string{
		"absent": "",
		"wrong":  "Bearer wrong",
		"raw":    "right",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, shell.Path, strings.NewReader("echo hi"))
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("want 403, got %d", rec.Code)
			}
		})
	}
}

func TestTheEndpointRunsAndReturnsTheTrail(t *testing.T) {
	root := readableRoot(t)
	mux := http.NewServeMux()
	shell.Register(mux, shell.Config{
		Token:  "right",
		Policy: &gated.Policy{ReadRoots: []string{root}},
	})

	rec := post(mux, "echo "+root+"/*; /bin/echo nope")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res gated.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(res.Stdout, "status") {
		t.Fatalf("glob output missing: %q", res.Stdout)
	}
	if strings.Contains(res.Stdout, "nope") {
		t.Fatalf("the exec ran: %q", res.Stdout)
	}
	if res.Denied == 0 {
		t.Fatalf("want the exec denial in the response trail: %+v", res.Trail)
	}
}

// TestTheBodyCapAgreesWithGated pins the endpoint's body cap to gated's script
// cap, which is unexported and so copied into the handler. A script at the cap
// must run (if gated lowered its cap, Run would refuse it with a 400); one byte
// over must reach gated and be refused by it, not run; and a body past the
// read limit must be a 413 from the endpoint before it is buffered.
func TestTheBodyCapAgreesWithGated(t *testing.T) {
	mux := http.NewServeMux()
	shell.Register(mux, shell.Config{Token: "right"})

	const limit = 8 << 10
	atCap := "#" + strings.Repeat("x", limit-1)

	if rec := post(mux, atCap); rec.Code != http.StatusOK {
		t.Fatalf("a script at the cap: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := post(mux, atCap+"x"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cap") {
		t.Fatalf("a script one byte over the cap: want gated's 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := post(mux, atCap+"xx"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body past the read limit: want 413, got %d: %s", rec.Code, rec.Body.String())
	}
}
