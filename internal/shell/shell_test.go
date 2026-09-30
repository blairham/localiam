// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blairham/localiam/internal/shell"
)

// readableRoot gives the tests a directory the policy allows, so that the
// allow-side cases assert on real content. /proc is not used: these tests run
// on a developer's macOS laptop as well as on a Linux runner, and a test whose
// verdict depends on which kernel it landed on is not a test.
func readableRoot(t *testing.T) (root string, sh *shell.Shell) {
	t.Helper()
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "status"), []byte("Name:\tsvc\nThreads:\t7\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return root, &shell.Shell{
		Policy:  &shell.Policy{ReadRoots: []string{root}},
		Session: "test",
	}
}

func run(t *testing.T, sh *shell.Shell, src string) shell.Result {
	t.Helper()
	res, err := sh.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("run %q: %v", src, err)
	}
	return res
}

// denials reads the rendered trail. Result.Denied is the authoritative count
// (the Recorder takes it off the typed enum); this exists so a test can assert
// on WHICH action was refused, and the two are cross-checked in
// TestTheDeniedCountAgreesWithTheTrail so that a rendering change cannot make
// one of them quietly wrong again.
func denials(res shell.Result) []shell.Record {
	var out []shell.Record
	for _, r := range res.Trail {
		if r.Kind == "denied" {
			out = append(out, r)
		}
	}
	return out
}

// TestTheShellCanReadWithNoExternalCommands is the premise of the whole
// package: in an image with no coreutils, globbing and `while read` still
// answer the questions an operator execs in to ask. If this fails the feature
// has no reason to exist, whatever the gate does.
func TestTheShellCanReadWithNoExternalCommands(t *testing.T) {
	root, sh := readableRoot(t)

	res := run(t, sh, "for f in "+root+"/*; do echo \"found $f\"; done")
	if !strings.Contains(res.Stdout, "found "+root+"/status") {
		t.Fatalf("glob did not list the directory: %q", res.Stdout)
	}

	res = run(t, sh, "while read line; do echo \"[$line]\"; done < "+root+"/status")
	if !strings.Contains(res.Stdout, "[Threads:\t7]") {
		t.Fatalf("read loop did not read the file: %q", res.Stdout)
	}
}

// TestExecIsRefusedEvenWhereTheBinaryExists pins the load-bearing rule. It
// names a binary that really is on the test machine, because the interesting
// failure is a gate that refuses only what was already going to fail.
func TestExecIsRefusedEvenWhereTheBinaryExists(t *testing.T) {
	_, sh := readableRoot(t)

	res := run(t, sh, "/bin/echo pwned")
	if strings.Contains(res.Stdout, "pwned") {
		t.Fatalf("the binary RAN: stdout %q", res.Stdout)
	}
	if res.Status == 0 {
		t.Fatalf("a refused command reported success")
	}
	// Two denials, not one: resolving the command stats the path before it
	// execs it, and the gate sees both. Asserting on the exec specifically
	// rather than on the count, because the count is the interpreter's
	// business and could reasonably change.
	var sawExec bool
	for _, d := range denials(res) {
		if d.Action == "exec" && d.Path == "/bin/echo" {
			sawExec = true
		}
	}
	if !sawExec {
		t.Fatalf("no exec denial naming /bin/echo: %+v", res.Trail)
	}
}

// TestTheDeniedCountAgreesWithTheTrail is here because the first version of
// this package counted denials by matching "EventDenied" against a field
// whose value is "denied", and logged denied=0 through three real refusals.
// Nothing failed; the number was simply wrong. This pins the two against each
// other so that the next rendering change cannot repeat it silently.
func TestTheDeniedCountAgreesWithTheTrail(t *testing.T) {
	_, sh := readableRoot(t)
	res := run(t, sh, "/bin/echo one; /bin/echo two")

	if res.Denied == 0 {
		t.Fatal("three refusals and Denied is 0, the count is not wired to the enum")
	}
	if got := len(denials(res)); got != res.Denied {
		t.Fatalf("Denied=%d but the trail renders %d denials", res.Denied, got)
	}
}

// TestAReadOutsideTheRootsIsRefused covers the plain case and the traversal
// that the plain case invites. path.Clean is what makes the second work, so
// the second is the one that would catch its removal.
func TestAReadOutsideTheRootsIsRefused(t *testing.T) {
	root, sh := readableRoot(t)
	secret := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The second form reaches the same file by climbing out of the root, and
	// it is the one that would survive removing path.Clean from the policy.
	escape := root + "/../" + filepath.Base(filepath.Dir(secret)) + "/token"
	for _, src := range []string{
		"while read l; do echo \"$l\"; done < " + secret,
		"while read l; do echo \"$l\"; done < " + escape,
	} {
		res := run(t, sh, src)
		if strings.Contains(res.Stdout, "s3cret") {
			t.Fatalf("read escaped the roots via %q: %q", src, res.Stdout)
		}
		if res.Denied == 0 {
			t.Fatalf("escape via %q was not recorded as a denial: %+v", src, res.Trail)
		}
	}
}

// TestTheEnvironmentIsRefusedInsideTheRoots covers the one path that is under
// an allowed root and still refused.
//
// It exists because the first probe of /proc/1/environ came back EMPTY AND
// SUCCESSFUL: a `while read` loop over a file with no trailing newline never
// runs its body. A bare `read` leaks the whole environment, so the empty
// answer protected nothing. The case below uses the bare form for that reason.
func TestTheEnvironmentIsRefusedInsideTheRoots(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "environ"), []byte("TOKEN=s3cret\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sh := &shell.Shell{Policy: &shell.Policy{ReadRoots: []string{root}}}

	res := run(t, sh, "read -r l < "+root+"/environ; echo \"$l\"")
	if strings.Contains(res.Stdout, "s3cret") {
		t.Fatalf("the environment was readable: %q", res.Stdout)
	}
	if res.Denied == 0 {
		t.Fatalf("the read was not refused, only empty: %+v", res.Trail)
	}
}

// TestAWriteIsRefusedInsideTheRoots separates read-only from reachable: the
// path is allowed, the direction is not.
func TestAWriteIsRefusedInsideTheRoots(t *testing.T) {
	root, sh := readableRoot(t)
	target := filepath.Join(root, "written")

	res := run(t, sh, "echo mutated > "+target)
	if _, err := os.Stat(target); err == nil {
		t.Fatalf("the write landed at %s", target)
	}
	if res.Denied == 0 {
		t.Fatalf("the write was not recorded as a denial: %+v", res.Trail)
	}
}

// TestTheDenialAndItsActionShareAnID is what makes the trail admissible. The
// interpreter's own doc says pairing by position does not work, so this pins
// that we read the ID rather than reconstructing the pairing.
func TestTheDenialAndItsActionShareAnID(t *testing.T) {
	_, sh := readableRoot(t)
	res := run(t, sh, "/bin/echo one; /bin/echo two")

	d := denials(res)
	if len(d) < 2 {
		t.Fatalf("want at least two denials, got %d", len(d))
	}
	if d[0].ID == "" || d[0].ID == d[1].ID {
		t.Fatalf("two runs of the same command share or lack an id: %q and %q", d[0].ID, d[1].ID)
	}
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
	root, _ := readableRoot(t)
	mux := http.NewServeMux()
	shell.Register(mux, shell.Config{
		Token:  "right",
		Policy: &shell.Policy{ReadRoots: []string{root}},
	})

	req := httptest.NewRequest(http.MethodPost, shell.Path, strings.NewReader("echo "+root+"/*; /bin/echo nope"))
	req.Header.Set("Authorization", "Bearer right")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res shell.Result
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

// TestArgsBindLikeShDashC pins what `sh -c src arg0 arg1` means: arg0 is $0 and
// the rest are the positional parameters. An earlier copy of cmd/sh joined
// every argument after -c into the script, which real sh does not do, and it
// hid a quoting mistake behind an exec refusal. Both halves are asserted: the
// words reach $0/$1/$2, and they are NOT executed as part of the script.
func TestArgsBindLikeShDashC(t *testing.T) {
	_, sh := readableRoot(t)

	res, err := sh.Run(context.Background(), `echo "0=$0 1=$1 2=$2 n=$#"`, "probe", "alpha", "beta")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got, want := strings.TrimSpace(res.Stdout), "0=probe 1=alpha 2=beta n=2"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if res.Denied != 0 {
		t.Fatalf("an argument was treated as a command: %+v", res.Trail)
	}

	res, err = sh.Run(context.Background(), `echo "0=$0 n=$#"`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got, want := strings.TrimSpace(res.Stdout), "0=sh n=0"; got != want {
		t.Fatalf("with no args: stdout = %q, want %q", got, want)
	}
}
