// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Package shell embeds a gated shell interpreter so that a distroless image
// can answer diagnostic questions without carrying a shell binary.
//
// A distroless image has no /bin/sh and no coreutils, so `kubectl exec` finds
// nothing to run. The usual answers are to add busybox to the image or to
// attach an ephemeral debug container. Both put an executable shell where an
// attacker who reaches code execution can find it, and neither leaves a
// record of what anyone did.
//
// This does the opposite. The interpreter (github.com/blairham/sh) is a Go
// library linked into localiam. Every action it takes passes a
// deny-by-default gate first, exec is refused unconditionally, and every
// action that happened is recorded. Two front ends share one gate:
//
//   - Register mounts POST /debug/sh on the `localiam server` mux, behind a
//     bearer token (LOCALIAM_SHELL_TOKEN).
//   - cmd/sh is the same Shell as a /bin/sh binary for `kubectl exec`.
//
// The gate is policy.go, and it is the whole security argument. README.md in
// this directory is the operator-facing half.
package shell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/blairham/sh/dialect/dash"
	"github.com/blairham/sh/interp"
	"github.com/blairham/sh/syntax"
)

const (
	// maxScript bounds the request body. A diagnostic is a few lines.
	maxScript = 8 << 10
	// maxOutput bounds what a script may write back. `echo /proc/*/status`
	// under a `while read` loop can produce megabytes from a pod with many
	// threads, and the response is buffered.
	maxOutput = 256 << 10
	// maxRecords bounds the audit trail. See Recorder.
	maxRecords = 4096
)

// Result is what one script run produced.
type Result struct {
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
	Trail  []Record `json:"trail"`
	Status int      `json:"status"`
	// Denied is how many actions the gate refused. Counted off the typed
	// event kind by the Recorder, never re-derived from Trail.
	Denied    int  `json:"denied"`
	Dropped   int  `json:"trail_dropped,omitempty"`
	Truncated bool `json:"truncated,omitempty"`
}

// Shell runs one script per call, each in a fresh Runner.
//
// Fresh per call on purpose: a Runner carries variables, functions, aliases
// and a working directory, and a long-lived one would let a script left behind
// by one operator change what the next one's script means. A diagnostic that
// is not reproducible is not a diagnostic. It also means there is no session
// state to leak between two people holding the same token.
type Shell struct {
	// Policy is the gate. Nil means DefaultPolicy.
	Policy *Policy
	// Session names this service in the audit trail, so records from several
	// pods can be joined. interp does not invent identity.
	Session string
}

// Run parses and executes src, and returns what happened.
//
// args, when given, are what `sh -c src arg0 arg1 ...` binds: args[0] is $0 and
// the rest are the positional parameters $1, $2 and so on. Nothing is joined
// into the script. An earlier copy of this code joined every argument after
// -c into the source, which real sh does not do and which hid a quoting
// mistake: a command string that arrived as several words parsed as a single
// quoted word, and the gate refused it as an exec of the whole script.
//
// The dialect is dash. It is the smallest of the five presets the interpreter
// ships, it is what an operator's muscle memory for `sh` expects, and a
// diagnostic endpoint has no use for the bash and zsh surface, arrays,
// coprocesses, process substitution, beyond the parameter expansion and
// globbing that dash already has. A smaller grammar is a smaller thing to be
// wrong about.
func (s *Shell) Run(ctx context.Context, src string, args ...string) (Result, error) {
	if len(src) > maxScript {
		return Result{}, fmt.Errorf("shell: script is %d bytes, cap is %d", len(src), maxScript)
	}

	pol := s.Policy
	if pol == nil {
		pol = DefaultPolicy()
	}
	rec := newRecorder(maxRecords)

	name, params := "sh", []string(nil)
	if len(args) > 0 {
		name, params = args[0], args[1:]
	}

	d := dash.Dialect()
	f, err := syntax.Parse(src, d)
	if err != nil {
		return Result{}, fmt.Errorf("shell: parse: %w", err)
	}

	stdout := &capped{limit: maxOutput}
	stderr := &capped{limit: maxOutput}
	sem, diag := dash.Semantics(), dash.Diagnostics()

	r := &interp.Runner{
		Stdout: stdout, Stderr: stderr, Stdin: emptyReader{},
		Dialect: &d, Semantics: &sem, Diagnostics: &diag,
		Gate: pol, Events: rec,
		Session: s.Session,
		Name:    name,
		Params:  params,
		// An absolute Dir, so a relative path the gate is asked about means
		// the interpreter is naming something this package did not set up,
		// and Policy.reachable can refuse it on that basis alone.
		Dir: "/",
		// No environment. The service's env holds its credentials, and an
		// endpoint that can print it is a secret-exfiltration primitive with
		// an audit trail attached. Nothing here needs it, and the same data
		// at /proc/<pid>/environ is refused by the gate (see DenyNames).
		Env: []string{},
	}
	dash.Apply(r)

	status, runErr := r.Run(ctx, f)

	trail, dropped, denied := rec.Trail()
	res := Result{
		Status:    status,
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Trail:     trail,
		Denied:    denied,
		Dropped:   dropped,
		Truncated: stdout.truncated || stderr.truncated,
	}
	// A non-zero status is a result, not an error: a denied command is a
	// command that failed, and the whole point of this endpoint is to hand
	// that back with the trail that explains it. Only a runner-level failure
	// is an error, and a deadline is reported as itself so the caller can
	// tell "your script was stopped" from "your script was wrong".
	switch {
	case runErr == nil:
		return res, nil
	case errors.Is(runErr, context.DeadlineExceeded), errors.Is(runErr, context.Canceled):
		return res, fmt.Errorf("shell: stopped: %w", runErr)
	default:
		return res, fmt.Errorf("shell: run: %w", runErr)
	}
}

// capped is an io.Writer that stops at a limit and remembers that it did.
type capped struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if room <= 0 {
		c.truncated = true
		// Report the full length. Returning short makes the interpreter treat
		// a capped write as a write error, which would abort the script
		// instead of finishing it with the output we did get.
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *capped) String() string { return c.buf.String() }

// emptyReader is stdin. A diagnostic script has no input, and leaving Stdin
// nil would let a `read` block on whatever the process's stdin happens to be.
type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
