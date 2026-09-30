// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Command sh is localiam's gated shell (internal/shell) as a binary, installed
// at /bin/sh in the distroless image so that
// `kubectl exec <pod> -- /bin/sh -c '<script>'` works.
//
// It is the same Shell and the same Policy as the HTTP endpoint, so there is
// no second boundary to keep in agreement with the first. It cannot exec
// anything, ever, and its reads are bounded to /proc and /sys/fs/cgroup.
//
// The Dockerfile builds it beside localiam and installs it at /bin/sh.
//
// Only install it at /bin/sh in an image that has no other shell or userland.
// Beside busybox the gate protects nothing: `ls`, `wget` and the rest are
// still there to exec from anything that is not this binary.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/blairham/localiam/internal/shell"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	src, args, code := source(os.Args[1:])
	if code != 0 {
		return code
	}

	sh := &shell.Shell{Session: os.Getenv("HOSTNAME")}
	res, err := sh.Run(ctx, src, args...)

	// The streams go to the real streams; this is a shell, not an API. A write
	// that fails (a closed pipe, a dropped exec session) fails the run, so a
	// truncated answer never exits 0.
	if _, werr := os.Stdout.WriteString(res.Stdout); werr != nil {
		fmt.Fprintf(os.Stderr, "sh: write stdout: %v\n", werr)
		return 1
	}
	if _, werr := os.Stderr.WriteString(res.Stderr); werr != nil {
		return 1
	}

	// Refusals go to stderr, and only when there were some. A glob the gate
	// stopped and a glob that matched nothing look identical on stdout, and an
	// operator reading "no output" concludes the opposite of what happened.
	if res.Denied > 0 {
		fmt.Fprintf(os.Stderr, "\nsh: the gate refused %d action(s):\n", res.Denied)
		for _, r := range res.Trail {
			if r.Kind == "denied" {
				fmt.Fprintf(os.Stderr, "  line %d: %s %s\n", r.Line, r.Action, r.Path)
			}
		}
		fmt.Fprintln(
			os.Stderr,
			"  (this shell cannot exec, and reads are bounded; see github.com/blairham/localiam/internal/shell)",
		)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "sh: %v\n", err)
		return 1
	}
	return res.Status
}

// source reads the script from -c or from stdin, and returns what `sh -c`
// binds after the script: the first word is $0 and the rest are $1, $2 and so
// on, exactly as real sh does. They are never joined into the script.
//
// There is deliberately no interactive REPL. Each run is a fresh Runner so that
// one operator's leftover variable cannot change what the next one's script
// means, and a terminal session is exactly the state that rules out.
// `kubectl exec -i ... -- /bin/sh < script` covers the same ground.
func source(argv []string) (src string, args []string, code int) {
	switch {
	case len(argv) >= 2 && argv[0] == "-c":
		return argv[1], argv[2:], 0
	case len(argv) == 0:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sh: read stdin: %v\n", err)
			return "", nil, 1
		}
		return string(b), nil, 0
	default:
		fmt.Fprintln(os.Stderr, "usage: sh -c <script> [arg0 [arg...]]   |   sh < script")
		fmt.Fprintln(os.Stderr, "a gated shell: no exec, reads bounded to /proc and /sys/fs/cgroup")
		return "", nil, 2
	}
}
