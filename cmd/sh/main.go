// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Command sh is localiam's gated shell, installed at /bin/sh in the distroless
// image so that `kubectl exec <pod> -- /bin/sh -c '<script>'` works.
//
// The shell, its policy and its front end live in github.com/blairham/sh/gated;
// this file is that package's ExampleMain and nothing more. The model (it
// cannot exec anything, ever, and its reads are bounded to /proc and
// /sys/fs/cgroup) is documented in gated/README.md in that repository. The
// HTTP endpoint in internal/shell wraps the same gated.Shell, so there is no
// second boundary to keep in agreement with the first.
//
// The Dockerfile builds it beside localiam and installs it at /bin/sh.
//
// Only install it at /bin/sh in an image that has no other shell or userland.
// Beside busybox the gate protects nothing: `ls`, `wget` and the rest are
// still there to exec from anything that is not this binary.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/blairham/sh/gated"
)

func main() {
	os.Exit(run())
}

// run is split from main so that `defer stop()` runs before os.Exit, which
// skips deferred calls. ExampleMain upstream is the same lines in one function.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return gated.Main(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv("HOSTNAME"))
}
