// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Command localiam runs every role of the local IAM plane.
//
//	localiam agent  — the per-pod sidecar: serves the EKS Pod Identity agent
//	               contract on loopback so the workload's own production code
//	               can mint SigV4 tokens, and pushes each issued credential to
//	               the central server.
//	localiam server — the central half: holds the credentials every agent issues
//	               and answers the store adapters' verification and
//	               authorization calls.
//
// See docs/architecture/iam-auth.md for how the two fit together, and
// docs/rfcs/0001-credential-issuance-topology.md for why the agent is a sidecar
// rather than a central service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const usage = `localiam — local AWS IAM auth for Redis, Postgres and Kafka

usage:
  localiam agent     [flags]   run the per-pod credential sidecar
  localiam server    [flags]   run the central verifier
  localiam proxy     [flags]   run an auth-terminating proxy beside a store
  localiam gen-certs [flags]   emit a CA + server keypair for the TLS-terminating proxies

run "localiam <command> -h" for a command's flags
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "agent":
		err = runAgent(os.Args[2:])
	case "server":
		err = runServer(os.Args[2:])
	case "proxy":
		err = runProxy(os.Args[2:])
	case "gen-certs":
		err = runGenCerts(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "localiam: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		slog.Error("localiam: exiting", "error", err)
		os.Exit(1)
	}
}

// envOrInt is the fallback that lets a deployment manifest supply an address.
//
// Kubernetes and compose templating commonly substitute into `env:` values but
// not args, and a cluster's namespaces often carry a per-engineer prefix, so the
// backend addresses cannot be written as literals in a manifest. Reading them
// from the environment is what lets the manifest name them at all.
func envOrInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		slog.Warn("localiam: ignoring unparseable env value", "name", name, "value", v)
	}
	return def
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// serve runs an HTTP server until SIGINT/SIGTERM, then drains.
func serve(addr string, h http.Handler) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveCtx(ctx, addr, h)
}

// serveCtx runs an HTTP server until ctx is canceled, then drains. Split from
// serve so the server command can share one signal context across the API
// listener and the Redis proxy.
func serveCtx(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("localiam: shutting down")
		// ctx is already canceled here; WithoutCancel keeps its values while giving
		// the drain its own deadline.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
