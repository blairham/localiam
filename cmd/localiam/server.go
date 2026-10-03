// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/blairham/localiam/internal/policy"
	"github.com/blairham/localiam/internal/proxy"
	"github.com/blairham/localiam/internal/server"
	"github.com/blairham/localiam/internal/shell"
	"github.com/blairham/localiam/verify"
)

// localVerifier is what the proxies `localiam server` hosts in-process verify
// through. The server and those proxies share an address space, so there is no
// HTTP hop — but every call still goes through the server's Verify methods,
// the same path the HTTP API takes, so the service's connect policy applies no
// matter where a proxy runs. (It once called the verifier directly and skipped
// policy entirely; TestServerHostedProxiesApplyPolicy pins that shut.)
type localVerifier struct {
	srv *server.Server
}

func (v localVerifier) VerifyRDS(
	ctx context.Context, token, host string, port int, dbUser string,
) (proxy.Identity, error) {
	res, err := v.srv.VerifyRDS(ctx, token, host, port, dbUser)
	if err != nil {
		return proxy.Identity{}, err
	}
	return identityOf(res), nil
}

func (v localVerifier) VerifyMSK(
	ctx context.Context, mechanism string, payload []byte, signedHost string,
) (proxy.Identity, error) {
	res, err := v.srv.VerifyMSK(ctx, mechanism, payload, signedHost)
	if err != nil {
		return proxy.Identity{}, err
	}
	return identityOf(res), nil
}

func (v localVerifier) VerifyElastiCache(
	ctx context.Context, token, group, user string,
) (proxy.Identity, error) {
	res, err := v.srv.VerifyElastiCache(ctx, token, group, user)
	if err != nil {
		return proxy.Identity{}, err
	}
	return identityOf(res), nil
}

// AuthorizeKafka answers the Kafka proxy's per-operation questions through
// the server's own Authorize — the path POST /v1/authorize takes.
func (v localVerifier) AuthorizeKafka(ctx context.Context, service, action, resource string) (bool, error) {
	allowed, _, err := v.srv.Authorize(ctx, service, action, resource)
	return allowed, err
}

func identityOf(res verify.Result) proxy.Identity {
	return proxy.Identity{
		Service:     res.Service,
		Principal:   res.Principal,
		AccessKeyID: res.AccessKeyID,
		ExpiresAt:   res.ExpiresAt,
	}
}

// serverFlags is everything `localiam server` is configured with.
type serverFlags struct {
	redisBackend string
	listen       string
	pgBackend    string
	specs        string
	token        string
	principals   string
	redisListen  string
	region       string
	pgListen     string
	redisGroup   string
	kafkaCert    string
	pgHost       string
	kafkaKey     string
	kafkaListen  string
	kafkaBackend string
	pgPort       int
}

func parseServerFlags(args []string) (serverFlags, error) {
	var f serverFlags
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	fs.StringVar(&f.listen, "listen", ":8080", "address to serve the verification API on")
	fs.StringVar(&f.region, "region", "us-east-1", "AWS region the tokens are scoped to")
	fs.StringVar(&f.specs, "specs", "",
		"directory of service spec *.yaml files to enforce; empty means authenticate only, never authorize")
	fs.StringVar(
		&f.token,
		"token",
		"",
		"bearer token agents must present to register (required)",
	)
	fs.StringVar(&f.principals, "principals", "",
		"JSON file of bootstrap principals to preload (see verify.LoadStore)")

	fs.StringVar(&f.redisListen, "redis-proxy-listen", "",
		"also run the Redis IAM proxy on this address, e.g. :6379 (empty disables it)")
	fs.StringVar(&f.redisBackend, "redis-backend", "",
		"the real Redis the proxy fronts, e.g. redis.redis.svc.cluster.local:6379")
	fs.StringVar(&f.redisGroup, "redis-replication-group", "",
		"ElastiCache replication group id the token must be signed against")

	fs.StringVar(&f.pgListen, "pg-proxy-listen", "",
		"also run the Postgres IAM proxy on this address, e.g. :5432 (empty disables it)")
	fs.StringVar(&f.pgBackend, "pg-backend", envOr("LOCALIAM_PG_BACKEND", ""),
		"the real Postgres the proxy fronts (env: LOCALIAM_PG_BACKEND)")
	// The RDS token is signed against the host:port the WORKLOAD was configured
	// with — which in a cluster is a templated FQDN, so it can only arrive through
	// the environment.
	fs.StringVar(&f.pgHost, "pg-host", envOr("LOCALIAM_PG_HOST", "postgres"),
		"hostname the RDS token is signed against (env: LOCALIAM_PG_HOST)")
	fs.IntVar(&f.pgPort, "pg-port", envOrInt("LOCALIAM_PG_PORT", 5432),
		"port the RDS token is signed against (env: LOCALIAM_PG_PORT)")

	fs.StringVar(&f.kafkaListen, "kafka-proxy-listen", "",
		"also run the Kafka IAM proxy on this address, e.g. :9094 (empty disables it)")
	fs.StringVar(&f.kafkaBackend, "kafka-backend", envOr("LOCALIAM_KAFKA_BACKEND", ""),
		"the real broker's PLAINTEXT listener (env: LOCALIAM_KAFKA_BACKEND)")
	fs.StringVar(&f.kafkaCert, "kafka-tls-cert", "", "PEM certificate presented to Kafka clients")
	fs.StringVar(&f.kafkaKey, "kafka-tls-key", "", "PEM private key for -kafka-tls-cert")

	return f, fs.Parse(args)
}

func runServer(args []string) error {
	f, err := parseServerFlags(args)
	if err != nil {
		return err
	}

	// A nil spec map means "authenticate only"; an EMPTY one would deny every
	// service. The distinction is load-bearing in server.New, so it is kept here
	// rather than hidden behind a helper that returns nil, nil.
	var loaded map[string]*policy.Spec
	if f.specs == "" {
		slog.Warn("localiam: no service specs loaded — every authenticated identity is permitted")
	} else {
		if loaded, err = policy.LoadDir(f.specs); err != nil {
			return err
		}
		slog.Info("localiam: loaded service policies", "count", len(loaded), "dir", f.specs)
	}

	// Bootstrap principals exist for one reason: a pod's INIT containers run to
	// completion BEFORE any regular container starts, so a credential agent that
	// is a sidecar is not listening yet when an init step needs AWS credentials.
	// A schema migration is exactly that shape. A long-lived static key the init
	// step carries in its env covers the gap; the workload itself still goes
	// through the full Pod Identity path.
	//
	// The proper fix is a NATIVE sidecar (an initContainer with
	// restartPolicy: Always, Kubernetes 1.29+), which starts before other init
	// containers and keeps running. That is a change to how the cluster renders its
	// pods, not one this repo can make.
	store, err := loadPrincipals(f.principals)
	if err != nil {
		return err
	}

	if f.token == "" {
		return errors.New(
			"server: -token is required (the Helm chart generates one; on a laptop any value works, e.g. -token dev)",
		)
	}

	srv, err := server.New(
		server.Options{Store: store, Specs: loaded, Token: f.token, Region: f.region},
	)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// One slot per goroutine that can send, so none blocks after the first error.
	errCh := make(chan error, 4)
	if err := startProxies(ctx, f, localVerifier{srv: srv}, errCh); err != nil {
		return err
	}

	slog.Info("localiam server listening", "addr", f.listen, "region", f.region)
	go func() { errCh <- serveCtx(ctx, f.listen, withShell(srv.Handler())) }()

	return <-errCh
}

// startProxies starts each auth-terminating proxy the server was asked to host
// alongside the credential store, sharing its in-process verifier.
func startProxies(ctx context.Context, f serverFlags, v localVerifier, errCh chan<- error) error {
	if f.pgListen != "" {
		pp, err := proxy.NewPostgres(proxy.PostgresOptions{
			Verify: v, Listen: f.pgListen, Backend: f.pgBackend, Host: f.pgHost, Port: f.pgPort,
		})
		if err != nil {
			return err
		}
		go func() { errCh <- pp.ListenAndServe(ctx) }()
	}

	if f.kafkaListen != "" {
		kp, err := newKafkaProxy(v, f.kafkaListen, f.kafkaBackend, "", f.kafkaCert, f.kafkaKey)
		if err != nil {
			return err
		}
		go func() { errCh <- kp.ListenAndServe(ctx) }()
	}

	if f.redisListen != "" {
		rp, err := proxy.NewRedis(proxy.RedisOptions{
			Verify: v, Listen: f.redisListen, Backend: f.redisBackend, ReplicationGroupID: f.redisGroup,
		})
		if err != nil {
			return err
		}
		go func() { errCh <- rp.ListenAndServe(ctx) }()
	}
	return nil
}

// loadPrincipals builds the credential store, preloaded with the bootstrap
// principals in path when one is named.
func loadPrincipals(path string) (*verify.Store, error) {
	store := verify.NewStore()
	if path == "" {
		return store, nil
	}
	loaded, err := verify.LoadStore(path)
	if err != nil {
		return nil, err
	}
	for _, p := range loaded.All() {
		store.Add(p)
	}
	slog.Info("localiam: preloaded bootstrap principals", "count", store.Len())
	return store, nil
}

// withShell mounts the gated shell beside the API. It mounts only when
// LOCALIAM_SHELL_TOKEN is set, so a deployment that has not been given the
// token answers 404 and "is it on here" is a question you can ask the pod
// rather than its manifest. The image is distroless; this and /bin/sh are how
// you read /proc in it. See internal/shell/README.md.
func withShell(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", api)
	if shell.Register(mux, shell.Config{
		Token:   os.Getenv("LOCALIAM_SHELL_TOKEN"),
		Session: os.Getenv("HOSTNAME"),
	}) {
		slog.Info("localiam: shell mounted", "path", shell.Path)
	}
	return mux
}
