// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/blairham/localiam/internal/client"
	"github.com/blairham/localiam/internal/proxy"
)

// runProxy runs auth terminators as a SIDECAR IN THE STORE'S OWN POD.
//
// 🚨 This is where a terminator belongs, and it is not where the credential
// agent belongs. Co-located with its store, the plaintext hop from proxy to
// backend is over loopback inside the pod — so the backend can bind 127.0.0.1
// and the proxy is the ONLY way in. Running the terminator as its own pod
// instead leaves the store reachable directly over the cluster network, which
// makes the proxy a convention rather than a gate.
//
// The credential agent is the opposite case: it belongs in the WORKLOAD's pod,
// because it stands in for the per-pod EKS Pod Identity agent and the AWS SDK
// refuses its endpoint anywhere but loopback.
//
// A proxy sidecar holds no secret keys. It asks the central server, which is
// the only component that can answer, because credentials are issued per pod
// and verified at the shared stores.
func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	var (
		verifyURL = fs.String("verify-url", envOr("LOCALIAM_VERIFY_URL", ""),
			"base URL of the central localiam server (env: LOCALIAM_VERIFY_URL)")

		pgListen  = fs.String("pg-listen", "", "serve the Postgres proxy here, e.g. :5432")
		pgBackend = fs.String("pg-backend", envOr("LOCALIAM_PG_BACKEND", "127.0.0.1:5433"),
			"the real Postgres, normally on loopback in this pod")
		// The RDS token is signed against the host:port the WORKLOAD was
		// configured with — which in a cluster is a templated FQDN, so it can
		// only arrive through the environment.
		pgHost = fs.String("pg-host", envOr("LOCALIAM_PG_HOST", "postgres"),
			"hostname the RDS token is signed against (env: LOCALIAM_PG_HOST)")
		pgPort = fs.Int("pg-port", envOrInt("LOCALIAM_PG_PORT", 5432),
			"port the RDS token is signed against (env: LOCALIAM_PG_PORT)")

		kafkaListen  = fs.String("kafka-listen", "", "serve the Kafka proxy here, e.g. :9094")
		kafkaBackend = fs.String("kafka-backend", envOr("LOCALIAM_KAFKA_BACKEND", "127.0.0.1:9095"),
			"the broker's PLAINTEXT listener, normally on loopback in this pod")
		kafkaCert = fs.String("kafka-tls-cert", "", "PEM certificate presented to Kafka clients")
		kafkaKey  = fs.String("kafka-tls-key", "", "PEM private key for -kafka-tls-cert")
		// The hostname CLIENTS dial, which is what their MSK token is signed
		// against. Empty falls back to the AWS endpoint for the region.
		kafkaHost = fs.String("kafka-host", envOr("LOCALIAM_KAFKA_HOST", ""),
			"broker hostname clients use and sign against (env: LOCALIAM_KAFKA_HOST)")

		redisListen  = fs.String("redis-listen", "", "serve the Redis proxy here, e.g. :6379")
		redisBackend = fs.String("redis-backend", envOr("LOCALIAM_REDIS_BACKEND", "127.0.0.1:6380"),
			"the real Redis, normally on loopback in this pod")
		redisGroup = fs.String("redis-replication-group", "",
			"ElastiCache replication group id the token must be signed against")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *verifyURL == "" {
		return errors.New("proxy: -verify-url is required")
	}
	if *pgListen == "" && *kafkaListen == "" && *redisListen == "" {
		return errors.New("proxy: name at least one of -pg-listen, -kafka-listen, -redis-listen")
	}

	v := client.New(*verifyURL)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 3)

	if *pgListen != "" {
		pp, err := proxy.NewPostgres(proxy.PostgresOptions{
			Verify: v, Listen: *pgListen, Backend: *pgBackend, Host: *pgHost, Port: *pgPort,
		})
		if err != nil {
			return err
		}
		go func() { errCh <- pp.ListenAndServe(ctx) }()
	}

	if *kafkaListen != "" {
		kp, err := newKafkaProxy(v, *kafkaListen, *kafkaBackend, *kafkaHost, *kafkaCert, *kafkaKey)
		if err != nil {
			return err
		}
		go func() { errCh <- kp.ListenAndServe(ctx) }()
	}

	if *redisListen != "" {
		rp, err := proxy.NewRedis(proxy.RedisOptions{
			Verify: v, Listen: *redisListen, Backend: *redisBackend,
			ReplicationGroupID: *redisGroup,
		})
		if err != nil {
			return err
		}
		go func() { errCh <- rp.ListenAndServe(ctx) }()
	}

	slog.Info("localiam proxy sidecar running", "verifier", *verifyURL,
		"postgres", *pgListen, "kafka", *kafkaListen, "redis", *redisListen)
	return <-errCh
}

// kafkaGate is what the Kafka terminator needs from its verifier: authenticate
// the SASL token, then authorize each topic, group and transactional id.
type kafkaGate interface {
	proxy.KafkaVerifier
	proxy.KafkaAuthorizer
}

// newKafkaProxy builds the Kafka terminator, loading an operator-supplied
// keypair when one is named. Split out of runProxy purely for length.
func newKafkaProxy(
	v kafkaGate, listen, backend, host, certFile, keyFile string,
) (*proxy.Kafka, error) {
	var tlsCfg *tls.Config
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading kafka tls keypair: %w", err)
		}
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	return proxy.NewKafka(proxy.KafkaOptions{
		Verify: v, Authorize: v, Listen: listen, Backend: backend, TLS: tlsCfg, Host: host,
	})
}
