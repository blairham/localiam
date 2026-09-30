// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Package proxy terminates authentication in front of a cluster's data stores and
// then gets out of the way.
//
// Redis has no server-side auth hook in the OSS build — no equivalent of
// Kafka's SASL callback — so the only way to make a cluster's Redis demand a real
// ElastiCache IAM token is to answer the handshake ourselves and splice the
// connection through to an untouched `redis:7-alpine` behind it.
//
// ⚠ A terminating proxy adds a hop for the connection's life. That is fine for
// correctness testing and wrong for performance testing, which is why it should
// be opt-in rather than a cluster's default.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
)

// Redis error replies, byte-for-byte what ElastiCache sends. The exact strings
// matter: WRONGPASS is what an expired token produces in ElastiCache, and
// client libraries classify auth failures by this prefix.
const (
	replyWrongPass = "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
	replyNoAuth    = "-NOAUTH Authentication required.\r\n"
	replyOK        = "+OK\r\n"
)

// Identity is what a successful verification learned.
type Identity struct {
	ExpiresAt   time.Time
	Service     string
	Principal   string
	AccessKeyID string
}

// Verifier checks an ElastiCache IAM token. It is an interface so the proxy can
// run against an in-process store or a remote localiam server without knowing
// which.
type Verifier interface {
	VerifyElastiCache(ctx context.Context, token, replicationGroupID, user string) (Identity, error)
}

// RedisOptions configures the proxy.
type RedisOptions struct {
	Verify Verifier
	Logger *slog.Logger
	// Listen is the address clients connect to, e.g. ":6379".
	Listen string
	// Backend is the real Redis, e.g. "redis.redis.svc.cluster.local:6379".
	Backend string
	// ReplicationGroupID is the host the token must have been signed against —
	// the same string the workload is configured with.
	ReplicationGroupID string
	DialTimeout        time.Duration
}

// Redis is the ElastiCache-IAM-terminating proxy.
type Redis struct {
	log  *slog.Logger
	opts RedisOptions
}

// NewRedis builds the proxy.
func NewRedis(opts RedisOptions) (*Redis, error) {
	switch {
	case opts.Verify == nil:
		return nil, errors.New("proxy: a Verifier is required")
	case opts.Backend == "":
		return nil, errors.New("proxy: a Backend is required")
	case opts.ReplicationGroupID == "":
		// Without this the proxy would accept a token minted for any
		// ElastiCache cluster in the account — validly signed, wrong target.
		return nil, errors.New("proxy: a ReplicationGroupID is required")
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 5 * time.Second
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Redis{opts: opts, log: log}, nil
}

// Serve accepts connections until ctx is canceled.
func (p *Redis) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		if err := ln.Close(); err != nil {
			p.log.Debug("localiam: closing listener", "error", err)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// A canceled context closed the listener deliberately; that is
				// a clean shutdown, not an accept failure.
				return nil //nolint:nilerr // see above
			}
			return fmt.Errorf("proxy: accept: %w", err)
		}
		go p.handle(ctx, conn)
	}
}

// ListenAndServe binds Listen and serves.
func (p *Redis) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", p.opts.Listen)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", p.opts.Listen, err)
	}
	p.log.Info("localiam redis proxy listening",
		"addr", p.opts.Listen, "backend", p.opts.Backend,
		"replicationGroup", p.opts.ReplicationGroupID)
	return p.Serve(ctx, ln)
}

func (p *Redis) handle(ctx context.Context, client net.Conn) {
	defer func() {
		if err := client.Close(); err != nil {
			p.log.Debug("localiam: closing client", "error", err)
		}
	}()

	br := bufio.NewReader(client)
	cmd, err := readCommand(br)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			p.log.Debug("localiam: reading handshake", "error", err)
		}
		return
	}

	user, token, forward, ok := parseHandshake(cmd)
	if !ok {
		// Anything before authentication gets NOAUTH, which is what a Redis
		// with an ACL user configured does.
		p.reject(client, br, replyNoAuth)
		return
	}

	id, err := p.opts.Verify.VerifyElastiCache(ctx, token, p.opts.ReplicationGroupID, user)
	if err != nil {
		// The reason never reaches the client — Redis says only WRONGPASS — so
		// the log line is the ONLY place an operator can see whether the token
		// was expired, forged, or minted for someone else. That distinction is
		// the entire point of running this in a cluster.
		p.log.Info("localiam: redis auth rejected",
			"user", user, "remote", client.RemoteAddr().String(), "reason", err.Error())
		p.reject(client, br, replyWrongPass)
		return
	}

	dialer := net.Dialer{Timeout: p.opts.DialTimeout}
	backend, err := dialer.DialContext(ctx, "tcp", p.opts.Backend)
	if err != nil {
		p.log.Error("localiam: dialing redis backend", "backend", p.opts.Backend, "error", err)
		p.reject(client, br, "-ERR localiam: backend unavailable\r\n")
		return
	}
	defer func() {
		if err := backend.Close(); err != nil {
			p.log.Debug("localiam: closing backend", "error", err)
		}
	}()

	p.log.Info("localiam: redis auth accepted",
		"service", id.Service, "user", user, "principal", id.Principal,
		// How much life the presented token had left is the direct signal for a
		// workload that is not refreshing.
		"tokenTTLRemaining", time.Until(id.ExpiresAt).Truncate(time.Second).String())

	if forward != nil {
		// A HELLO is replayed with its credentials stripped: the backend has no
		// auth of its own, and its reply flows back through the splice.
		if _, err := backend.Write(forward); err != nil {
			p.log.Error("localiam: forwarding handshake", "error", err)
			return
		}
	} else if _, err := client.Write([]byte(replyOK)); err != nil {
		p.log.Debug("localiam: writing AUTH reply", "error", err)
		return
	}

	p.splice(client, backend, br)
}

// reject refuses the connection the way a real Redis does: an error for the
// command that failed, and an error for every command already in flight behind
// it.
//
// ⚠ Answering only the first command is not enough, and the failure it causes
// is misleading. Clients pipeline their handshake — go-redis flushes HELLO and
// two CLIENT SETINFO commands together, then reads three replies. A proxy that
// writes one error and closes leaves the client reading into EOF, so the
// application sees "EOF" instead of "WRONGPASS" and the operator loses the one
// string that says why.
//
// Redis itself would answer the commands after the failure with NOAUTH. This
// deliberately repeats the ORIGINAL error instead: clients surface the LAST
// reply in a pipeline, so a NOAUTH tail throws the reason away and hands the
// application "NOAUTH Authentication required" for what was really an expired
// token. The diagnostic is the whole point of running this in a cluster, so it wins
// over matching Redis's tail behavior exactly.
func (p *Redis) reject(client net.Conn, br *bufio.Reader, reply string) {
	if _, err := client.Write([]byte(reply)); err != nil {
		p.log.Debug("localiam: writing rejection", "error", err)
		return
	}
	// Bounded: a client that keeps talking does not keep this goroutine alive.
	deadline := time.Now().Add(drainTimeout)
	if err := client.SetReadDeadline(deadline); err != nil {
		return
	}
	for time.Now().Before(deadline) {
		if _, err := readCommand(br); err != nil {
			return
		}
		if _, err := client.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// drainTimeout bounds how long a refused connection is answered before closing.
const drainTimeout = 250 * time.Millisecond

// parseHandshake pulls the ElastiCache user and token out of the first command.
//
// Both client shapes in the wild are handled:
//
//	AUTH <user> <token>              StackExchange.Redis (the .NET services)
//	HELLO 3 AUTH <user> <token>      go-redis (go-redis) and node-redis
//
// forward is the command to replay to the backend, or nil when the proxy should
// answer the client itself.
func parseHandshake(cmd command) (user, token string, forward []byte, ok bool) {
	switch cmd.name() {
	case "AUTH":
		// ElastiCache IAM always names a user, so the two-argument
		// password-only form is not a valid IAM handshake.
		if len(cmd.args) != 3 {
			return "", "", nil, false
		}
		return cmd.args[1], cmd.args[2], nil, true

	case "HELLO":
		if len(cmd.args) < 2 {
			return "", "", nil, false
		}
		for i := 1; i+2 < len(cmd.args); i++ {
			if !strings.EqualFold(cmd.args[i], "AUTH") {
				continue
			}
			// Replay the protocol negotiation without the credentials.
			return cmd.args[i+1], cmd.args[i+2], encodeCommand("HELLO", cmd.args[1]), true
		}
		return "", "", nil, false

	default:
		return "", "", nil, false
	}
}

// splice copies in both directions until either side closes.
//
// The client side is read through br, not the raw conn: a client that pipelined
// commands behind its handshake already has those bytes sitting in the reader's
// buffer, and copying from the socket would silently drop them.
func (p *Redis) splice(client, backend net.Conn, br *bufio.Reader) {
	done := make(chan struct{}, 2)
	// A copy always ends in an error when the far side closes, which is the
	// normal way a Redis connection finishes. Both directions log at debug
	// rather than treating that as a failure.
	pipe := func(dst net.Conn, src io.Reader, direction string) {
		if _, err := io.Copy(dst, src); err != nil {
			p.log.Debug("localiam: splice ended", "direction", direction, "error", err)
		}
		// Half-close so the far side sees EOF and finishes its reply.
		if tcp, ok := dst.(*net.TCPConn); ok {
			if err := tcp.CloseWrite(); err != nil {
				p.log.Debug("localiam: half-closing", "direction", direction, "error", err)
			}
		}
		done <- struct{}{}
	}
	go pipe(backend, br, "client->backend")
	go pipe(client, backend, "backend->client")
	<-done
}
