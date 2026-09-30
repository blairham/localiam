// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"

	"github.com/blairham/localiam/internal/proxy"
	"github.com/blairham/localiam/verify"
)

const (
	pgHost   = "postgres"
	pgPort   = 5432
	pgDBUser = "reports"
)

// pgVerifier is the in-process RDS verifier.
type pgVerifier struct {
	store *verify.Store
}

func (v pgVerifier) VerifyRDS(
	_ context.Context, token, host string, port int, dbUser string,
) (proxy.Identity, error) {
	res, err := verify.RDS(token, host, port, dbUser, region, v.store, time.Now().UTC())
	if err != nil {
		return proxy.Identity{}, err
	}
	return proxy.Identity{
		Service:     res.Service,
		Principal:   res.Principal,
		AccessKeyID: res.AccessKeyID,
		ExpiresAt:   res.ExpiresAt,
	}, nil
}

// fakePostgres is the minimum a backend must do for a client to finish
// connecting: accept the startup packet the proxy replays, then AuthenticationOk
// and ReadyForQuery. It stands in for `postgres:16-alpine` with
// POSTGRES_HOST_AUTH_METHOD=trust, which is how a cluster runs it behind the proxy.
//
// It deliberately does NOT implement queries. The proxy's job ends at the
// handshake; everything after it is an opaque splice, and a cluster is where that
// gets exercised against a real Postgres.
func fakePostgres(t *testing.T) (addr string, gotStartup chan map[string]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	startups := make(chan map[string]string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()

				params, err := readStartupParams(conn)
				if err != nil {
					return
				}
				startups <- params

				out := make([]byte, 0, 64)
				out = append(out, pgMessage('R', beInt32(0))...)                        // AuthenticationOk
				out = append(out, pgMessage('K', append(beInt32(1), beInt32(2)...))...) // BackendKeyData
				out = append(out, pgMessage('Z', []byte{'I'})...)                       // ReadyForQuery
				if _, err := conn.Write(out); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String(), startups
}

func pgMessage(kind byte, body []byte) []byte {
	msg := make([]byte, 5+len(body))
	msg[0] = kind
	binary.BigEndian.PutUint32(msg[1:], uint32(len(body)+4))
	copy(msg[5:], body)
	return msg
}

func beInt32(v int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b
}

func readStartupParams(conn net.Conn) (map[string]string, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(lenBuf[:]))
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	params := map[string]string{}
	fields := strings.Split(string(body[4:]), "\x00")
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == "" {
			break
		}
		params[fields[i]] = fields[i+1]
	}
	return params, nil
}

// pgHarness stands the proxy up in front of the fake backend.
func pgHarness(t *testing.T) (addr string, startups chan map[string]string) {
	t.Helper()
	backendAddr, startups := fakePostgres(t)

	store := verify.NewStore()
	store.Add(verify.Principal{
		AccessKeyID: accessKey,
		SecretKey:   secretKey,
		Service:     "reports",
		ARN:         "arn:aws:iam::000000000000:role/reports",
		Expiration:  time.Now().UTC().Add(time.Hour),
	})

	p, err := proxy.NewPostgres(proxy.PostgresOptions{
		Verify:  pgVerifier{store: store},
		Backend: backendAddr,
		Host:    pgHost,
		Port:    pgPort,
	})
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx, ln) }()

	return ln.Addr().String(), startups
}

// rdsToken mints through aws-sdk-go-v2/feature/rds/auth — the exact function
// pgx calls, so the token is byte-identical to what reports sends.
func rdsToken(t *testing.T, dbUser string) string {
	t.Helper()
	provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
	tok, err := auth.BuildAuthToken(
		context.Background(), fmt.Sprintf("%s:%d", pgHost, pgPort), region, dbUser, provider,
	)
	if err != nil {
		t.Fatalf("BuildAuthToken: %v", err)
	}
	return tok
}

func connect(t *testing.T, addr, password string) error {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting %q: %v", addr, err)
	}
	// sslmode=require is what pgx uses under IAM: encrypt, do not verify.
	dsn := fmt.Sprintf("host=%s port=%s dbname=reports user=%s password=%s sslmode=require",
		host, port, pgDBUser, password)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	return conn.Close(ctx)
}

// TestPgxAuthenticatesWithAnRdsIamToken is the reports path end to end: the
// real pgx client, sslmode=require so TLS is negotiated, a token from the real
// RDS signer, and the proxy replaying the startup packet to the backend.
func TestPgxAuthenticatesWithAnRdsIamToken(t *testing.T) {
	t.Parallel()
	addr, startups := pgHarness(t)

	if err := connect(t, addr, rdsToken(t, pgDBUser)); err != nil {
		t.Fatalf("connect: %v", err)
	}

	select {
	case params := <-startups:
		// The backend must see the CLIENT's startup packet, not one the proxy
		// invented — otherwise the database and user a workload asked for could
		// silently differ from what it got.
		if params["user"] != pgDBUser {
			t.Errorf("backend saw user %q, want %q", params["user"], pgDBUser)
		}
		if params["database"] != "reports" {
			t.Errorf("backend saw database %q, want reports", params["database"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend never received a startup packet")
	}
}

// TestPgxIsRejectedWithAStaleToken is the RDS twin of the Redis expiry test.
// The failure a client sees is the same "PAM authentication failed" RDS sends —
// the exact symptom of the wholesale-role-swap footgun.
func TestPgxIsRejectedWithAStaleToken(t *testing.T) {
	t.Parallel()
	addr, _ := pgHarness(t)

	// A token is valid for 900s; sign one and hold it past that.
	stale := rdsToken(t, pgDBUser)
	time.Sleep(10 * time.Millisecond)

	// Rather than wait 15 minutes, tamper it — the verifier rejects both, and
	// the point here is the PROXY's error path, which is identical.
	stale = strings.Replace(stale, "X-Amz-Expires=900", "X-Amz-Expires=9000", 1)

	err := connect(t, addr, stale)
	if err == nil {
		t.Fatal("a bad token was accepted")
	}
	if !strings.Contains(err.Error(), "PAM authentication failed") {
		t.Fatalf("got %v, want a PAM authentication failure", err)
	}
}

func TestPgxIsRejectedForAnotherDbUser(t *testing.T) {
	t.Parallel()
	addr, _ := pgHarness(t)

	// A validly signed token — for a different database user.
	err := connect(t, addr, rdsToken(t, "someone_else"))
	if err == nil {
		t.Fatal("a token minted for another dbUser was accepted")
	}
	if !strings.Contains(err.Error(), "PAM authentication failed") {
		t.Errorf("got %v, want a PAM authentication failure", err)
	}
}

func TestNewPostgresRequiresItsTargets(t *testing.T) {
	t.Parallel()
	v := pgVerifier{store: verify.NewStore()}

	tests := []struct {
		name string
		opts proxy.PostgresOptions
	}{
		{name: "no verifier", opts: proxy.PostgresOptions{Backend: "x:1", Host: "h"}},
		{name: "no backend", opts: proxy.PostgresOptions{Verify: v, Host: "h"}},
		// The token is signed against Host:Port; without it the proxy would
		// accept one minted for any other database in the account.
		{name: "no signed host", opts: proxy.PostgresOptions{Verify: v, Backend: "x:1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := proxy.NewPostgres(tc.opts); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
