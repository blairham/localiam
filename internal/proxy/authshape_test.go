// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// The .NET services use StackExchange.Redis, which authenticates with a plain
// `AUTH <user> <token>` rather than the `HELLO 3 AUTH ...` go-redis sends. That
// branch had NO test: every end-to-end case here drives go-redis, which speaks
// RESP3, so the shape used by every .NET service was covered only
// by reading the code.
//
// There is no .NET runtime here to drive the real client, so these speak the
// wire directly. That is weaker than a real-client test — it asserts what
// StackExchange.Redis sends rather than observing it — but it is stronger than
// nothing, and the frame is simple enough to be worth pinning by hand.
func dial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

// respArray renders a command the way a client would put it on the wire.
func respArray(args ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.String()
}

func send(t *testing.T, conn net.Conn, br *bufio.Reader, args ...string) string {
	t.Helper()
	if _, err := conn.Write([]byte(respArray(args...))); err != nil {
		t.Fatalf("write %v: %v", args, err)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read reply to %v: %v", args, err)
	}
	return strings.TrimSpace(line)
}

// TestTheDotNetAuthShapeIsAccepted covers `AUTH <user> <token>` — the
// StackExchange.Redis handshake — end to end through the proxy to miniredis.
func TestTheDotNetAuthShapeIsAccepted(t *testing.T) {
	t.Parallel()
	addr := harness(t)
	conn, br := dial(t, addr)

	if got := send(t, conn, br, "AUTH", cacheUser, token(t, cacheUser, time.Now().UTC())); got != "+OK" {
		t.Fatalf("AUTH reply = %q, want +OK", got)
	}
	// The connection must now be spliced to the real Redis behind the proxy.
	if got := send(t, conn, br, "PING"); got != "+PONG" {
		t.Errorf("PING reply = %q, want +PONG", got)
	}
	if got := send(t, conn, br, "SET", "k", "v"); got != "+OK" {
		t.Errorf("SET reply = %q, want +OK", got)
	}
}

func TestTheDotNetAuthShapeIsRejectedWhenStale(t *testing.T) {
	t.Parallel()
	addr := harness(t)
	conn, br := dial(t, addr)

	stale := token(t, cacheUser, time.Now().UTC().Add(-16*time.Minute))
	got := send(t, conn, br, "AUTH", cacheUser, stale)
	if !strings.HasPrefix(got, "-WRONGPASS") {
		t.Fatalf("AUTH reply = %q, want -WRONGPASS", got)
	}
}

// TestThePasswordOnlyAuthShapeIsRefused pins that a two-argument AUTH is not a
// valid IAM handshake: ElastiCache IAM always names a user, so a bare password
// cannot be one of our tokens no matter what it contains.
func TestThePasswordOnlyAuthShapeIsRefused(t *testing.T) {
	t.Parallel()
	addr := harness(t)
	conn, br := dial(t, addr)

	got := send(t, conn, br, "AUTH", token(t, cacheUser, time.Now().UTC()))
	if !strings.HasPrefix(got, "-NOAUTH") {
		t.Errorf("AUTH reply = %q, want -NOAUTH", got)
	}
}
