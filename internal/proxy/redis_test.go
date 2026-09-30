// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy_test

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/redis/go-redis/v9"

	"github.com/blairham/localiam/internal/proxy"
	"github.com/blairham/localiam/verify"
)

const (
	accessKey   = "AKIDEXAMPLE"
	secretKey   = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	region      = "us-east-1"
	cacheGroup  = "localiam-redis"
	cacheUser   = "localiam-iam"
	workloadARN = "arn:aws:iam::000000000000:role/api"

	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// storeVerifier is the in-process Verifier — what `localiam server` uses when the
// proxy shares its address space with the credential store.
type storeVerifier struct {
	store *verify.Store
}

func (v storeVerifier) VerifyElastiCache(
	_ context.Context, token, group, user string,
) (proxy.Identity, error) {
	res, err := verify.ElastiCache(token, group, user, region, v.store, time.Now().UTC())
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

// harness stands up miniredis as the untouched backend with the proxy in front,
// and returns the proxy's address.
func harness(t *testing.T) string {
	t.Helper()

	backend := miniredis.RunT(t)

	store := verify.NewStore()
	store.Add(verify.Principal{
		AccessKeyID: accessKey,
		SecretKey:   secretKey,
		Service:     "api",
		ARN:         workloadARN,
		Expiration:  time.Now().UTC().Add(time.Hour),
	})

	p, err := proxy.NewRedis(proxy.RedisOptions{
		Verify:             storeVerifier{store: store},
		Backend:            backend.Addr(),
		ReplicationGroupID: cacheGroup,
	})
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx, ln) }()

	return ln.Addr().String()
}

// token mints an ElastiCache IAM token the way go-redis does.
func token(t *testing.T, user string, at time.Time) string {
	t.Helper()
	q := url.Values{"Action": {"connect"}, "User": {user}, "X-Amz-Expires": {"900"}}
	u := url.URL{Scheme: "https", Host: cacheGroup, Path: "/", RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, u.String(), http.NoBody,
	)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	signed, _, err := v4.NewSigner().PresignHTTP(
		context.Background(), creds, req, emptyPayloadHash, "elasticache", region, at,
	)
	if err != nil {
		t.Fatalf("presigning: %v", err)
	}
	return strings.TrimPrefix(signed, "https://")
}

// client builds a go-redis client that mints a fresh token per connection —
// exactly go-redis's CredentialsProviderContext shape.
func client(t *testing.T, addr string, mint func() string) *redis.Client {
	t.Helper()
	c := redis.NewClient(&redis.Options{
		Addr:     addr,
		Username: cacheUser,
		CredentialsProviderContext: func(context.Context) (string, string, error) {
			return cacheUser, mint(), nil
		},
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestARealClientAuthenticatesAndTalksToRedis is the end-to-end shape a cluster
// runs: the production client library, an IAM token it minted itself, the proxy
// verifying it, and an untouched Redis behind.
func TestARealClientAuthenticatesAndTalksToRedis(t *testing.T) {
	t.Parallel()
	addr := harness(t)
	c := client(t, addr, func() string { return token(t, cacheUser, time.Now().UTC()) })

	ctx := context.Background()
	if err := c.Ping(ctx).Err(); err != nil {
		t.Fatalf("PING through the proxy: %v", err)
	}
	if err := c.Set(ctx, "localiam:ping", "open", 0).Err(); err != nil {
		t.Fatalf("SET: %v", err)
	}
	got, err := c.Get(ctx, "localiam:ping").Result()
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if got != "open" {
		t.Errorf("GET = %q, want open", got)
	}
}

// TestAnExpiredTokenGetsWrongpass is the mint-once-never-refresh bug
// reproduced on a laptop: a token minted 16 minutes ago, presented on a new
// connection, gets the same WRONGPASS ElastiCache sends.
func TestAnExpiredTokenGetsWrongpass(t *testing.T) {
	t.Parallel()
	minted := time.Now().UTC().Add(-16 * time.Minute)
	addr := harness(t)

	// The stale token a pod would replay on reconnect.
	c := client(t, addr, func() string { return token(t, cacheUser, minted) })

	err := c.Ping(context.Background()).Err()
	if err == nil {
		t.Fatal("an expired token was accepted")
	}
	if !strings.Contains(err.Error(), "WRONGPASS") {
		t.Fatalf("got %v, want WRONGPASS", err)
	}
}

func TestRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "a token minted for a different ElastiCache user",
			token: token(t, "someone-else", time.Now().UTC()),
		},
		{
			name: "a tampered token",
			token: strings.Replace(token(t, cacheUser, time.Now().UTC()),
				"X-Amz-Expires=900", "X-Amz-Expires=9000", 1),
		},
		{
			name:  "a static password instead of a token",
			token: "hunter2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := harness(t)
			c := client(t, addr, func() string { return tc.token })

			err := c.Ping(context.Background()).Err()
			if err == nil {
				t.Fatal("expected a rejection")
			}
			if !strings.Contains(err.Error(), "WRONGPASS") {
				t.Errorf("got %v, want WRONGPASS", err)
			}
		})
	}
}

// TestAnUnauthenticatedClientGetsNoauth pins that the proxy is a real gate: a
// client that never authenticates cannot reach the Redis behind it.
func TestAnUnauthenticatedClientGetsNoauth(t *testing.T) {
	t.Parallel()
	addr := harness(t)

	c := redis.NewClient(&redis.Options{Addr: addr}) // no credentials at all
	defer func() { _ = c.Close() }()

	err := c.Ping(context.Background()).Err()
	if err == nil {
		t.Fatal("an unauthenticated client reached Redis")
	}
	if !strings.Contains(err.Error(), "NOAUTH") && !strings.Contains(err.Error(), "WRONGPASS") {
		t.Errorf("got %v, want NOAUTH", err)
	}
}

func TestNewRedisRequiresItsTargets(t *testing.T) {
	t.Parallel()
	v := storeVerifier{store: verify.NewStore()}

	tests := []struct {
		name string
		opts proxy.RedisOptions
	}{
		{name: "no verifier", opts: proxy.RedisOptions{Backend: "x:1", ReplicationGroupID: "g"}},
		{name: "no backend", opts: proxy.RedisOptions{Verify: v, ReplicationGroupID: "g"}},
		// Without this the proxy accepts a validly-signed token minted for any
		// other cluster in the account.
		{name: "no replication group", opts: proxy.RedisOptions{Verify: v, Backend: "x:1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := proxy.NewRedis(tc.opts); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
