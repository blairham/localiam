// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	fraws "github.com/twmb/franz-go/pkg/sasl/aws"

	"github.com/blairham/localiam/internal/proxy"
	"github.com/blairham/localiam/verify"
)

// These tests run a real Kafka client (franz-go) through the proxy, in front
// of franz-go's in-process broker (kfake), with a policy that allows topic
// "allowed", group "allowed-group" and no transactional ids. They are the
// per-operation half of what MSK enforces: a service whose spec forgot a
// topic must fail on that topic, with the error that names it.

// policy is a KafkaAuthorizer over a fixed allow-list.
type policy struct {
	allow map[string]bool
	asked []string
	mu    sync.Mutex
}

func (p *policy) AuthorizeKafka(_ context.Context, service, action, resource string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, service+":"+action+"/"+resource)
	return p.allow[action+"/"+resource], nil
}

func newPolicy() *policy {
	return &policy{allow: map[string]bool{
		"WriteData/allowed":   true,
		"ReadData/allowed":    true,
		"Group/allowed-group": true,
	}}
}

// authzHarness starts kfake and the proxy in front of it, returning the
// proxy's address.
func authzHarness(t *testing.T, authz proxy.KafkaAuthorizer) string {
	t.Helper()

	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, "allowed", "denied"))
	if err != nil {
		t.Fatalf("kfake: %v", err)
	}
	t.Cleanup(cluster.Close)

	store := verify.NewStore()
	store.Add(verify.Principal{
		AccessKeyID: accessKey, SecretKey: secretKey,
		Service: "reports", ARN: "arn:aws:iam::000000000000:role/reports",
		Expiration: time.Now().UTC().Add(time.Hour),
	})

	p, err := proxy.NewKafka(proxy.KafkaOptions{
		Verify:    kafkaVerifier{store: store},
		Authorize: authz,
		Backend:   cluster.ListenAddrs()[0],
		// What mskBroker signs every token for.
		Host: mskBroker,
	})
	if err != nil {
		t.Fatalf("NewKafka: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tlsCfg, err := proxy.SelfSignedTLSForTest("127.0.0.1")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	go func() { _ = p.Serve(ctx, tls.NewListener(ln, tlsCfg)) }()
	return ln.Addr().String()
}

// kclient builds a franz-go client that authenticates with AWS_MSK_IAM and
// reaches every broker through the proxy. Without the dialer override the
// client would follow kfake's own address from Metadata and bypass the proxy.
func kclient(t *testing.T, proxyAddr string, opts ...kgo.Opt) *kgo.Client {
	t.Helper()
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the test's own self-signed cert
		MinVersion:         tls.VersionTLS12,
	}}
	base := []kgo.Opt{
		kgo.SeedBrokers(proxyAddr),
		kgo.Dialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, proxyAddr)
		}),
		kgo.SASL(fixedHost{fraws.ManagedStreamingIAM(func(context.Context) (fraws.Auth, error) {
			return fraws.Auth{AccessKey: accessKey, SecretKey: secretKey}, nil
		})}),
		kgo.RequestRetries(1),
		kgo.RetryTimeout(5 * time.Second),
	}
	c, err := kgo.NewClient(append(base, opts...)...)
	if err != nil {
		t.Fatalf("kgo: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func timeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestAnAllowedTopicProducesAndConsumes(t *testing.T) {
	t.Parallel()
	addr := authzHarness(t, newPolicy())
	ctx := timeout(t)

	if err := kclient(
		t,
		addr,
	).ProduceSync(ctx, &kgo.Record{Topic: "allowed", Value: []byte("hello")}).
		FirstErr(); err != nil {
		t.Fatalf("produce to an allowed topic: %v", err)
	}

	consumer := kclient(t, addr, kgo.ConsumeTopics("allowed"), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	fetches := consumer.PollRecords(ctx, 1)
	if errs := fetches.Errors(); len(errs) > 0 {
		t.Fatalf("consume an allowed topic: %v", errs[0].Err)
	}
	if n := fetches.NumRecords(); n != 1 {
		t.Fatalf("consumed %d records, want 1", n)
	}
}

func TestADeniedTopicFailsToProduceWithTopicAuthorizationFailed(t *testing.T) {
	t.Parallel()
	addr := authzHarness(t, newPolicy())

	err := kclient(t, addr).ProduceSync(timeout(t), &kgo.Record{Topic: "denied", Value: []byte("x")}).FirstErr()
	if !errors.Is(err, kerr.TopicAuthorizationFailed) {
		t.Fatalf("produce to a denied topic: want TOPIC_AUTHORIZATION_FAILED, got %v", err)
	}
}

func TestADeniedTopicFailsToConsumeWithTopicAuthorizationFailed(t *testing.T) {
	t.Parallel()
	addr := authzHarness(t, newPolicy())

	consumer := kclient(t, addr, kgo.ConsumeTopics("denied"), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	ctx := timeout(t)
	for ctx.Err() == nil {
		for _, fe := range consumer.PollFetches(ctx).Errors() {
			if errors.Is(fe.Err, kerr.TopicAuthorizationFailed) {
				return
			}
			if !errors.Is(fe.Err, context.DeadlineExceeded) {
				t.Fatalf("consume a denied topic: want TOPIC_AUTHORIZATION_FAILED, got %v", fe.Err)
			}
		}
	}
	t.Fatal("consume a denied topic: no TOPIC_AUTHORIZATION_FAILED before the deadline")
}

func TestADeniedGroupFailsWithGroupAuthorizationFailed(t *testing.T) {
	t.Parallel()
	addr := authzHarness(t, newPolicy())

	consumer := kclient(t, addr, kgo.ConsumerGroup("other-group"), kgo.ConsumeTopics("allowed"))
	ctx := timeout(t)
	for ctx.Err() == nil {
		for _, fe := range consumer.PollFetches(ctx).Errors() {
			if errors.Is(fe.Err, kerr.GroupAuthorizationFailed) {
				return
			}
			if !errors.Is(fe.Err, context.DeadlineExceeded) {
				t.Fatalf("join a denied group: want GROUP_AUTHORIZATION_FAILED, got %v", fe.Err)
			}
		}
	}
	t.Fatal("join a denied group: no GROUP_AUTHORIZATION_FAILED before the deadline")
}

func TestADeniedTransactionalIDFailsWithTransactionalIDAuthorizationFailed(t *testing.T) {
	t.Parallel()
	addr := authzHarness(t, newPolicy())

	producer := kclient(t, addr, kgo.TransactionalID("other-txn"))
	err := producer.BeginTransaction()
	if err == nil {
		err = producer.ProduceSync(timeout(t), &kgo.Record{Topic: "allowed", Value: []byte("x")}).FirstErr()
	}
	if !errors.Is(err, kerr.TransactionalIDAuthorizationFailed) {
		t.Fatalf("a denied transactional id: want TRANSACTIONAL_ID_AUTHORIZATION_FAILED, got %v", err)
	}
}

// TestDenialsKeepResponseOrder pins the ordering rule. Three requests are sent
// back to back without reading — one forwarded, one denied by the proxy, one
// forwarded — and the three responses must come back in request order. A
// denial written the moment it was decided would overtake the first response.
func TestDenialsKeepResponseOrder(t *testing.T) {
	t.Parallel()
	addr := authzHarness(t, newPolicy())
	conn := kdial(t, addr)

	// Authenticate first, over the raw connection.
	kwrite(t, conn, kafkaRequest(17, 1, 1, appendKString(nil, "AWS_MSK_IAM")))
	_ = kread(t, conn)
	payload := mskIAMPayloadFor(t, mskBroker+":9098")
	auth := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	kwrite(t, conn, kafkaRequest(36, 1, 2, append(auth, payload...)))
	if resp := kread(t, conn); binary.BigEndian.Uint16(resp[4:6]) != 0 {
		t.Fatalf("authentication failed: error code %d", binary.BigEndian.Uint16(resp[4:6]))
	}

	// Metadata v1 (forwarded), Produce v3 to "denied" (answered by the proxy),
	// ApiVersions v0 (forwarded) — pipelined.
	metadata := binary.BigEndian.AppendUint32(nil, 0xffffffff) // all topics
	produce := binary.BigEndian.AppendUint16(nil, 0xffff)      // transactional_id: null
	produce = binary.BigEndian.AppendUint16(produce, 1)        // acks
	produce = binary.BigEndian.AppendUint32(produce, 1000)     // timeout_ms
	produce = binary.BigEndian.AppendUint32(produce, 1)        // one topic
	produce = appendKString(produce, "denied")
	produce = binary.BigEndian.AppendUint32(produce, 1)          // one partition
	produce = binary.BigEndian.AppendUint32(produce, 0)          // index 0
	produce = binary.BigEndian.AppendUint32(produce, 0xffffffff) // records: null
	kwrite(t, conn, kafkaRequest(3, 1, 10, metadata))
	kwrite(t, conn, kafkaRequest(0, 3, 11, produce))
	kwrite(t, conn, kafkaRequest(18, 0, 12, nil))

	for _, want := range []int32{10, 11, 12} {
		resp := kread(t, conn)
		if got := int32(binary.BigEndian.Uint32(resp[0:4])); got != want {
			t.Fatalf("response correlation %d, want %d", got, want)
		}
		if want == 11 {
			// topics[0].name="denied", partitions[0].error_code
			off := 4 + 4 + 2 + len("denied") + 4 + 4
			if code := int16(binary.BigEndian.Uint16(resp[off : off+2])); code != 29 {
				t.Fatalf("denied produce error code %d, want 29", code)
			}
		}
	}
}

// TestNoAuthorizerKeepsTheSplice: without an Authorize the proxy does what it
// always did — authenticate, then splice — so a topic no policy allows works.
func TestNoAuthorizerKeepsTheSplice(t *testing.T) {
	t.Parallel()
	addr := authzHarness(t, nil)
	if err := kclient(
		t,
		addr,
	).ProduceSync(timeout(t), &kgo.Record{Topic: "denied", Value: []byte("x")}).
		FirstErr(); err != nil {
		t.Fatalf("produce with no authorizer: %v", err)
	}
}

// mskBroker is the MSK-style broker name every test token is signed for.
// franz-go's AWS_MSK_IAM signer reads the region off the broker hostname
// (*.kafka.<region>.amazonaws.com) and refuses 127.0.0.1, which is all
// kfake can advertise.
const mskBroker = "b-1.test.kafka." + region + ".amazonaws.com"

// fixedHost signs for mskBroker whatever address the client dialed. The token
// is still minted by franz-go's real mechanism; only the host it signs over
// is fixed.
type fixedHost struct{ sasl.Mechanism }

func (f fixedHost) Authenticate(ctx context.Context, _ string) (sasl.Session, []byte, error) {
	return f.Mechanism.Authenticate(ctx, mskBroker+":9098")
}

func appendKString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func mskIAMPayloadFor(t *testing.T, host string) []byte {
	t.Helper()
	mech := fraws.ManagedStreamingIAM(func(context.Context) (fraws.Auth, error) {
		return fraws.Auth{AccessKey: accessKey, SecretKey: secretKey}, nil
	})
	_, payload, err := mech.Authenticate(context.Background(), host)
	if err != nil {
		t.Fatalf("franz-go authenticate: %v", err)
	}
	return payload
}
