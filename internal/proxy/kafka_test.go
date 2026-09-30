// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	fraws "github.com/twmb/franz-go/pkg/sasl/aws"

	"github.com/blairham/localiam/internal/proxy"
	"github.com/blairham/localiam/verify"
)

// What this file covers, and what it does not.
//
// It drives the proxy's SASL phase over a real TLS connection with payloads
// produced by franz-go's own AWS_MSK_IAM mechanism — so the bytes are the ones
// every Go service in the wild actually sends. It does NOT stand up a broker:
// the post-authentication splice, ApiVersions negotiation against a real Kafka,
// and produce/fetch are a cluster's job, not a unit test's.

type kafkaVerifier struct {
	store *verify.Store
}

func (v kafkaVerifier) VerifyMSK(
	_ context.Context, mechanism string, payload []byte, signedHost string,
) (proxy.Identity, error) {
	var (
		res verify.Result
		err error
	)
	if mechanism == "AWS_MSK_IAM" {
		res, err = verify.MSKAWSMSKIAM(payload, region, signedHost, v.store, time.Now().UTC())
	} else {
		res, err = verify.MSKOAuthBearer(string(payload), region, signedHost, v.store, time.Now().UTC())
	}
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

// deadBroker accepts and does nothing. The SASL phase never reaches the broker,
// so the proxy only needs it to be dialable.
func deadBroker(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, conn) }()
		}
	}()
	return ln.Addr().String()
}

func kafkaHarness(t *testing.T) string {
	t.Helper()

	store := verify.NewStore()
	store.Add(verify.Principal{
		AccessKeyID: accessKey,
		SecretKey:   secretKey,
		Service:     "reports",
		ARN:         "arn:aws:iam::000000000000:role/reports",
		Expiration:  time.Now().UTC().Add(time.Hour),
	})

	p, err := proxy.NewKafka(proxy.KafkaOptions{
		Verify:  kafkaVerifier{store: store},
		Backend: deadBroker(t),
		// The test payloads are signed against the AWS MSK endpoint, so that is
		// the host the proxy must expect. A cluster sets this to its own broker.
		Host: "kafka." + region + ".amazonaws.com",
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

	tlsCfg, err := proxy.SelfSignedTLSForTest("kafka")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	go func() { _ = p.Serve(ctx, tls.NewListener(ln, tlsCfg)) }()

	return ln.Addr().String()
}

func kdial(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the test's own self-signed cert
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	return conn
}

// kafkaRequest builds a request header v1 plus a body.
func kafkaRequest(apiKey, apiVersion int16, correlation int32, body []byte) []byte {
	out := make([]byte, 0, 32+len(body))
	out = binary.BigEndian.AppendUint16(out, uint16(apiKey))
	out = binary.BigEndian.AppendUint16(out, uint16(apiVersion))
	out = binary.BigEndian.AppendUint32(out, uint32(correlation))
	const clientID = "localiam-test"
	out = binary.BigEndian.AppendUint16(out, uint16(len(clientID)))
	out = append(out, clientID...)
	return append(out, body...)
}

func kwrite(t *testing.T, conn net.Conn, frame []byte) {
	t.Helper()
	out := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(out, uint32(len(frame)))
	copy(out[4:], frame)
	if _, err := conn.Write(out); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func kread(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		t.Fatalf("read size: %v", err)
	}
	buf := make([]byte, binary.BigEndian.Uint32(sizeBuf[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return buf
}

// mskIAMPayload produces the AWS_MSK_IAM payload franz-go sends — the exact
// bytes franz-go puts on the wire for every Go service.
func mskIAMPayload(t *testing.T, key, secret string) []byte {
	t.Helper()
	mech := fraws.ManagedStreamingIAM(func(context.Context) (fraws.Auth, error) {
		return fraws.Auth{AccessKey: key, SecretKey: secret}, nil
	})
	_, payload, err := mech.Authenticate(context.Background(), "kafka."+region+".amazonaws.com:9098")
	if err != nil {
		t.Fatalf("franz-go authenticate: %v", err)
	}
	return payload
}

func TestSaslHandshakeAdvertisesBothMechanisms(t *testing.T) {
	t.Parallel()
	conn := kdial(t, kafkaHarness(t))

	body := make([]byte, 0, 32)
	body = binary.BigEndian.AppendUint16(body, uint16(len("AWS_MSK_IAM")))
	body = append(body, "AWS_MSK_IAM"...)
	kwrite(t, conn, kafkaRequest(17, 1, 7, body))

	resp := kread(t, conn)
	if corr := int32(binary.BigEndian.Uint32(resp[0:4])); corr != 7 {
		t.Errorf("correlation = %d, want 7", corr)
	}
	if code := int16(binary.BigEndian.Uint16(resp[4:6])); code != 0 {
		t.Fatalf("error_code = %d, want 0", code)
	}
	// A proxy advertising only one mechanism locks out half the clients.
	text := string(resp)
	if !strings.Contains(text, "AWS_MSK_IAM") || !strings.Contains(text, "OAUTHBEARER") {
		t.Errorf("response must advertise both mechanisms, got %q", text)
	}
}

func TestSaslHandshakeRefusesAnUnknownMechanism(t *testing.T) {
	t.Parallel()
	conn := kdial(t, kafkaHarness(t))

	body := make([]byte, 0, 32)
	body = binary.BigEndian.AppendUint16(body, uint16(len("SCRAM-SHA-512")))
	body = append(body, "SCRAM-SHA-512"...)
	kwrite(t, conn, kafkaRequest(17, 1, 1, body))

	resp := kread(t, conn)
	// 33 = UNSUPPORTED_SASL_MECHANISM
	if code := int16(binary.BigEndian.Uint16(resp[4:6])); code != 33 {
		t.Errorf("error_code = %d, want 33", code)
	}
}

// TestAwsMskIamAuthenticates drives the franz-go payload all the way through.
func TestAwsMskIamAuthenticates(t *testing.T) {
	t.Parallel()
	conn := kdial(t, kafkaHarness(t))

	payload := mskIAMPayload(t, accessKey, secretKey)
	body := make([]byte, 0, len(payload)+4)
	body = binary.BigEndian.AppendUint32(body, uint32(len(payload)))
	body = append(body, payload...)
	kwrite(t, conn, kafkaRequest(36, 1, 9, body))

	resp := kread(t, conn)
	if code := int16(binary.BigEndian.Uint16(resp[4:6])); code != 0 {
		t.Fatalf("error_code = %d, want 0 (accepted)", code)
	}
}

func TestAwsMskIamIsRejectedForAnUnknownKey(t *testing.T) {
	t.Parallel()
	conn := kdial(t, kafkaHarness(t))

	// Correctly signed, but by a key localiam never issued.
	payload := mskIAMPayload(t, "AKIDNOTISSUED", "a-secret-nobody-registered-aaaaaaaaaaaaaa")
	body := make([]byte, 0, len(payload)+4)
	body = binary.BigEndian.AppendUint32(body, uint32(len(payload)))
	body = append(body, payload...)
	kwrite(t, conn, kafkaRequest(36, 1, 11, body))

	resp := kread(t, conn)
	// 58 = SASL_AUTHENTICATION_FAILED
	if code := int16(binary.BigEndian.Uint16(resp[4:6])); code != 58 {
		t.Errorf("error_code = %d, want 58", code)
	}
}

// TestOAuthBearerAuthenticates covers the .NET and Node path: the same
// signature, wrapped in the SASL GS2 envelope instead of the JSON one.
func TestOAuthBearerAuthenticates(t *testing.T) {
	t.Parallel()
	conn := kdial(t, kafkaHarness(t))

	raw := presignMSK(t)
	bearer := base64.RawURLEncoding.EncodeToString([]byte("https://" + raw))
	envelope := "n,,\x01auth=Bearer " + bearer + "\x01\x01"

	body := make([]byte, 0, len(envelope)+4)
	body = binary.BigEndian.AppendUint32(body, uint32(len(envelope)))
	body = append(body, envelope...)
	kwrite(t, conn, kafkaRequest(36, 1, 13, body))

	resp := kread(t, conn)
	if code := int16(binary.BigEndian.Uint16(resp[4:6])); code != 0 {
		t.Fatalf("error_code = %d, want 0 (accepted)", code)
	}
}

// TestAnUnauthenticatedRequestIsRefused pins that the proxy is a real gate: a
// Metadata request before SASL must not reach the broker.
func TestAnUnauthenticatedRequestIsRefused(t *testing.T) {
	t.Parallel()
	conn := kdial(t, kafkaHarness(t))

	kwrite(t, conn, kafkaRequest(3, 9, 1, []byte{0, 0, 0, 0})) // Metadata

	var sizeBuf [4]byte
	_, err := io.ReadFull(conn, sizeBuf[:])
	if err == nil {
		t.Fatal("the proxy answered an unauthenticated Metadata request")
	}
}

// presignMSK mints an MSK connect token through aws-sdk-go-v2's presigner.
func presignMSK(t *testing.T) string {
	t.Helper()
	q := url.Values{"Action": {"kafka-cluster:Connect"}, "X-Amz-Expires": {"900"}}
	u := url.URL{Scheme: "https", Host: "kafka." + region + ".amazonaws.com", Path: "/", RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	signed, _, err := v4.NewSigner().PresignHTTP(
		context.Background(), creds, req, emptyPayloadHash, "kafka-cluster", region, time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("presigning: %v", err)
	}
	return strings.TrimPrefix(signed, "https://")
}
