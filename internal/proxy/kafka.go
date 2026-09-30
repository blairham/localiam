// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
)

// Kafka API keys this proxy cares about. Everything else is forwarded blind.
const (
	apiKeySaslHandshake    = 17
	apiKeySaslAuthenticate = 36
	apiKeyAPIVersions      = 18
)

// Mechanisms advertised to clients. Real clients use BOTH: franz-go (every Go
// service, via franz-go) speaks AWS_MSK_IAM, while the .NET and Node clients
// speak OAUTHBEARER. Advertising one would lock out half the services.
const (
	mechAWSMSKIAM   = "AWS_MSK_IAM"
	mechOAuthBearer = "OAUTHBEARER"
)

// maxFrame bounds a single Kafka request. Test traffic is small; this refuses to
// allocate on a hostile length prefix.
const maxFrame = 16 << 20

// saslMaxVersion is the highest SaslHandshake/SaslAuthenticate version this
// proxy implements.
//
// 🚨 This is clamped INTO the broker's own ApiVersions response as it passes
// through, which is what lets the proxy avoid implementing Kafka's "flexible"
// (compact/tagged) encoding at all. Raising it means implementing that
// encoding; do not raise it casually.
const saslMaxVersion = 1

// KafkaVerifier checks an MSK IAM token carried by either SASL mechanism.
type KafkaVerifier interface {
	// signedHost is the broker hostname the client signed against — the address
	// it was configured with, not necessarily an AWS endpoint.
	VerifyMSK(ctx context.Context, mechanism string, payload []byte, signedHost string) (Identity, error)
}

// KafkaOptions configures the Kafka auth-terminating proxy.
type KafkaOptions struct {
	Verify KafkaVerifier
	Logger *slog.Logger
	// TLS is presented to clients. Nil generates a self-signed certificate,
	// which only works if the client trusts it — franz-go verifies against
	// the system pool, so a cluster mounts a CA and sets SSL_CERT_FILE.
	TLS *tls.Config
	// Listen is the address clients connect to, e.g. ":9094".
	Listen string
	// Backend is the real broker's PLAINTEXT listener.
	Backend string
	// Host is the broker hostname CLIENTS use, which is both the certificate's
	// subject and the host their MSK token is signed against. Empty means the
	// AWS MSK endpoint for the region.
	Host        string
	DialTimeout time.Duration
}

// Kafka is the MSK-IAM-terminating proxy.
//
// It sits in front of the BROKERS, never beside a client: a terminator next to
// the client would be verifying a token minted by the pod it protects, and
// anything that can mint can pass that check.
type Kafka struct {
	log  *slog.Logger
	opts KafkaOptions
}

// NewKafka builds the proxy.
func NewKafka(opts KafkaOptions) (*Kafka, error) {
	switch {
	case opts.Verify == nil:
		return nil, errors.New("proxy: a KafkaVerifier is required")
	case opts.Backend == "":
		return nil, errors.New("proxy: a Backend is required")
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.TLS == nil {
		host := opts.Host
		if host == "" {
			host = "kafka"
		}
		cfg, err := selfSignedTLS(host)
		if err != nil {
			return nil, err
		}
		opts.TLS = cfg
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Kafka{opts: opts, log: log}, nil
}

// ListenAndServe binds Listen and serves until ctx is canceled.
func (p *Kafka) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", p.opts.Listen)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", p.opts.Listen, err)
	}
	p.log.Info("localiam kafka proxy listening",
		"addr", p.opts.Listen, "backend", p.opts.Backend)
	return p.Serve(ctx, tls.NewListener(ln, p.opts.TLS))
}

// Serve accepts connections until ctx is canceled.
func (p *Kafka) Serve(ctx context.Context, ln net.Listener) error {
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
				return nil //nolint:nilerr // a canceled context is a clean shutdown
			}
			return fmt.Errorf("proxy: accept: %w", err)
		}
		go p.handle(ctx, conn)
	}
}

// handle runs the request/response phase until SASL completes, then splices.
//
// The split matters: before authentication the proxy must see every request, so
// an unauthenticated client cannot reach the broker. After it, the connection is
// opaque bytes and the proxy stops parsing Kafka entirely.
func (p *Kafka) handle(ctx context.Context, client net.Conn) {
	defer func() {
		if err := client.Close(); err != nil {
			p.log.Debug("localiam: closing client", "error", err)
		}
	}()

	dialer := net.Dialer{Timeout: p.opts.DialTimeout}
	backend, err := dialer.DialContext(ctx, "tcp", p.opts.Backend)
	if err != nil {
		p.log.Error("localiam: dialing kafka backend", "backend", p.opts.Backend, "error", err)
		return
	}
	defer func() {
		if err := backend.Close(); err != nil {
			p.log.Debug("localiam: closing backend", "error", err)
		}
	}()

	for {
		authenticated, err := p.step(ctx, client, backend)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.log.Debug("localiam: sasl phase ended", "error", err)
			}
			return
		}
		if authenticated {
			// Everything from here is the broker's business.
			p.spliceKafka(client, backend)
			return
		}
	}
}

// step handles exactly one pre-authentication request, reporting whether SASL
// has now completed.
func (p *Kafka) step(ctx context.Context, client, backend net.Conn) (bool, error) {
	frame, err := readFrame(client)
	if err != nil {
		return false, err
	}
	hdr, err := parseRequestHeader(frame)
	if err != nil {
		return false, err
	}

	switch hdr.apiKey {
	case apiKeyAPIVersions:
		// Forwarded so the client learns what the REAL broker supports — then
		// the two SASL entries are clamped on the way back.
		return false, p.relayAPIVersions(client, backend, frame, hdr)
	case apiKeySaslHandshake:
		return false, p.answerHandshake(client, frame, hdr)
	case apiKeySaslAuthenticate:
		return p.answerAuthenticate(ctx, client, frame, hdr)
	default:
		// Kafka refuses non-SASL requests before authentication; so do we, by
		// closing. Forwarding would make the proxy a bypass.
		p.log.Info("localiam: kafka request before authentication",
			"apiKey", hdr.apiKey, "remote", client.RemoteAddr().String())
		return false, errors.New("proxy: request before authentication")
	}
}

// requestHeader is what the proxy needs from a Kafka request header.
type requestHeader struct {
	body        []byte // after the header
	apiKey      int16
	apiVersion  int16
	correlation int32
}

// parseRequestHeader decodes header v1: api_key, api_version, correlation_id,
// nullable client_id. Header v2 adds tagged fields, which only appear on
// flexible request versions — and the SASL versions are clamped below
// flexibility, so only ApiVersions can reach here flexible.
func parseRequestHeader(frame []byte) (requestHeader, error) {
	if len(frame) < 8 {
		return requestHeader{}, errors.New("proxy: short request header")
	}
	h := requestHeader{
		apiKey:      int16(binary.BigEndian.Uint16(frame[0:2])),
		apiVersion:  int16(binary.BigEndian.Uint16(frame[2:4])),
		correlation: int32(binary.BigEndian.Uint32(frame[4:8])),
	}
	off := 8
	if len(frame) < off+2 {
		return requestHeader{}, errors.New("proxy: no client id")
	}
	idLen := int16(binary.BigEndian.Uint16(frame[off : off+2]))
	off += 2
	if idLen > 0 {
		if len(frame) < off+int(idLen) {
			return requestHeader{}, errors.New("proxy: truncated client id")
		}
		off += int(idLen)
	}
	// Flexible request versions carry a tagged-field block here. Only
	// ApiVersions v3+ is flexible by the time it reaches this proxy.
	if h.apiKey == apiKeyAPIVersions && h.apiVersion >= 3 {
		if len(frame) > off {
			off++ // an empty tagged-field block is a single zero byte
		}
	}
	h.body = frame[off:]
	return h, nil
}

// relayAPIVersions forwards the request and clamps the SASL entries in the
// reply so clients negotiate versions this proxy actually implements.
func (p *Kafka) relayAPIVersions(client, backend net.Conn, frame []byte, hdr requestHeader) error {
	if err := writeFrame(backend, frame); err != nil {
		return err
	}
	resp, err := readFrame(backend)
	if err != nil {
		return err
	}
	clampSaslVersions(resp, hdr.apiVersion >= 3, p.log)
	return writeFrame(client, resp)
}

// clampSaslVersions rewrites the max_version of the two SASL entries in an
// ApiVersions response, in place.
//
// In place is the point: every entry is fixed width, so patching two int16s
// changes no length and the frame needs no re-encoding. That is what makes
// avoiding the flexible encoding cheap rather than a rewrite.
//
// The response header for ApiVersions is ALWAYS v0 (a bare correlation id) even
// when the body is flexible — the client has to parse it before it knows the
// version it is dealing with.
func clampSaslVersions(resp []byte, flexible bool, log *slog.Logger) {
	off := 4 // correlation id
	if len(resp) < off+2 {
		return
	}
	off += 2 // error_code

	var count int
	switch {
	case flexible:
		n, used := uvarint(resp[off:])
		if used == 0 || n == 0 {
			return
		}
		count = int(n) - 1
		off += used
	default:
		if len(resp) < off+4 {
			return
		}
		count = int(int32(binary.BigEndian.Uint32(resp[off : off+4])))
		off += 4
	}

	for range count {
		if len(resp) < off+6 {
			return
		}
		key := int16(binary.BigEndian.Uint16(resp[off : off+2]))
		if key == apiKeySaslHandshake || key == apiKeySaslAuthenticate {
			maxOff := off + 4
			if cur := int16(binary.BigEndian.Uint16(resp[maxOff : maxOff+2])); cur > saslMaxVersion {
				binary.BigEndian.PutUint16(resp[maxOff:maxOff+2], uint16(saslMaxVersion))
				log.Debug("localiam: clamped SASL api version",
					"apiKey", key, "from", cur, "to", saslMaxVersion)
			}
		}
		off += 6
		if flexible {
			_, used := uvarint(resp[off:])
			off += used
		}
	}
}

// answerHandshake replies with the mechanisms the proxy accepts.
func (p *Kafka) answerHandshake(client net.Conn, _ []byte, hdr requestHeader) error {
	requested, err := readString(hdr.body)
	if err != nil {
		return err
	}

	var errCode int16
	if requested != mechAWSMSKIAM && requested != mechOAuthBearer {
		// UNSUPPORTED_SASL_MECHANISM
		errCode = 33
		p.log.Info("localiam: unsupported sasl mechanism", "requested", requested)
	}

	body := make([]byte, 0, 64)
	body = appendInt32(body, hdr.correlation)
	body = appendInt16(body, errCode)
	body = appendInt32(body, 2)
	body = appendString(body, mechAWSMSKIAM)
	body = appendString(body, mechOAuthBearer)
	return writeFrame(client, body)
}

// answerAuthenticate verifies the presented token and reports whether the
// connection may proceed.
func (p *Kafka) answerAuthenticate(
	ctx context.Context, client net.Conn, _ []byte, hdr requestHeader,
) (bool, error) {
	payload, err := readBytesField(hdr.body)
	if err != nil {
		return false, err
	}

	mechanism, token := classifySASLPayload(payload)
	id, verr := p.opts.Verify.VerifyMSK(ctx, mechanism, token, p.opts.Host)
	if verr != nil {
		p.log.Info("localiam: kafka auth rejected",
			"mechanism", mechanism, "remote", client.RemoteAddr().String(), "reason", verr.Error())
		// SASL_AUTHENTICATION_FAILED. The client sees only this; the reason
		// lives in the line above, which is the whole diagnostic.
		return false, p.writeAuthResponse(client, hdr, 58, "localiam: authentication failed", nil)
	}

	p.log.Info("localiam: kafka auth accepted",
		"service", id.Service, "mechanism", mechanism, "principal", id.Principal,
		"tokenTTLRemaining", time.Until(id.ExpiresAt).Truncate(time.Second).String())

	// AWS_MSK_IAM expects a small JSON acknowledgement; OAUTHBEARER expects none.
	var out []byte
	if mechanism == mechAWSMSKIAM {
		out = []byte(`{"version":"2020_10_22","request-id":"localiam"}`)
	}
	return true, p.writeAuthResponse(client, hdr, 0, "", out)
}

func (p *Kafka) writeAuthResponse(
	client net.Conn, hdr requestHeader, errCode int16, errMsg string, authBytes []byte,
) error {
	body := make([]byte, 0, 128)
	body = appendInt32(body, hdr.correlation)
	body = appendInt16(body, errCode)
	if errMsg == "" {
		body = appendInt16(body, -1) // null error_message
	} else {
		body = appendString(body, errMsg)
	}
	body = appendBytes(body, authBytes)
	if hdr.apiVersion >= 1 {
		body = appendInt64(body, 0) // session_lifetime_ms: no re-auth deadline
	}
	return writeFrame(client, body)
}

// classifySASLPayload tells the two envelopes apart and unwraps OAUTHBEARER.
//
// OAUTHBEARER arrives in the SASL GS2 wrapper — "n,,\x01auth=Bearer <tok>\x01\x01"
// — while AWS_MSK_IAM is the bare JSON object franz-go builds. The leading byte
// separates them without needing the handshake's mechanism to be remembered.
func classifySASLPayload(payload []byte) (mechanism string, token []byte) {
	trimmed := strings.TrimSpace(string(payload))
	if strings.HasPrefix(trimmed, "{") {
		return mechAWSMSKIAM, payload
	}
	for _, part := range strings.Split(trimmed, "\x01") {
		if after, found := strings.CutPrefix(part, "auth=Bearer "); found {
			return mechOAuthBearer, []byte(strings.TrimSpace(after))
		}
	}
	return mechOAuthBearer, []byte(trimmed)
}

func (p *Kafka) spliceKafka(client, backend net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst io.Writer, src io.Reader, direction string) {
		if _, err := io.Copy(dst, src); err != nil {
			p.log.Debug("localiam: splice ended", "direction", direction, "error", err)
		}
		done <- struct{}{}
	}
	go pipe(backend, client, "client->backend")
	go pipe(client, backend, "backend->client")
	<-done
}

// ── framing ─────────────────────────────────────────────────────────────────

func readFrame(r io.Reader) ([]byte, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, err
	}
	size := int(int32(binary.BigEndian.Uint32(sizeBuf[:])))
	if size <= 0 || size > maxFrame {
		return nil, fmt.Errorf("proxy: frame size %d out of range", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(w io.Writer, body []byte) error {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	_, err := w.Write(out)
	return err
}

func readString(b []byte) (string, error) {
	if len(b) < 2 {
		return "", errors.New("proxy: short string")
	}
	n := int(int16(binary.BigEndian.Uint16(b[:2])))
	if n < 0 {
		return "", nil
	}
	if len(b) < 2+n {
		return "", errors.New("proxy: truncated string")
	}
	return string(b[2 : 2+n]), nil
}

func readBytesField(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, errors.New("proxy: short bytes field")
	}
	n := int(int32(binary.BigEndian.Uint32(b[:4])))
	if n < 0 {
		return nil, nil
	}
	if len(b) < 4+n {
		return nil, errors.New("proxy: truncated bytes field")
	}
	return b[4 : 4+n], nil
}

func appendInt16(b []byte, v int16) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(v))
}

func appendInt32(b []byte, v int32) []byte {
	return binary.BigEndian.AppendUint32(b, uint32(v))
}

func appendInt64(b []byte, v int64) []byte {
	return binary.BigEndian.AppendUint64(b, uint64(v))
}

func appendString(b []byte, s string) []byte {
	b = appendInt16(b, int16(len(s)))
	return append(b, s...)
}

func appendBytes(b, v []byte) []byte {
	if v == nil {
		return appendInt32(b, -1)
	}
	b = appendInt32(b, int32(len(v)))
	return append(b, v...)
}

// uvarint reads an unsigned varint, returning the value and bytes consumed.
func uvarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, c := range b {
		if i > 9 {
			return 0, 0
		}
		if c < 0x80 {
			return x | uint64(c)<<s, i + 1
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
	return 0, 0
}
