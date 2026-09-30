// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"time"
)

// Postgres protocol v3 constants.
const (
	pgProtocolV3    = 196608   // 3.0
	pgSSLRequest    = 80877103 // the magic "may I start TLS" version
	pgGSSENCRequest = 80877104

	pgMsgPassword       = 'p'
	pgMsgAuthentication = 'R'
	pgMsgError          = 'E'

	pgAuthCleartextPassword = 3

	// pgMaxStartupLen bounds the startup packet. Postgres itself caps it at
	// 10000 bytes; anything larger is a client bug or an attack.
	pgMaxStartupLen = 10000
)

// PostgresOptions configures the Postgres auth-terminating proxy.
type PostgresOptions struct {
	Verify PostgresVerifier
	Logger *slog.Logger
	// TLS is the certificate presented to clients. Nil generates a self-signed
	// one at startup, which is what a cluster wants: pgx uses sslmode=require
	// under IAM, and `require` encrypts WITHOUT verifying the certificate.
	TLS *tls.Config
	// Listen is the address clients connect to, e.g. ":5432".
	Listen string
	// Backend is the real Postgres. It must accept the proxy without a password
	// (POSTGRES_HOST_AUTH_METHOD=trust in a cluster) — the proxy replays the
	// client's startup packet verbatim and does not hold backend credentials.
	Backend string
	// Host and Port are what the token must have been signed against — the
	// values the workload was configured with, not the backend's real address.
	Host        string
	Port        int
	DialTimeout time.Duration
}

// PostgresVerifier checks an RDS IAM token.
type PostgresVerifier interface {
	VerifyRDS(ctx context.Context, token, host string, port int, dbUser string) (Identity, error)
}

// Postgres is the RDS-IAM-terminating proxy.
type Postgres struct {
	log  *slog.Logger
	opts PostgresOptions
}

// NewPostgres builds the proxy, generating a self-signed certificate when none
// is supplied.
func NewPostgres(opts PostgresOptions) (*Postgres, error) {
	switch {
	case opts.Verify == nil:
		return nil, errors.New("proxy: a PostgresVerifier is required")
	case opts.Backend == "":
		return nil, errors.New("proxy: a Backend is required")
	case opts.Host == "":
		return nil, errors.New("proxy: a Host is required — the token is signed against it")
	}
	if opts.Port == 0 {
		opts.Port = 5432
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.TLS == nil {
		cfg, err := selfSignedTLS(opts.Host)
		if err != nil {
			return nil, err
		}
		opts.TLS = cfg
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Postgres{opts: opts, log: log}, nil
}

// ListenAndServe binds Listen and serves until ctx is canceled.
func (p *Postgres) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", p.opts.Listen)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", p.opts.Listen, err)
	}
	p.log.Info("localiam postgres proxy listening",
		"addr", p.opts.Listen, "backend", p.opts.Backend,
		"signedHost", fmt.Sprintf("%s:%d", p.opts.Host, p.opts.Port))
	return p.Serve(ctx, ln)
}

// Serve accepts connections until ctx is canceled.
func (p *Postgres) Serve(ctx context.Context, ln net.Listener) error {
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

func (p *Postgres) handle(ctx context.Context, raw net.Conn) {
	defer func() {
		if err := raw.Close(); err != nil {
			p.log.Debug("localiam: closing client", "error", err)
		}
	}()

	client, startup, negErr := p.negotiate(ctx, raw)
	if negErr != nil {
		p.log.Debug("localiam: postgres handshake", "error", negErr)
		return
	}

	dbUser := startup.params["user"]
	if dbUser == "" {
		p.fail(client, "localiam: startup packet named no user")
		return
	}

	// AuthenticationCleartextPassword — the same challenge RDS issues for IAM,
	// because the "password" IS the presigned token.
	if _, writeErr := client.Write(pgAuthRequest(pgAuthCleartextPassword)); writeErr != nil {
		p.log.Debug("localiam: writing auth request", "error", writeErr)
		return
	}

	token, readErr := readPasswordMessage(client)
	if readErr != nil {
		p.log.Debug("localiam: reading password message", "error", readErr)
		return
	}

	id, err := p.opts.Verify.VerifyRDS(ctx, token, p.opts.Host, p.opts.Port, dbUser)
	if err != nil {
		// The client only ever learns that PAM auth failed — the same thing RDS
		// tells it — so this log line is the only place the REASON exists.
		p.log.Info("localiam: postgres auth rejected",
			"dbUser", dbUser, "remote", raw.RemoteAddr().String(), "reason", err.Error())
		p.fail(client, fmt.Sprintf("PAM authentication failed for user %q", dbUser))
		return
	}

	dialer := net.Dialer{Timeout: p.opts.DialTimeout}
	backend, err := dialer.DialContext(ctx, "tcp", p.opts.Backend)
	if err != nil {
		p.log.Error("localiam: dialing postgres backend", "backend", p.opts.Backend, "error", err)
		p.fail(client, "localiam: backend unavailable")
		return
	}
	defer func() {
		if err := backend.Close(); err != nil {
			p.log.Debug("localiam: closing backend", "error", err)
		}
	}()

	p.log.Info("localiam: postgres auth accepted",
		"service", id.Service, "dbUser", dbUser, "principal", id.Principal,
		"tokenTTLRemaining", time.Until(id.ExpiresAt).Truncate(time.Second).String())

	// Replay the client's startup packet verbatim. The backend trusts the proxy
	// and answers AuthenticationOk immediately, which is exactly the message the
	// client is waiting for next — so everything from here is an opaque splice.
	if _, err := backend.Write(startup.raw); err != nil {
		p.log.Error("localiam: forwarding startup packet", "error", err)
		return
	}
	p.splicePG(client, backend)
}

// startupPacket is a parsed StartupMessage.
type startupPacket struct {
	params map[string]string
	raw    []byte
}

// negotiate handles the optional SSLRequest and reads the StartupMessage.
//
// pgx sets sslmode=require under IAM (RDS rejects IAM auth in the clear),
// so a client asks for TLS before it will send anything else. `require`
// encrypts without verifying the certificate, which is why a self-signed one is
// enough here.
func (p *Postgres) negotiate(ctx context.Context, raw net.Conn) (net.Conn, startupPacket, error) {
	conn := raw
	for range 2 { // at most: one SSLRequest/GSSENCRequest, then the real startup
		pkt, err := readStartup(conn)
		if err != nil {
			return nil, startupPacket{}, err
		}
		switch pkt.version {
		case pgSSLRequest:
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return nil, startupPacket{}, err
			}
			tlsConn := tls.Server(conn, p.opts.TLS)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, startupPacket{}, fmt.Errorf("tls handshake: %w", err)
			}
			conn = tlsConn
		case pgGSSENCRequest:
			// Not supported; 'N' makes the client fall through to SSLRequest.
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, startupPacket{}, err
			}
		case pgProtocolV3:
			return conn, startupPacket{params: pkt.params, raw: pkt.raw}, nil
		default:
			return nil, startupPacket{}, fmt.Errorf("proxy: unsupported startup version %d", pkt.version)
		}
	}
	return nil, startupPacket{}, errors.New("proxy: no StartupMessage after negotiation")
}

type rawStartup struct {
	params  map[string]string
	raw     []byte
	version int32
}

func readStartup(conn net.Conn) (rawStartup, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return rawStartup{}, err
	}
	length := int(binary.BigEndian.Uint32(lenBuf[:]))
	if length < 8 || length > pgMaxStartupLen {
		return rawStartup{}, fmt.Errorf("proxy: startup length %d out of range", length)
	}

	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return rawStartup{}, err
	}
	version := int32(binary.BigEndian.Uint32(body[:4]))

	out := rawStartup{
		version: version,
		raw:     append(lenBuf[:], body...),
		params:  map[string]string{},
	}
	if version != pgProtocolV3 {
		return out, nil
	}

	// key\0value\0 ... \0
	fields := strings.Split(string(body[4:]), "\x00")
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == "" {
			break
		}
		out.params[fields[i]] = fields[i+1]
	}
	return out, nil
}

// readPasswordMessage reads the 'p' message carrying the IAM token.
func readPasswordMessage(conn net.Conn) (string, error) {
	var head [5]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", err
	}
	if head[0] != pgMsgPassword {
		return "", fmt.Errorf("proxy: expected a PasswordMessage, got %q", head[0])
	}
	length := int(binary.BigEndian.Uint32(head[1:]))
	if length < 5 || length > pgMaxStartupLen {
		return "", fmt.Errorf("proxy: password length %d out of range", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\x00"), nil
}

// pgAuthRequest builds an Authentication* message.
func pgAuthRequest(kind int32) []byte {
	buf := make([]byte, 9)
	buf[0] = pgMsgAuthentication
	binary.BigEndian.PutUint32(buf[1:], 8)
	binary.BigEndian.PutUint32(buf[5:], uint32(kind))
	return buf
}

// fail sends an ErrorResponse and closes. SQLSTATE 28P01 is invalid_password,
// which is what a client library classifies as an auth failure rather than a
// transient connection problem.
func (p *Postgres) fail(conn net.Conn, message string) {
	var body []byte
	for _, f := range []struct {
		text string
		code byte
	}{
		{code: 'S', text: "FATAL"},
		{code: 'V', text: "FATAL"},
		{code: 'C', text: "28P01"},
		{code: 'M', text: message},
	} {
		body = append(body, f.code)
		body = append(body, f.text...)
		body = append(body, 0)
	}
	body = append(body, 0)

	msg := make([]byte, 5+len(body))
	msg[0] = pgMsgError
	binary.BigEndian.PutUint32(msg[1:], uint32(len(body)+4))
	copy(msg[5:], body)

	if _, err := conn.Write(msg); err != nil {
		p.log.Debug("localiam: writing error response", "error", err)
	}
}

func (p *Postgres) splicePG(client, backend net.Conn) {
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

// selfSignedTLS generates an in-memory certificate for the proxy.
//
// A client uses sslmode=require, which encrypts but does not verify, so no
// CA distribution is needed. Anything stricter would mean shipping a private CA
// into every pod's trust store — the cost a credential server would otherwise pay and
// declined for the same reason.
func selfSignedTLS(host string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxy: generating key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxy: generating serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host, "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("proxy: creating certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, nil
}

// SelfSignedTLSForTest exposes the in-memory certificate generator to tests in
// other packages. Production callers get one implicitly from NewPostgres or
// NewKafka when they pass no TLS config.
func SelfSignedTLSForTest(host string) (*tls.Config, error) { return selfSignedTLS(host) }

// CABundle is a generated certificate authority and the server keypair it
// signed, as PEM.
type CABundle struct {
	CAPEM   []byte
	CertPEM []byte
	KeyPEM  []byte
}

// GenerateCA creates a CA and a server certificate for hosts, signed by it.
//
// A CA rather than a bare self-signed certificate because franz-go verifies
// against the system pool: the cluster mounts CAPEM and sets SSL_CERT_FILE, which
// Go's x509 honors, so no image rebuild is needed to trust the proxy.
func GenerateCA(hosts []string) (CABundle, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CABundle{}, fmt.Errorf("proxy: generating ca key: %w", err)
	}
	caTmpl, err := certTemplate("localiam CA", nil)
	if err != nil {
		return CABundle{}, err
	}
	caTmpl.IsCA = true
	caTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return CABundle{}, fmt.Errorf("proxy: creating ca: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return CABundle{}, fmt.Errorf("proxy: parsing ca: %w", err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CABundle{}, fmt.Errorf("proxy: generating server key: %w", err)
	}
	srvTmpl, err := certTemplate(hosts[0], hosts)
	if err != nil {
		return CABundle{}, err
	}
	srvTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return CABundle{}, fmt.Errorf("proxy: creating server certificate: %w", err)
	}
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return CABundle{}, fmt.Errorf("proxy: marshaling server key: %w", err)
	}

	return CABundle{
		CAPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER}),
	}, nil
}

func certTemplate(cn string, dnsNames []string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxy: generating serial: %w", err)
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, nil
}
