// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Per-operation authorization after SASL.
//
// MSK authorizes every topic, group and transactional id, not just the
// connection, so a service whose spec forgot a topic fails when it first
// touches it. Splicing after authentication hid exactly that bug. With an
// Authorize set, the proxy keeps framing requests after SASL and checks the
// three requests every such operation goes through:
//
//	Produce          every topic needs WriteData
//	Fetch            every topic needs ReadData
//	FindCoordinator  a group needs Group, a transactional id TransactionalId —
//	                 every group and transaction operation starts here
//
// A denied request is answered by the proxy with the Kafka authorization error
// (TOPIC_ / GROUP_ / TRANSACTIONAL_ID_AUTHORIZATION_FAILED), so the client
// names the missing grant. Everything else goes to the broker untouched.

// Kafka API keys enforced after authentication.
const (
	apiKeyProduce         = 0
	apiKeyFetch           = 1
	apiKeyFindCoordinator = 10
)

// The newest version of each enforced API that is not "flexible" (compact
// strings, tagged fields). Capping clients here in the ApiVersions reply — the
// same trick saslMaxVersion uses — means the proxy decodes and encodes only
// the classic format. Every current client and broker supports these.
const (
	produceMaxVersion         = 8  // v9 is flexible
	fetchMaxVersion           = 11 // v12 is flexible
	findCoordinatorMaxVersion = 2  // v3 is flexible
)

// The oldest versions the decoders handle. Kafka 4 brokers no longer accept
// anything older, and the request layouts below assume these fields exist.
const (
	produceMinVersion = 3 // transactional_id
	fetchMinVersion   = 4 // isolation_level
)

// Kafka error codes the proxy answers with.
const (
	errTopicAuthorizationFailed         = 29
	errGroupAuthorizationFailed         = 30
	errTransactionalIDAuthorizationFail = 53
)

// Policy action names, as POST /v1/authorize spells them.
const (
	actionReadData        = "ReadData"
	actionWriteData       = "WriteData"
	actionGroup           = "Group"
	actionTransactionalID = "TransactionalId"
)

// KafkaAuthorizer answers one per-operation policy question for an
// authenticated service.
type KafkaAuthorizer interface {
	AuthorizeKafka(ctx context.Context, service, action, resource string) (bool, error)
}

// versionLimits is the cap applied to the broker's ApiVersions reply.
func (p *Kafka) versionLimits() map[int16]int16 {
	limits := map[int16]int16{
		apiKeySaslHandshake:    saslMaxVersion,
		apiKeySaslAuthenticate: saslMaxVersion,
	}
	if p.opts.Authorize != nil {
		limits[apiKeyProduce] = produceMaxVersion
		limits[apiKeyFetch] = fetchMaxVersion
		limits[apiKeyFindCoordinator] = findCoordinatorMaxVersion
	}
	return limits
}

// reply is one response the client is owed, in request order: either the
// broker's next response, or a frame the proxy wrote itself.
type reply struct {
	synthetic []byte // non-nil: send this instead of reading the broker
	clamp     bool   // ApiVersions: patch the broker's reply on the way back
	flexible  bool   // ...whose body is in the flexible encoding
}

// enforce runs the authenticated connection: requests are checked and either
// forwarded or answered, and replies go back strictly in request order.
//
// Order is the hard part. Clients pipeline several requests before reading a
// response, so a denial cannot be written the moment it is decided — it would
// overtake the broker's responses to earlier requests. Each request instead
// queues the reply it is owed, and one writer drains the queue: a synthetic
// reply is written as is, a broker reply is read off the backend in turn.
func (p *Kafka) enforce(ctx context.Context, client, backend net.Conn, id Identity) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			p.closeConn(client, "client")
			p.closeConn(backend, "backend")
		})
	}

	queue := make(chan reply, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer stop()
		p.writeReplies(client, backend, queue)
	}()

	g := gate{p: p, id: id, decisions: map[string]bool{}}
	p.readRequests(ctx, client, backend, &g, queue)
	close(queue)
	<-done
	stop()
}

// writeReplies drains the reply queue to the client until it closes or a
// write fails.
func (p *Kafka) writeReplies(client, backend net.Conn, queue <-chan reply) {
	for r := range queue {
		if err := p.deliver(client, backend, r); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				p.log.Debug("localiam: kafka reply ended", "error", err)
			}
			return
		}
	}
}

// readRequests decides each client request in turn, queueing the reply it is
// owed, until the client goes away or a request cannot be handled.
func (p *Kafka) readRequests(ctx context.Context, client, backend net.Conn, g *gate, queue chan<- reply) {
	for ctx.Err() == nil {
		frame, err := readFrame(client)
		if err != nil {
			return
		}
		r, expectReply, err := g.request(ctx, frame, backend)
		if err != nil {
			p.log.Info("localiam: kafka connection closed", "service", g.id.Service, "reason", err.Error())
			return
		}
		if !expectReply {
			continue
		}
		select {
		case queue <- r:
		case <-ctx.Done():
		}
	}
}

func (p *Kafka) closeConn(c net.Conn, which string) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		p.log.Debug("localiam: closing kafka connection", "side", which, "error", err)
	}
}

// deliver writes one owed reply to the client.
func (p *Kafka) deliver(client, backend net.Conn, r reply) error {
	if r.synthetic != nil {
		return writeFrame(client, r.synthetic)
	}
	resp, err := readFrame(backend)
	if err != nil {
		return err
	}
	if r.clamp {
		clampAPIVersions(resp, r.flexible, p.versionLimits(), p.log)
	}
	return writeFrame(client, resp)
}

// gate makes the per-request decision for one authenticated connection.
type gate struct {
	p         *Kafka
	decisions map[string]bool // action+resource → allowed, for this connection
	id        Identity
}

// request decides one request. It forwards an allowed request to the backend
// and returns the reply the client is owed; expectReply is false only for
// Produce with acks=0, which gets no response.
func (g *gate) request(ctx context.Context, frame []byte, backend net.Conn) (reply, bool, error) {
	if len(frame) < 8 {
		return reply{}, false, errors.New("short request")
	}
	apiKey := int16(binary.BigEndian.Uint16(frame[0:2]))
	apiVersion := int16(binary.BigEndian.Uint16(frame[2:4]))

	var (
		d   decision
		err error
	)
	switch apiKey {
	case apiKeyAPIVersions:
		d = decision{forward: true, expect: true, owed: reply{clamp: true, flexible: apiVersion >= 3}}
	case apiKeyProduce:
		d, err = g.decideProduce(ctx, frame, apiVersion)
	case apiKeyFetch:
		d, err = g.decideFetch(ctx, frame, apiVersion)
	case apiKeyFindCoordinator:
		d, err = g.decideFindCoordinator(ctx, frame, apiVersion)
	default:
		d = decision{forward: true, expect: true}
	}
	if err != nil {
		return reply{}, false, err
	}
	if d.forward {
		if err := writeFrame(backend, frame); err != nil {
			return reply{}, false, err
		}
	}
	return d.owed, d.expect, nil
}

// decision is what one request gets: forwarded to the broker or not, and the
// reply the client is owed, if any.
type decision struct {
	owed    reply
	forward bool
	expect  bool
}

func denied(synthetic []byte) decision {
	return decision{expect: true, owed: reply{synthetic: synthetic}}
}

func (g *gate) decideProduce(ctx context.Context, frame []byte, version int16) (decision, error) {
	hdr, err := parseRequestHeader(frame)
	if err != nil {
		return decision{}, err
	}
	req, err := parseProduce(hdr.body, version)
	if err != nil {
		return decision{}, err
	}
	if g.allTopics(ctx, actionWriteData, req.topics) {
		return decision{forward: true, expect: req.acks != 0}, nil
	}
	if req.acks == 0 {
		// No response exists to carry the error, so close, as a broker does.
		return decision{}, errors.New("denied produce with acks=0")
	}
	return denied(produceDenied(hdr.correlation, version, req.topics)), nil
}

func (g *gate) decideFetch(ctx context.Context, frame []byte, version int16) (decision, error) {
	hdr, err := parseRequestHeader(frame)
	if err != nil {
		return decision{}, err
	}
	topics, err := parseFetch(hdr.body, version)
	if err != nil {
		return decision{}, err
	}
	if g.allTopics(ctx, actionReadData, topics) {
		return decision{forward: true, expect: true}, nil
	}
	return denied(fetchDenied(hdr.correlation, version, topics)), nil
}

func (g *gate) decideFindCoordinator(ctx context.Context, frame []byte, version int16) (decision, error) {
	hdr, err := parseRequestHeader(frame)
	if err != nil {
		return decision{}, err
	}
	key, keyType, err := parseFindCoordinator(hdr.body, version)
	if err != nil {
		return decision{}, err
	}
	action, code := actionGroup, int16(errGroupAuthorizationFailed)
	if keyType == 1 {
		action, code = actionTransactionalID, errTransactionalIDAuthorizationFail
	}
	if g.allowed(ctx, action, key) {
		return decision{forward: true, expect: true}, nil
	}
	return denied(findCoordinatorDenied(hdr.correlation, version, code)), nil
}

// allTopics reports whether every topic in a request is allowed. One denied
// topic refuses the whole request: splitting it between broker and proxy would
// mean re-encoding both the request and the response.
func (g *gate) allTopics(ctx context.Context, action string, topics []topicPartitions) bool {
	for _, t := range topics {
		if !g.allowed(ctx, action, t.name) {
			return false
		}
	}
	return true
}

// allowed asks the authorizer once per action and resource per connection. An
// authorizer error denies (fail closed) and is not cached, so a transient
// outage does not stick.
func (g *gate) allowed(ctx context.Context, action, resource string) bool {
	k := action + "\x00" + resource
	if v, ok := g.decisions[k]; ok {
		return v
	}
	ok, err := g.p.opts.Authorize.AuthorizeKafka(ctx, g.id.Service, action, resource)
	if err != nil {
		g.p.log.Info("localiam: kafka authorize failed; denying",
			"service", g.id.Service, "action", action, "resource", resource, "error", err)
		return false
	}
	g.decisions[k] = ok
	if !ok {
		g.p.log.Info("localiam: kafka operation denied",
			"service", g.id.Service, "action", action, "resource", resource)
	}
	return ok
}

// ── request decoding (classic, non-flexible versions only) ─────────────────

type topicPartitions struct {
	name       string
	partitions []int32
}

type produceRequest struct {
	topics []topicPartitions
	acks   int16
}

// decoder reads classic Kafka primitives off a body, remembering the first
// error so call sites stay linear.
type decoder struct {
	err error
	b   []byte
}

func (d *decoder) need(n int) bool {
	if d.err != nil {
		return false
	}
	if n < 0 || len(d.b) < n {
		d.err = errors.New("truncated request")
		return false
	}
	return true
}

func (d *decoder) int8() int8 {
	if !d.need(1) {
		return 0
	}
	v := int8(d.b[0])
	d.b = d.b[1:]
	return v
}

func (d *decoder) int16() int16 {
	if !d.need(2) {
		return 0
	}
	v := int16(binary.BigEndian.Uint16(d.b))
	d.b = d.b[2:]
	return v
}

func (d *decoder) int32() int32 {
	if !d.need(4) {
		return 0
	}
	v := int32(binary.BigEndian.Uint32(d.b))
	d.b = d.b[4:]
	return v
}

func (d *decoder) skip(n int) {
	if d.need(n) {
		d.b = d.b[n:]
	}
}

// string reads a (nullable) int16-length string; null reads as "".
func (d *decoder) string() string {
	n := int(d.int16())
	if n < 0 || !d.need(n) {
		return ""
	}
	s := string(d.b[:n])
	d.b = d.b[n:]
	return s
}

// count reads an int32 array length, bounding it by what could possibly fit
// so a hostile length cannot force a huge allocation.
func (d *decoder) count(minElem int) int {
	n := int(d.int32())
	if n < 0 {
		return 0 // null array
	}
	if d.err == nil && n*minElem > len(d.b) {
		d.err = errors.New("array length exceeds request")
		return 0
	}
	return n
}

// parseProduce reads Produce v3–v8: transactional_id, acks, timeout_ms, then
// topics, each with partitions carrying an index and a record batch.
func parseProduce(body []byte, version int16) (produceRequest, error) {
	if version < produceMinVersion || version > produceMaxVersion {
		return produceRequest{}, fmt.Errorf("produce v%d outside v%d–v%d", version, produceMinVersion, produceMaxVersion)
	}
	d := decoder{b: body}
	_ = d.string() // transactional_id
	req := produceRequest{acks: d.int16()}
	d.skip(4) // timeout_ms
	for range d.count(2 + 4) {
		t := topicPartitions{name: d.string()}
		for range d.count(4 + 4) {
			t.partitions = append(t.partitions, d.int32())
			if n := int(d.int32()); n > 0 { // records: nullable bytes
				d.skip(n)
			}
		}
		req.topics = append(req.topics, t)
	}
	return req, d.err
}

// parseFetch reads the topics of Fetch v4–v11. A request in an incremental
// fetch session may name no topics; it only re-fetches ones already allowed.
func parseFetch(body []byte, version int16) ([]topicPartitions, error) {
	if version < fetchMinVersion || version > fetchMaxVersion {
		return nil, fmt.Errorf("fetch v%d outside v%d–v%d", version, fetchMinVersion, fetchMaxVersion)
	}
	d := decoder{b: body}
	d.skip(4 + 4 + 4 + 4) // replica_id, max_wait_ms, min_bytes, max_bytes
	_ = d.int8()          // isolation_level
	if version >= 7 {
		d.skip(4 + 4) // session_id, session_epoch
	}
	partSize := 4 + 8 + 4 // partition, fetch_offset, partition_max_bytes
	if version >= 9 {
		partSize += 4 // current_leader_epoch
	}
	if version >= 5 {
		partSize += 8 // log_start_offset
	}
	var topics []topicPartitions
	for range d.count(2 + 4) {
		t := topicPartitions{name: d.string()}
		for range d.count(partSize) {
			t.partitions = append(t.partitions, d.int32())
			d.skip(partSize - 4)
		}
		topics = append(topics, t)
	}
	return topics, d.err
}

// parseFindCoordinator reads FindCoordinator v0–v2: key, and from v1 the key
// type (0 group, 1 transactional id). v0 can only name a group.
func parseFindCoordinator(body []byte, version int16) (key string, keyType int8, err error) {
	if version > findCoordinatorMaxVersion {
		return "", 0, fmt.Errorf("find coordinator v%d above v%d", version, findCoordinatorMaxVersion)
	}
	d := decoder{b: body}
	key = d.string()
	if version >= 1 {
		keyType = d.int8()
	}
	return key, keyType, d.err
}

// ── denial encoding (response header v0: correlation id only) ──────────────

// produceDenied answers a Produce with TOPIC_AUTHORIZATION_FAILED on every
// partition it named.
func produceDenied(correlation int32, version int16, topics []topicPartitions) []byte {
	b := appendInt32(nil, correlation)
	b = appendInt32(b, int32(len(topics)))
	for _, t := range topics {
		b = appendString(b, t.name)
		b = appendInt32(b, int32(len(t.partitions)))
		for _, part := range t.partitions {
			b = appendInt32(b, part)
			b = appendInt16(b, errTopicAuthorizationFailed)
			b = appendInt64(b, -1) // base_offset
			b = appendInt64(b, -1) // log_append_time_ms (v2+)
			if version >= 5 {
				b = appendInt64(b, -1) // log_start_offset
			}
			if version >= 8 {
				b = appendInt32(b, 0)  // record_errors: empty
				b = appendInt16(b, -1) // error_message: null
			}
		}
	}
	return appendInt32(b, 0) // throttle_time_ms (v1+)
}

// fetchDenied answers a Fetch with TOPIC_AUTHORIZATION_FAILED on every
// partition it named, outside any fetch session.
func fetchDenied(correlation int32, version int16, topics []topicPartitions) []byte {
	b := appendInt32(nil, correlation)
	b = appendInt32(b, 0) // throttle_time_ms (v1+)
	if version >= 7 {
		b = appendInt16(b, 0) // error_code
		b = appendInt32(b, 0) // session_id: none
	}
	b = appendInt32(b, int32(len(topics)))
	for _, t := range topics {
		b = appendString(b, t.name)
		b = appendInt32(b, int32(len(t.partitions)))
		for _, part := range t.partitions {
			b = appendInt32(b, part)
			b = appendInt16(b, errTopicAuthorizationFailed)
			b = appendInt64(b, -1) // high_watermark
			b = appendInt64(b, -1) // last_stable_offset (v4+)
			if version >= 5 {
				b = appendInt64(b, -1) // log_start_offset
			}
			b = appendInt32(b, -1) // aborted_transactions: null (v4+)
			if version >= 11 {
				b = appendInt32(b, -1) // preferred_read_replica
			}
			b = appendInt32(b, 0) // records: empty
		}
	}
	return b
}

// findCoordinatorDenied answers a FindCoordinator with the given
// authorization error and no coordinator.
func findCoordinatorDenied(correlation int32, version, code int16) []byte {
	b := appendInt32(nil, correlation)
	if version >= 1 {
		b = appendInt32(b, 0) // throttle_time_ms
	}
	b = appendInt16(b, code)
	if version >= 1 {
		b = appendInt16(b, -1) // error_message: null
	}
	b = appendInt32(b, -1) // node_id
	b = appendString(b, "")
	return appendInt32(b, -1) // port
}
