// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// errProtocol is returned for input that is not a RESP command we can read.
var errProtocol = errors.New("proxy: malformed RESP command")

// maxBulkLen caps a single argument. A credential token is ~700 bytes; this
// leaves room while refusing to allocate on a hostile length prefix.
const maxBulkLen = 64 * 1024

// maxArgs caps arguments in one command.
const maxArgs = 64

// command is one client command: the verb plus its arguments, decoded.
//
// Only what the handshake needs is decoded — AUTH and HELLO. Everything after
// authentication is spliced through as opaque bytes, so this is not a Redis
// protocol implementation and must not grow into one.
type command struct {
	raw  []byte
	args []string
}

// name returns the uppercased verb.
func (c command) name() string {
	if len(c.args) == 0 {
		return ""
	}
	return strings.ToUpper(c.args[0])
}

// readCommand reads one RESP array-of-bulk-strings command, keeping the raw
// bytes so an unmodified command can be replayed to the backend verbatim.
//
// Inline commands (a bare "PING\r\n", what `redis-cli` sends interactively) are
// accepted too: rejecting them would make the proxy confusing to poke at by
// hand, which is half of why an operator ever touches it.
func readCommand(r *bufio.Reader) (command, error) {
	prefix, err := r.Peek(1)
	if err != nil {
		return command{}, err
	}
	if prefix[0] != '*' {
		line, lineErr := r.ReadBytes('\n')
		if lineErr != nil {
			return command{}, lineErr
		}
		return command{raw: line, args: strings.Fields(strings.TrimSpace(string(line)))}, nil
	}

	var raw []byte
	header, err := r.ReadBytes('\n')
	if err != nil {
		return command{}, err
	}
	raw = append(raw, header...)

	n, err := strconv.Atoi(strings.TrimSpace(string(header[1:])))
	if err != nil || n < 0 || n > maxArgs {
		return command{}, fmt.Errorf("%w: array length %q", errProtocol, strings.TrimSpace(string(header)))
	}

	args := make([]string, 0, n)
	for range n {
		arg, argRaw, argErr := readBulk(r)
		if argErr != nil {
			return command{}, argErr
		}
		raw = append(raw, argRaw...)
		args = append(args, arg)
	}
	return command{raw: raw, args: args}, nil
}

// readBulk reads one $-prefixed bulk string, returning its value and the raw
// bytes it occupied so the command can be replayed verbatim.
func readBulk(r *bufio.Reader) (value string, raw []byte, err error) {
	lenLine, err := r.ReadBytes('\n')
	if err != nil {
		return "", nil, err
	}
	if len(lenLine) == 0 || lenLine[0] != '$' {
		return "", nil, fmt.Errorf("%w: expected a bulk string", errProtocol)
	}
	size, err := strconv.Atoi(strings.TrimSpace(string(lenLine[1:])))
	if err != nil || size < 0 || size > maxBulkLen {
		return "", nil, fmt.Errorf("%w: bulk length %q", errProtocol, strings.TrimSpace(string(lenLine)))
	}

	// +2 for the trailing CRLF.
	buf := make([]byte, size+2)
	if _, err := readFull(r, buf); err != nil {
		return "", nil, err
	}
	return string(buf[:size]), append(lenLine, buf...), nil
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// encodeCommand renders args as a RESP array — used to forward a HELLO with its
// credentials stripped.
func encodeCommand(args ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(b.String())
}
