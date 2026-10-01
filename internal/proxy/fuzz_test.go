// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadCommand: the Redis proxy reads a client's handshake before it has
// authenticated anyone, so these bytes come from anybody who can connect. No
// input may panic it, and a parsed command must respect the caps.
func FuzzReadCommand(f *testing.F) {
	for _, s := range []string{
		"*3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n$5\r\ntoken\r\n",
		"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$1\r\nu\r\n$1\r\nt\r\n",
		"AUTH user token\r\n", "*-1\r\n", "*99999\r\n", "*1\r\n$-1\r\n", "*1\r\n$99999999\r\n", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cmd, err := readCommand(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		if len(cmd.args) > maxArgs {
			t.Fatalf("%d args exceeds maxArgs %d", len(cmd.args), maxArgs)
		}
		for _, a := range cmd.args {
			if len(a) > maxBulkLen && data[0] == '*' {
				t.Fatalf("arg of %d bytes exceeds maxBulkLen %d", len(a), maxBulkLen)
			}
		}
	})
}

// FuzzKafkaPreAuthParsing: the Kafka proxy parses request headers and SASL
// payloads before authentication, from anybody who can connect. None of it may
// panic, whatever the bytes.
func FuzzKafkaPreAuthParsing(f *testing.F) {
	for _, s := range [][]byte{
		{0, 18, 0, 3, 0, 0, 0, 1, 0, 4, 't', 'e', 's', 't', 0},
		{0, 17, 0, 1, 0, 0, 0, 2, 0xff, 0xff},
		{0, 36, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'},
		[]byte(`{"version":"2020_10_22"}`), []byte("n,,\x01auth=Bearer x\x01\x01"),
		{},
		{0},
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseRequestHeader(data)
		_, _ = readString(data)
		_, _ = readBytesField(data)
		_, _ = classifySASLPayload(data)
		_, _ = readFrame(bytes.NewReader(data))
	})
}
