// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/blairham/localiam/internal/proxy"
)

// runGenCerts writes a CA and a server keypair.
//
// The Kafka proxy needs a certificate its clients TRUST: franz-go verifies
// against the system pool and exposes no insecure escape hatch, so a cluster mounts
// the CA and points SSL_CERT_FILE at it. Postgres does not need this — pgx
// uses sslmode=require, which encrypts without verifying — but one command
// covering both keeps the certificate story in a single place.
func runGenCerts(args []string) error {
	fs := flag.NewFlagSet("gen-certs", flag.ExitOnError)
	var (
		hosts  = fs.String("hosts", "localiam,localhost", "comma-separated DNS names for the server certificate")
		outDir = fs.String("out", ".", "directory to write ca.pem, server.pem and server-key.pem into")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	bundle, err := proxy.GenerateCA(strings.Split(*hosts, ","))
	if err != nil {
		return err
	}
	for name, pem := range map[string][]byte{
		"ca.pem":         bundle.CAPEM,
		"server.pem":     bundle.CertPEM,
		"server-key.pem": bundle.KeyPEM,
	} {
		path := filepath.Join(*outDir, name)
		if err := os.WriteFile(path, pem, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		slog.Info("localiam: wrote", "path", path)
	}
	return nil
}
