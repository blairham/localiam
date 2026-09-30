// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

// Package policy reads a service's AWS permissions from a per-service spec —
// one YAML file per service with a `podIdentity.permissions` block — so a cluster
// enforces exactly what the deployed service is allowed to do.
//
// # Why a spec rather than a policy document
//
// The spec should be the same file the deployment grants permissions from. A
// test-only permission file drifts from the deployed one the day it is written;
// reading the deployed spec means a cluster catches the class of bug that spec is
// prone to: a missing grant fails on a laptop instead of at pod start after
// deploy.
//
// # Scope
//
// This is deliberately NOT a general IAM engine — no conditions, no policy
// documents, no deny precedence. It answers only the questions the three
// data planes actually ask, because those are the only ones an adapter can act
// on. See docs/architecture/iam-auth.md § Policy.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Spec is the part of a service spec localiam cares about.
type Spec struct {
	PodIdentity *PodIdentity `yaml:"podIdentity"`
	Name        string       `yaml:"-"`
}

// PodIdentity mirrors the spec's `podIdentity:` block.
type PodIdentity struct {
	// Permissions absent means the service runs on a SHARED data-services
	// role, which grants everything. That is the deployed behavior, so localiam
	// reproduces it rather than defaulting closed — a cluster that denied here
	// would fail services that work in prod.
	Permissions *Permissions `yaml:"permissions"`
}

// Permissions mirrors `podIdentity.permissions`.
//
// ⚠ Declaring ANY permissions block is a wholesale role swap, not an additive
// grant: the pod moves off the shared role and only what is listed survives.
// That is the wholesale-role-swap footgun — add a `msk:` block and the unlisted
// `rds-db:connect` is silently lost, so every new pod fails PAM auth hours
// later on restart. Modeling it faithfully means a cluster fails that immediately
// instead.
type Permissions struct {
	MSK         *MSK `yaml:"msk"`
	RDS         *RDS `yaml:"rds"`
	ElastiCache bool `yaml:"elastiCache"`
}

// MSK mirrors `podIdentity.permissions.msk`.
//
// Topics is a read+write shorthand alongside the directional
// readTopics/writeTopics fields. Specs use both forms, so both have to work.
type MSK struct {
	Topics           []string `yaml:"topics"`
	ReadTopics       []string `yaml:"readTopics"`
	WriteTopics      []string `yaml:"writeTopics"`
	ConfigReadTopics []string `yaml:"configReadTopics"`
	AdminTopics      []string `yaml:"adminTopics"`
	Groups           []string `yaml:"groups"`
	TransactionalIDs []string `yaml:"transactionalIds"`
	Cluster          bool     `yaml:"cluster"`
}

// RDS mirrors `podIdentity.permissions.rds`.
type RDS struct {
	DBUser   string `yaml:"dbUser"`
	Database string `yaml:"database"`
}

// Load reads one service spec. The service name comes from the file name, which
// is how the deploy pipeline identifies it.
func Load(path string) (*Spec, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return nil, fmt.Errorf("policy: reading %s: %w", path, err)
	}
	var s Spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("policy: parsing %s: %w", path, err)
	}
	s.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return &s, nil
}

// LoadDir reads every *.yaml in a service spec directory.
func LoadDir(dir string) (map[string]*Spec, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("policy: globbing %s: %w", dir, err)
	}
	out := make(map[string]*Spec, len(entries))
	for _, e := range entries {
		s, err := Load(e)
		if err != nil {
			return nil, err
		}
		out[s.Name] = s
	}
	return out, nil
}

// ── Decisions ───────────────────────────────────────────────────────────────
//
// Every decision returns true when the spec declares no permissions, because
// that is the shared-role case and the shared role grants everything.

// unrestricted reports the shared-role case.
func (s *Spec) unrestricted() bool {
	return s.PodIdentity == nil || s.PodIdentity.Permissions == nil
}

func (s *Spec) perms() *Permissions {
	if s.PodIdentity == nil {
		return nil
	}
	return s.PodIdentity.Permissions
}

// MayConnectRedis reports whether the service may authenticate to ElastiCache.
func (s *Spec) MayConnectRedis() bool {
	if s.unrestricted() {
		return true
	}
	return s.perms().ElastiCache
}

// MayConnectPostgresAs reports whether the service may connect as dbUser. A
// spec's `*` means any user, which the schema explicitly allows.
func (s *Spec) MayConnectPostgresAs(dbUser string) bool {
	if s.unrestricted() {
		return true
	}
	r := s.perms().RDS
	if r == nil || r.DBUser == "" {
		return false
	}
	return r.DBUser == "*" || r.DBUser == dbUser
}

// MayConnectKafka reports whether the service may open an MSK connection.
func (s *Spec) MayConnectKafka() bool {
	if s.unrestricted() {
		return true
	}
	m := s.perms().MSK
	return m != nil && m.Cluster
}

// MayReadTopic reports DescribeTopic + ReadData on a topic.
func (s *Spec) MayReadTopic(topic string) bool {
	return s.topicAllowed(topic, func(m *MSK) [][]string {
		return [][]string{m.Topics, m.ReadTopics}
	})
}

// MayWriteTopic reports DescribeTopic + WriteData on a topic.
func (s *Spec) MayWriteTopic(topic string) bool {
	return s.topicAllowed(topic, func(m *MSK) [][]string {
		return [][]string{m.Topics, m.WriteTopics, m.AdminTopics}
	})
}

// MayUseGroup reports DescribeGroup / AlterGroup on a consumer group.
func (s *Spec) MayUseGroup(group string) bool {
	return s.topicAllowed(group, func(m *MSK) [][]string { return [][]string{m.Groups} })
}

// MayUseTransactionalID reports Describe/AlterTransactionalId. A transactional
// producer needs this explicitly — the cluster-level idempotent-write grant
// alone does not cover InitTransactions.
func (s *Spec) MayUseTransactionalID(id string) bool {
	return s.topicAllowed(id, func(m *MSK) [][]string { return [][]string{m.TransactionalIDs} })
}

func (s *Spec) topicAllowed(name string, pick func(*MSK) [][]string) bool {
	if s.unrestricted() {
		return true
	}
	m := s.perms().MSK
	if m == nil {
		return false
	}
	for _, list := range pick(m) {
		if matchAny(list, name) {
			return true
		}
	}
	return false
}

// matchAny reports whether name matches any pattern.
//
// Only a TRAILING "*" is a wildcard, which is the only form the specs use
// (`api-*`, `my-reference-*`). Deliberately not path.Match or a regexp: those
// would give `.` and `?` meanings the spec authors never intended, and a
// pattern that silently matches more than its author meant is the one mistake
// an authorization check must not make.
func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		switch {
		case p == "*":
			return true
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(name, strings.TrimSuffix(p, "*")) {
				return true
			}
		case p == name:
			return true
		}
	}
	return false
}
