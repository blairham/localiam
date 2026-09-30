// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Principal is one credential localiam has issued, and the identity it stands
// for. SecretKey is what the verifier re-derives the signing key from, which is
// only possible because localiam mints its own credentials — there is no AWS in
// the loop, and there is no network call anywhere in verification.
type Principal struct {
	Expiration   time.Time `json:"expiration,omitempty"`
	AccessKeyID  string    `json:"accessKeyId"`
	SecretKey    string    `json:"secretKey"`
	SessionToken string    `json:"sessionToken,omitempty"`
	Service      string    `json:"service,omitempty"`
	ARN          string    `json:"arn"`
}

// Expired reports whether the credential has lapsed as of now.
func (p Principal) Expired(now time.Time) bool {
	return !p.Expiration.IsZero() && now.After(p.Expiration)
}

// Store maps access key IDs to principals. It is safe for concurrent use: the
// STS shim issues into it while adapters verify against it.
type Store struct {
	by map[string]Principal
	mu sync.RWMutex
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{by: make(map[string]Principal)} }

// Add registers or replaces a principal.
func (s *Store) Add(p Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.by[p.AccessKeyID] = p
}

// Lookup resolves an access key ID. Expiry is NOT checked here — Verify does
// that, so it can tell an expired credential apart from one that never existed.
func (s *Store) Lookup(accessKeyID string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.by[accessKeyID]
	return p, ok
}

// Sweep drops every credential that lapsed before now and reports how many went.
// The issuer mints a fresh credential on each SDK refresh, so without this the
// store grows for the life of the server.
func (s *Store) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, p := range s.by {
		if p.Expired(now) {
			delete(s.by, k)
			n++
		}
	}
	return n
}

// All returns a snapshot of every registered principal.
func (s *Store) All() []Principal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Principal, 0, len(s.by))
	for _, p := range s.by {
		out = append(out, p)
	}
	return out
}

// Len reports how many principals are registered.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.by)
}

// LoadStore reads a JSON array of principals from a file — static
// bootstrap set, before any STS shim has issued anything.
func LoadStore(path string) (*Store, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return nil, fmt.Errorf("reading principals: %w", err)
	}
	var ps []Principal
	if err := json.Unmarshal(raw, &ps); err != nil {
		return nil, fmt.Errorf("parsing principals %s: %w", path, err)
	}
	s := NewStore()
	for _, p := range ps {
		if p.AccessKeyID == "" || p.SecretKey == "" {
			return nil, fmt.Errorf("principal %q: accessKeyId and secretKey are required", p.ARN)
		}
		s.Add(p)
	}
	return s, nil
}
