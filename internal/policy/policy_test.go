// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"path/filepath"
	"testing"

	"github.com/blairham/localiam/internal/policy"
)

func load(t *testing.T, name string) *policy.Spec {
	t.Helper()
	s, err := policy.Load(filepath.Join("testdata", name+".yaml"))
	if err != nil {
		t.Fatalf("loading %s: %v", name, err)
	}
	return s
}

// TestTheSharedRoleGrantsEverything pins the production default: a spec with no
// permissions block runs on the shared data-services role, which grants
// everything. A cluster that defaulted CLOSED here would deny services that work
// perfectly well in production — the opposite of fidelity.
func TestTheSharedRoleGrantsEverything(t *testing.T) {
	t.Parallel()
	s := load(t, "shared-role")

	if !s.MayConnectRedis() || !s.MayConnectKafka() || !s.MayConnectPostgresAs("anyone") {
		t.Error("the shared role should grant every connect")
	}
	if !s.MayReadTopic("anything") || !s.MayWriteTopic("anything") || !s.MayUseGroup("anything") {
		t.Error("the shared role should grant every topic and group")
	}
}

// TestDeclaringOnePermissionRevokesTheRest is the wholesale-role-swap
// footgun, executable.
//
// `permissions:` is a wholesale role swap, not an additive grant: the pod moves
// off the shared role and only what is listed survives. Add an `msk:`
// block and the unlisted `rds-db:connect` is silently lost, so every new pod
// fails PAM auth on restart — hours later, because running pods keep using
// cached shared-role credentials. A cluster enforcing this fails it
// immediately instead.
func TestDeclaringOnePermissionRevokesTheRest(t *testing.T) {
	t.Parallel()
	s := load(t, "msk-only")

	if !s.MayConnectKafka() {
		t.Error("the declared msk grant should still work")
	}
	if s.MayConnectPostgresAs("processor_app") {
		t.Error("an undeclared rds grant must NOT survive the role swap")
	}
	if s.MayConnectRedis() {
		t.Error("an undeclared elastiCache grant must NOT survive the role swap")
	}
}

func TestTopicsShorthandGrantsBothDirections(t *testing.T) {
	t.Parallel()
	s := load(t, "api")

	if !s.MayReadTopic("requests") || !s.MayWriteTopic("requests") {
		t.Error("the topics: shorthand should grant read and write")
	}
	if s.MayReadTopic("not-granted") || s.MayWriteTopic("not-granted") {
		t.Error("an unlisted topic must be denied")
	}
	if !s.MayConnectRedis() {
		t.Error("elastiCache: true should grant Redis connect")
	}
}

func TestDirectionalGrantsAreDirectional(t *testing.T) {
	t.Parallel()
	s := load(t, "worker")

	if !s.MayReadTopic("events") {
		t.Error("readTopics should grant read")
	}
	if s.MayWriteTopic("events") {
		t.Error("readTopics must NOT grant write")
	}
	if !s.MayWriteTopic("events-processed") {
		t.Error("writeTopics should grant write")
	}
	if s.MayReadTopic("events-processed") {
		t.Error("writeTopics must NOT grant read")
	}
}

func TestPostgresIdentityIsTheDbUser(t *testing.T) {
	t.Parallel()
	s := load(t, "worker")

	if !s.MayConnectPostgresAs("worker_app") {
		t.Error("the declared dbUser should be allowed")
	}
	if s.MayConnectPostgresAs("app_admin") {
		t.Error("a different dbUser must be denied")
	}
}

// TestATransactionalIdNeedsItsOwnGrant pins the footgun the schema calls out:
// the cluster-level idempotent-write grant does not cover InitTransactions, so
// a transactional producer fails at startup without an explicit grant.
func TestATransactionalIdNeedsItsOwnGrant(t *testing.T) {
	t.Parallel()

	if s := load(t, "worker"); !s.MayUseTransactionalID("worker-txn-1") {
		t.Error("a granted transactional id should be allowed")
	}
	// api has cluster: true and topic grants but no transactionalIds.
	if s := load(t, "api"); s.MayUseTransactionalID("api-txn-1") {
		t.Error("cluster: true must NOT imply a transactional id grant")
	}
}

// TestWildcardsMatchOnlyAsAPrefix pins the matcher's deliberate narrowness. A
// pattern that silently matches more than its author meant is the one mistake
// an authorization check must not make, so `*` is honored only at the end and
// regex/glob metacharacters stay literal.
func TestWildcardsMatchOnlyAsAPrefix(t *testing.T) {
	t.Parallel()
	s := load(t, "api") // groups: api-*, shared-*

	tests := []struct {
		group string
		want  bool
	}{
		{group: "api-consumers-1-abc", want: true},
		{group: "shared-settings", want: true},
		{group: "api-", want: true},
		{group: "api", want: false},        // the prefix is "api-", not "api"
		{group: "xapi-thing", want: false}, // contains "api-", but a prefix is not a substring
		{group: "API-upper", want: false},  // case-sensitive, like IAM
		{group: "", want: false},
	}
	for _, tc := range tests {
		if got := s.MayUseGroup(tc.group); got != tc.want {
			t.Errorf("MayUseGroup(%q) = %v, want %v", tc.group, got, tc.want)
		}
	}
}

func TestLoadDirReadsEverySpec(t *testing.T) {
	t.Parallel()
	specs, err := policy.LoadDir("testdata")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	for _, want := range []string{"api", "worker", "shared-role", "msk-only"} {
		if _, ok := specs[want]; !ok {
			t.Errorf("spec %q missing from %v", want, specs)
		}
	}
}
