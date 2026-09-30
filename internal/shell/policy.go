// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"path"
	"strings"
	"sync/atomic"

	"github.com/blairham/sh/interp"
)

// Policy is the gate. It is deny-by-default and it is the whole security
// argument for this package, so it is the first file to read.
//
// The premise the design rests on: a distroless image has no binaries, so a
// shell embedded in it is not a way to RUN things, it is a way to READ things.
// Most of what an operator execs into a pod to ask (what is pid 1 doing, what
// is it connected to, what are its limits, how close is it to its memory
// ceiling) is a file under /proc or /sys/fs/cgroup. Globbing and `read`
// cover all of it with no external command at all.
//
// So ActionExec is refused unconditionally, including for a path that exists.
// That is not a hardening measure bolted on afterwards; it is the shape of the
// feature. There is nothing to exec, and a gate that says so can never be
// talked into finding something later, an operator who adds a binary to the
// image does not thereby widen this endpoint.
type Policy struct {
	// ReadRoots are the path prefixes an open or a stat may reach. A path is
	// cleaned before it is compared, so `/proc/1/../../etc/shadow` is tested
	// as `/etc/shadow` and refused.
	ReadRoots []string

	// DenyNames are base names refused anywhere under a root, whatever the
	// roots say. One entry, and it is the interesting one: /proc/<pid>/environ
	// is the process environment, which is where a service's credentials arrive:
	// a database password, an API key, this package's own bearer token.
	//
	// Without this deny the environment is readable with one line:
	// `read -r v < /proc/1/environ; echo "$v"` returns every variable. The
	// first probe of it came back EMPTY only because it used a `while read`
	// loop, and environ has no trailing newline, so the loop's only `read`
	// hits EOF, returns 1, and the body never runs. That is ordinary POSIX
	// behavior (real dash does the same) and it protected nothing: the bare
	// `read` above leaks the secret in both dash and this interpreter.
	//
	// Nil means DefaultDenyNames.
	DenyNames []string

	denied atomic.Int64
}

// DefaultDenyNames is what a Policy refuses when DenyNames is nil.
var DefaultDenyNames = []string{"environ"}

// DefaultPolicy is what the endpoint runs with unless a caller overrides it.
//
// /proc is the whole point. /sys/fs/cgroup answers the memory-limit question
// that /proc gets wrong in a container, which is the single most common thing
// a person execs in to check. Nothing else is listed, deliberately: a
// service's config and credentials arrive as env and as files outside these
// roots, and an endpoint that can read /proc must not be able to read those.
func DefaultPolicy() *Policy {
	return &Policy{
		ReadRoots: []string{"/proc", "/sys/fs/cgroup"},
		DenyNames: DefaultDenyNames,
	}
}

// Allow implements interp.Gate.
//
// Called from more than one goroutine, the package doc on interp.Gate says a
// background job and each half of a pipeline gate from their own goroutine ,
// so the only mutable state here is atomic.
func (p *Policy) Allow(_ context.Context, a interp.Action) interp.Decision {
	switch a.Kind {
	case interp.ActionExec:
		// No exec, ever. See the type comment.
		p.denied.Add(1)
		return interp.Deny

	case interp.ActionSignal:
		// The shell can address any process in the pod's PID namespace, and
		// pid 1 is the service itself. A diagnostic endpoint that can SIGKILL the
		// service it is diagnosing is a liveness probe with extra steps.
		p.denied.Add(1)
		return interp.Deny

	case interp.ActionOpen:
		if a.Write {
			// Read-only is not a convenience. The gate sees an open for
			// writing from a redirection, and `> /proc/sys/...` is a real
			// write on a real kernel knob.
			p.denied.Add(1)
			return interp.Deny
		}
		return p.decideRead(a)

	case interp.ActionStat:
		// Wider than a read: see traversable.
		if p.traversable(a.Path) {
			return interp.Allow
		}
		return p.decideRead(a)

	case interp.ActionReadDir:
		return p.decideRead(a)

	case interp.ActionInherit:
		// Recorded rather than gated by the interpreter, a capability the
		// shell was handed before it read a line. Allowing it is the only
		// coherent answer; refusing a thing that already happened would put a
		// Deny in the audit trail for an access this package performed itself.
		return interp.Allow

	default:
		// A new ActionKind in a later release of the interpreter reaches here.
		// It is refused, so the failure mode of an upgrade is a diagnostic
		// that stops working rather than a boundary that quietly widened.
		p.denied.Add(1)
		return interp.Deny
	}
}

// decideRead tests a path against the roots. Resolved is preferred over Path
// when the interpreter reports one: it is the kernel's own name for what the
// open reached, which is what a symlink out of /proc would show up as.
func (p *Policy) decideRead(a interp.Action) interp.Decision {
	target := a.Path
	if a.Resolved != "" {
		target = a.Resolved
	}
	if p.reachable(target) {
		return interp.Allow
	}
	p.denied.Add(1)
	return interp.Deny
}

func (p *Policy) reachable(target string) bool {
	clean, ok := absClean(target)
	if !ok {
		return false
	}
	deny := p.DenyNames
	if deny == nil {
		deny = DefaultDenyNames
	}
	for _, name := range deny {
		if path.Base(clean) == name {
			return false
		}
	}
	for _, root := range p.ReadRoots {
		root = path.Clean(root)
		if clean == root || root == "/" || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}

// traversable reports whether target is an ANCESTOR of a root.
//
// This exists because globbing walks down from the first path component:
// expanding `/proc/1/*` stats `/proc` and `/proc/1` on the way, and with a
// root of `/proc/1` the stat of `/proc` would be refused and the glob would
// silently collapse to the literal pattern. That is the worst failure shape
// available, not an error, just a diagnostic that quietly stops working ,
// and it is how this rule was found rather than reasoned about: the first
// test of globbing returned the unexpanded pattern.
//
// It applies to STAT ONLY. Confirming that a directory on the way to a root
// exists leaks nothing the operator does not already know, since they were
// told the root. Listing it or opening a file in it would, so ActionReadDir
// and ActionOpen do not consult this.
func (p *Policy) traversable(target string) bool {
	clean, ok := absClean(target)
	if !ok {
		return false
	}
	for _, root := range p.ReadRoots {
		root = path.Clean(root)
		if clean == "/" || root == clean || strings.HasPrefix(root, clean+"/") {
			return true
		}
	}
	return false
}

// absClean normalizes a path the gate was asked about, and reports whether it
// is usable. Cleaning is what makes `/proc/1/../../etc/shadow` get tested as
// `/etc/shadow`; a relative path means the interpreter is naming something
// this package did not set up, since the Runner is given an absolute Dir.
func absClean(target string) (string, bool) {
	if target == "" {
		return "", false
	}
	clean := path.Clean(target)
	if !path.IsAbs(clean) {
		return "", false
	}
	return clean, true
}

// Denied is how many actions this policy refused, for the metric.
func (p *Policy) Denied() int64 { return p.denied.Load() }
