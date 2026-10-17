// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"sync"

	"github.com/blairham/sh/interp"
)

// Record is one line of the audit trail, flattened for JSON.
//
// It is a projection of interp.Event rather than the event itself: the event
// carries a syntax-level Action with fields that mean nothing to an operator,
// and an audit record that changes shape when the interpreter adds a field is
// not one you can build an alert on.
type Record struct {
	// ID is interp.Action.ID. The gate is consulted about an action and every
	// event that action produces carries the same string, so a Deny and the
	// command it refused are provably the same action rather than two lines
	// that look alike. Pairing by position does not work here: a pipeline
	// emits from two goroutines.
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Action string   `json:"action"`
	Path   string   `json:"path,omitempty"`
	Err    string   `json:"err,omitempty"`
	Args   []string `json:"args,omitempty"`
	Status int      `json:"status,omitempty"`
	Line   int      `json:"line,omitempty"`
}

// Recorder is the event sink: a bounded slice of Records.
//
// Bounded because the endpoint hands the trail back in the response, and an
// unbounded audit buffer is a memory amplifier reachable by anyone who can
// reach the endpoint, `for i in 1 2 3 ...; do echo /proc/*; done` emits an
// event per access. Over the cap, records are dropped and the count is
// reported, which is the honest failure: a truncated trail that says it was
// truncated beats a complete one that costs the process its heap.
type Recorder struct {
	records []Record
	cap     int
	dropped int
	// denied is counted here, off the typed EventKind, rather than by any
	// later pass over Record.Kind. The first version of this package counted
	// denials by matching the string "EventDenied" against a field whose
	// value is "denied", so it logged `denied=0` for a run the gate had
	// refused three times. A count that reads zero and means nothing is
	// worse than no count, and the fix is to never re-derive it from the
	// rendering: the enum decides, once, here.
	denied int
	mu     sync.Mutex
}

func newRecorder(capacity int) *Recorder {
	return &Recorder{cap: capacity, records: make([]Record, 0, min(capacity, 64))}
}

// Emit implements interp.Sink. Called from more than one goroutine.
func (rec *Recorder) Emit(_ context.Context, e interp.Event) {
	r := Record{
		ID:     e.Action.ID,
		Kind:   e.Kind.String(),
		Action: e.Action.Kind.String(),
		Path:   e.Action.Path,
		Args:   e.Action.Args,
		Status: e.Status,
		Line:   e.Line,
	}
	if e.Err != nil {
		r.Err = e.Err.Error()
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if e.Kind == interp.EventDenied {
		// Counted before the cap, so a script that floods the trail cannot
		// hide a denial by pushing it past the limit.
		rec.denied++
	}
	if len(rec.records) >= rec.cap {
		rec.dropped++
		return
	}
	rec.records = append(rec.records, r)
}

// Trail returns a copy of what was recorded, how many records were dropped,
// and how many actions the gate refused.
func (rec *Recorder) Trail() (records []Record, dropped, denied int) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]Record, len(rec.records))
	copy(out, rec.records)
	return out, rec.dropped, rec.denied
}
