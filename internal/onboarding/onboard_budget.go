// Package onboarding is the "infer intent" half.
//
// It enumerates declarations, applies the grouping policy and the various fuses,
// and finally writes a desired-state document. wecert only reads that document and
// never infers anything.
//
// The boundary is deliberate: every known pitfall in this system (rate limits,
// accidental deletion, state drift) comes from "judgement", and judgement logic
// inevitably changes again and again -- new sources, tuned thresholds, fixed edge
// cases. Certificate lifecycle must stay stable, so inference has to live in its
// own component and be disposable and rewritable without affecting issuance.
//
// The five invariants that must never break, mapped to their code:
//
//	5.1 source failure ≠ name gone    → the sourceErr branch in run.gather
//	5.2 abrupt desired-state fuse     → run.fuse
//	5.3 deletion conservative by an order of magnitude
//	                                  → grace period and reference check in run.resolve
//	5.4 quota fuse                    → run.budget
//	5.5 explicit authorization        → Declaration itself + Options.Allowlist
package onboarding

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/susunola/wecert/internal/atomicfile"
	"github.com/susunola/wecert/internal/spec"
)

// Split out so one concern lives in one file. Same package.

func (r *run) budget() {
	rev := spec.Revision(r.certs)
	r.rep.Revision = rev

	// The state revision is normally authoritative, but Commit writes the document
	// before the state: if the state save failed, the document on disk already
	// carries this revision while the state still holds the previous one. Trusting
	// the state alone would double-count the budget and restart grace clocks on the
	// retry, so the loaded document's own revision counts as "already written" too.
	prevRev := ""
	if r.prev != nil {
		prevRev = r.prev.Revision
	}
	changed := rev != r.st.LastRevision && rev != prevRev

	// The other direction of the same crash window also counts: the document
	// carries a revision the state never recorded, and this round recomputed the
	// state's revision -- a revert X -> Y -> X where Y's state save was lost. The
	// rewrite is a real name-set change wecert will act on, so it must spend budget
	// like any other; calling it "unchanged" would let a revert escape accounting.
	if !changed && prevRev != "" && rev != prevRev {
		changed = true
	}

	if !changed {
		// In the already-written case (the document carries this revision but the
		// state does not) the state's fuse baseline lags what is actually on disk,
		// typically because a -force round's state save was lost. Refresh
		// LastDeclared from this round's declarations before calling the round
		// unchanged: the fuse must judge later rounds against reality, not against
		// the pre-force baseline. Commit persists the state on unchanged rounds too.
		if rev != r.st.LastRevision {
			r.st.SetLastDeclared(r.declaredNames())
		}
		r.rep.Mode = ModeUnchanged
		return
	}

	if r.o.opts.Force {
		r.st.RecordChange(r.now)
		return
	}

	used := r.st.ChangesWithin(r.o.opts.BudgetWindow, r.now)
	if used >= r.o.opts.Budget {
		r.freeze(fmt.Sprintf(
			"the change budget is exhausted: %d name-set changes in the last %s (budget %d); "+
				"Let's Encrypt allows 50 new certificates per registered domain per 7 days, shared across accounts, "+
				"and burning the whole allowance on configuration churn is how an account gets rate limited",
			used, humanDuration(r.o.opts.BudgetWindow), r.o.opts.Budget))
		return
	}

	r.st.RecordChange(r.now)
}

// declaredNames returns this round's expanded declaration set -- what DNS actually
// asked for, before guards, grace carries and grouping.
// declaredNameSet is every name the current round's declarations contribute, as a set.
//
// Distinct from the eligible set: a declared name may still have been filtered out by a
// guard, so this answers "did DNS still ask for it", which is what the grace period needs
// to know. Parse failures and conflict-rejected declarations are absent from
// r.declarations, so they do correctly count as no-longer-declared.
func (r *run) declaredNameSet() map[string]bool {
	out := make(map[string]bool, len(r.declarations)*2)
	for _, d := range r.declarations {
		for _, n := range d.Names() {
			out[n] = true
		}
	}
	return out
}

func (r *run) declaredNames() []string {
	declared := make([]string, 0, len(r.declarations)*2)
	for _, d := range r.declarations {
		declared = append(declared, d.Names()...)
	}
	return declared
}

// assemble builds the document and state.
func (r *run) assemble() {
	// Age the change ledger on EVERY round that reaches here.
	//
	// ChangesWithin both counts and prunes, and it used to be reached only on the path that
	// records a change -- so the -force path (which records without counting) and the
	// unchanged path (which does neither) never pruned. The ledger then grew without bound on
	// a deployment whose name set never changed, which is the common steady state: one entry
	// per pass that took either of those two paths.
	//
	// Calling it here means pruning is unconditional. The count is discarded because this is
	// not the decision point; the budget check below calls it again for the value.
	_ = r.st.ChangesWithin(r.o.opts.BudgetWindow, r.now)

	names := make([]string, 0, len(r.eligible))
	for n := range r.eligible {
		names = append(names, n)
	}
	sort.Strings(names)

	r.rep.Certificates = len(r.certs)
	r.st.SetLastNames(names)
	r.st.LastRevision = r.rep.Revision
	r.st.UpdatedAt = r.now

	// The fuse's baseline is the pure declaration set, kept apart from LastNames
	// on purpose -- see State.LastDeclared for why comparing against the covered
	// set wedges a staged decommission.
	r.st.SetLastDeclared(r.declaredNames())

	r.rep.Document = &spec.Document{
		APIVersion:   spec.APIVersionV1,
		Kind:         spec.KindDesiredState,
		GeneratedAt:  r.now,
		Generator:    r.o.opts.Generator,
		Revision:     r.rep.Revision,
		Certificates: r.certs,
	}
}

// freeze marks this round frozen and records the reason.
func (r *run) freeze(reason string) {
	r.rep.Mode = ModeFrozen
	r.rep.FreezeReasons = append(r.rep.FreezeReasons, reason)
	r.o.log.Warn("freezing: keeping the previous desired state", "reason", reason)

	// When frozen, still expose the previous document so callers and the report can
	// show what was left untouched.
	if r.prev != nil {
		cp := *r.prev
		r.rep.Document = &cp
		r.rep.Revision = r.prev.Revision
	}
}

func sameBoolPtr(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	if d < time.Hour {
		return d.Round(time.Minute).String()
	}
	return d.Round(time.Hour).String()
}

// sortDecisions keeps the report order stable: by hostname, then by the
// certificate the hostname landed in.
//
// The report is meant to be diffed by humans, and unstable ordering is unreadable.
func sortDecisions(ds []spec.Decision) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Hostname != ds[j].Hostname {
			return ds[i].Hostname < ds[j].Hostname
		}
		return ds[i].Certificate < ds[j].Certificate
	})
}

// writeJSONAtomic replaces the report in one step.
//
// The temp+fsync+rename protocol lives in internal/atomicfile: this writer, the desired-state
// document and the onboarding state file each had their own copy, and the copies had drifted (this
// one was missing the fsync, so a crash could leave a renamed, truncated report behind a round that
// otherwise completed).
func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')
	return atomicfile.Write(path, data, 0o644)
}
