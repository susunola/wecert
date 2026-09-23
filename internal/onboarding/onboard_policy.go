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
	"fmt"
	"sort"

	"github.com/susunola/wecert/internal/group"
)

// Split out so one concern lives in one file. Same package.

func (r *run) fuse() {
	if r.o.opts.Force {
		return
	}

	prev := r.st.LastDeclaredNameSet()
	if len(prev) == 0 {
		return // No baseline to compare against; the first run should write normally.
	}

	now := make(map[string]bool, r.rep.Declared)
	for _, d := range r.declarations {
		for _, n := range d.Names() {
			now[n] = true
		}
	}

	lost := 0
	for n := range prev {
		if !now[n] {
			lost++
		}
	}
	if lost == 0 {
		return
	}

	ratio := float64(lost) / float64(len(prev))
	r.rep.DeclarationDrop = lost

	if ratio <= r.o.opts.DropThreshold {
		// Below the freeze threshold, so the round proceeds -- but a run of these is
		// how a source that keeps returning slightly incomplete data erodes the
		// declaration set without ever tripping the fuse. Log it so the pattern is
		// visible instead of only showing up as a smaller document over time.
		r.o.log.Warn("the declared name set shrank, but stayed under the freeze threshold",
			"was", len(prev), "now", len(now), "lost", lost,
			"ratio", fmt.Sprintf("%.0f%%", ratio*100),
			"threshold", fmt.Sprintf("%.0f%%", r.o.opts.DropThreshold*100),
			"hint", "a one-off is normal; the same shrink every round means the declaration source is losing data")
		return
	}

	// A drop the written document already reflects is not upstream data loss: if
	// every name the previous document covers is still declared, acting on this
	// round cannot strip anything the document serves. That is exactly the
	// situation a -force round leaves behind when it wrote the document but crashed
	// before the state save -- the baseline simply lagged reality. Refresh the
	// baseline from this round's declarations and let the round proceed: freezing
	// here wedges, because frozen rounds never persist state, so every unforced
	// retry would re-trip on the same drop until someone passed -force again.
	if r.prev != nil && r.documentReflects(now) {
		r.st.SetLastDeclared(r.declaredNames())
		r.o.log.Warn("the written document already reflects this declaration set, so the fuse's "+
			"baseline was stale (a previous round's state save was lost); refreshing the baseline instead of freezing",
			"baseline", len(prev), "declared", len(now))
		return
	}

	r.freeze(fmt.Sprintf(
		"the declared name set dropped from %d to %d (%.0f%%, threshold %.0f%%): "+
			"this is almost always an upstream failure rather than a real decommission, "+
			"so nothing was changed; pass -force if the drop is intentional",
		len(prev), len(now), ratio*100, r.o.opts.DropThreshold*100))
}

// documentReflects reports whether every name the previous document covers is in
// the given declaration set -- i.e. acting on these declarations cannot remove any
// name the document currently serves.
func (r *run) documentReflects(declared map[string]bool) bool {
	for _, c := range r.prev.Certificates {
		for _, n := range c.Domains {
			if !declared[n] {
				return false
			}
		}
	}
	return true
}

// resolve applies the allowlist, guard 1 and the deletion grace period to obtain
// the final set of names to cover.
func (r *run) resolve() {
	r.eligible = make(map[string]bool, len(r.declarations)*2)
	r.accepted = make(map[string]bool, len(r.declarations))

	for _, d := range r.declarations {
		if !r.allowed(d.Hostname) {
			for _, n := range d.Names() {
				r.reject(n, fmt.Sprintf("registered domain %q is not in the allowlist",
					group.RegisteredDomain(d.Hostname)))
			}
			continue
		}

		// Guard 1: a declaration only counts when a CLB rule actually serves it.
		//
		// The check is against the names the declaration contributes, not against
		// Hostname alone. A wildcard declaration's subject is its subdomains, so asking
		// whether a rule serves the bare Hostname rejects it even when *.Hostname is
		// served -- which is the arrangement this guard exists to recognise, and the
		// rejection froze the whole round when it was the only declaration.
		//
		// A concrete declaration contributes just its Hostname, so its behaviour is
		// unchanged; the wildcard form additionally passes when the wildcard itself (or a
		// rule covering it) is served. The servedByRule lookup deliberately asks about the
		// expanded name as written, so a wildcard rule covers "*.example.com" and not the
		// apex -- that asymmetry is real and is why both names are checked separately.
		if r.o.opts.RequireRule && !r.guardUnavailable && !r.anyNameServed(d) {
			r.reject(d.Hostname, "no CLB rule serves this name (guard 1 not satisfied)")
			continue
		}

		r.accepted[d.Hostname] = true
		for _, n := range d.Names() {
			r.eligible[n] = true
		}
	}

	// The abrupt-change fuse must run before eligible, hence its separate call right
	// after parse in Run. Here we only look at names "present last round, ineligible
	// now".
	r.applyGrace()
}

// anyNameServed reports whether a CLB rule serves any of the names this declaration
// contributes. See the guard-1 comment in resolve.
func (r *run) anyNameServed(d *Declaration) bool {
	for _, n := range d.Names() {
		if r.servedByRule(n) {
			return true
		}
	}
	return false
}

func (r *run) allowed(hostname string) bool {
	if len(r.o.opts.Allowlist) == 0 {
		return true
	}
	reg := group.RegisteredDomain(hostname)
	i := sort.SearchStrings(r.o.opts.Allowlist, reg)
	return i < len(r.o.opts.Allowlist) && r.o.opts.Allowlist[i] == reg
}

// applyGrace is §5.3: deletion is an order of magnitude more conservative than
// addition.
//
// Addition is convergence, deletion is a decision. A two-source design naturally
// makes state flap:
//
//	t0: _wecert declaration added   → guard not ready, no issue    correct
//	t1: CLB rule added              → issue                        correct
//	t2: a DNS query flaps           → delete at once → re-issue    ✗ burns quota
//	t3: DNS recovers                → re-issued again              ✗ burns it again
//
// So deletion must satisfy all of: every source confirms absence, the absence lasts
// past the grace period, and no other resource still references it.
func (r *run) applyGrace() {
	// First snapshot the names that really are still in this round's declarations.
	//
	// It must be taken before carry: carry pushes the previous revision's names back
	// into eligible, and clearing their absence markers resets the grace period every
	// time -- it would never elapse and the deletion path would be a no-op.
	present := make(map[string]bool, len(r.eligible))
	for n := range r.eligible {
		present[n] = true
	}

	absent := make([]string, 0)
	for n := range r.st.LastNameSet() {
		if !r.eligible[n] {
			absent = append(absent, n)
		}
	}
	sort.Strings(absent)

	// A name covered last round but not eligible now is only "absent" in the sense that it
	// left the accepted set. It has NOT necessarily stopped being declared: guard 1 rejects a
	// declaration whose name no CLB rule serves, the allowlist rejects a declaration outside
	// it, and a declaration that failed the conflict check never reaches the eligible set
	// either. Treating those as removed was wrong twice over:
	//
	//   - the report said "no longer declared, but only absent for 0s" about a name that is
	//     declared right now, and
	//   - dropping it from the document changes the revision, so the certificate is reissued
	//     without the name -- and when the filter recovers (a rule flaps back, a region becomes
	//     visible again) the revision changes back and the name is issued all over again. One
	//     wobble in a network-read guard therefore cost two issuances AND two rounds without
	//     coverage of a name that never stopped being declared.
	//
	// So the rule is: a DECLARATION keeps a name covered. A filter that does not accept it --
	// a guard read, or an allowlist a human narrowed -- prevents new coverage and is reported
	// with its own reason, but it never removes coverage that exists. Removing coverage is done
	// by removing the declaration, which then goes through the grace period and the reference
	// check below like any other removal (or with -force, for an operator who wants it now).
	declaredNow := r.declaredNameSet()
	stillDeclared := make([]string, 0)
	genuinelyAbsent := make([]string, 0, len(absent))
	for _, n := range absent {
		if declaredNow[n] {
			stillDeclared = append(stillDeclared, n)
			continue
		}
		genuinelyAbsent = append(genuinelyAbsent, n)
	}
	absent = genuinelyAbsent

	for _, n := range stillDeclared {
		// MarkPresent because the name is here right now: a stale absence marker from an
		// earlier round must not shorten the grace period if the declaration is later removed.
		// MarkAbsent would start a grace clock for a name that never left.
		r.st.MarkPresent(n)

		// One verdict per hostname in the report: the filter's exclusion is replaced by the
		// carry, with the filter's own words explaining why it was not accepted on its merits.
		reason := r.stillDeclaredReason(n)
		r.unreject(n)
		r.carry(n, reason)
		r.o.log.Info("a declared name did not pass a filter this round; keeping its coverage",
			"hostname", n, "reason", reason)
	}

	for _, n := range absent {
		since, _ := r.st.MarkAbsent(n, r.now)
		age := r.now.Sub(since)

		switch {
		case r.o.opts.Force:
			r.reject(n, "removed: -force was used, so the grace period and the reference check were skipped")

		case r.guardUnavailable:
			// With the guard unreadable we cannot say whether the name is still served,
			// so a deletion here has no basis.
			r.carry(n, fmt.Sprintf("was declared before but the guard is unavailable; "+
				"keeping it for now (absent for %s)", humanDuration(age)))

		case age < r.o.opts.GracePeriod:
			r.carry(n, fmt.Sprintf("no longer declared, but only absent for %s (grace period %s); "+
				"a declaration can flap, and a flap would otherwise cost two issuances",
				humanDuration(age), humanDuration(r.o.opts.GracePeriod)))

		case r.o.src.Rules == nil:
			// No rule source means the reference check cannot run at all. Unlike a
			// guard outage this is configuration, not weather, so the reason says
			// which -- "a CLB rule still references it" would be a lie here.
			r.carry(n, fmt.Sprintf("no longer declared and absent for %s, but no CLB rule source is configured, "+
				"so the reference check cannot run", humanDuration(age)))

		case r.referenced(n):
			r.carry(n, fmt.Sprintf("no longer declared and absent for %s, but a CLB rule still references it",
				humanDuration(age)))

		default:
			// Confirmed absent + past the grace period + unreferenced: all three must
			// hold before removal is allowed.
			r.reject(n, fmt.Sprintf("removed: confirmed absent for %s, past the %s grace period, "+
				"and no CLB rule references it", humanDuration(age), humanDuration(r.o.opts.GracePeriod)))
		}
	}

	// Clear the absence marker for names that really appeared this round: the name
	// is back, so the grace period resets.
	for n := range present {
		r.st.MarkPresent(n)
	}

	// Drop absence markers that no longer describe anything.
	//
	// MarkAbsent is reached only from the absent set, which is derived from the PREVIOUS
	// round's covered names. Once a name has left the covered set and its grace period has
	// run out, it never enters that set again -- so nothing clears its marker, and
	// MarkPresent only runs for names that come back. The map therefore grew by one entry
	// for every name ever removed from a certificate, for the life of the state file, on a
	// system whose hostnames churn by design.
	//
	// After the loop above, the markers that SHOULD exist are exactly the names absent this
	// round: every one of them got a MarkAbsent, and every name that came back got a
	// MarkPresent. Anything else is a leftover from an earlier round, including names whose
	// grace period expired and which were consequently removed from the document.
	//
	// Pruning to the absent set rather than to "previous or current names" is deliberate:
	// this runs BEFORE LastNames is reassigned, so r.st.LastNames is still the previous
	// revision and would keep every already-removed name alive for one more round.
	keepMarkers := make(map[string]bool, len(absent))
	for _, n := range absent {
		keepMarkers[n] = true
	}
	for n := range r.st.AbsentSince {
		if !keepMarkers[n] {
			delete(r.st.AbsentSince, n)
		}
	}
}

// carry keeps a name that was present last round but ineligible this round in the
// final set.
//
// Keeping it means wecert keeps converging on it -- the domain stays in the
// certificate and nothing breaks. This is the only safe default in every "cannot
// tell" situation.
func (r *run) carry(name, reason string) {
	r.eligible[name] = true
	r.reasons[name] = reason
	r.rep.CarriedForward++
}

// stillDeclaredReason explains why a still-declared name was not accepted this round.
//
// The wording comes from the decision the filter already recorded for it -- guard 1 and the
// allowlist each reject with their own reason -- so the report does not grow a second vocabulary
// for the same fact. A name with no recorded decision (a conflict, or a wildcard whose declaration
// was rejected under its apex name) falls back to a sentence that says what is known: it is
// declared, it did not pass, and it keeps what it has.
func (r *run) stillDeclaredReason(name string) string {
	if i, excluded := r.excludedIdx[name]; excluded {
		return fmt.Sprintf("%s; the declaration is still there, so the name keeps its coverage "+
			"(removing coverage means removing the declaration)", r.rep.Decisions[i].Reason)
	}
	return "declared, but it did not pass a filter this round; keeping its coverage " +
		"(removing coverage means removing the declaration)"
}

// unreject drops the exclusion decision recorded for a hostname this round carries anyway.
//
// The report carries ONE verdict per hostname, and the verdict for a name that keeps its coverage
// is "included". Leaving the earlier exclusion in place showed the same name twice with opposite
// answers, in the artifact a human reads to find out what happened.
func (r *run) unreject(hostname string) {
	i, excluded := r.excludedIdx[hostname]
	if !excluded {
		return
	}
	delete(r.excludedIdx, hostname)
	r.rep.Decisions = append(r.rep.Decisions[:i], r.rep.Decisions[i+1:]...)
	// Removing an entry shifts every later one; the index has to shift with it.
	for h, j := range r.excludedIdx {
		if j > i {
			r.excludedIdx[h] = j - 1
		}
	}
}

// referenced reports whether a name is still referenced by some CLB rule.
//
// "Cannot tell" counts as referenced: the conservative direction is to keep, not
// to delete. applyGrace handles the no-rule-source case itself, so the carry
// reason can say *why* it cannot tell instead of claiming a rule exists.
func (r *run) referenced(name string) bool {
	if r.guardUnavailable || r.o.src.Rules == nil {
		return true
	}
	return r.servedByRule(name)
}

// servedByRule reports whether some layer-7 rule can serve this name.
//
// A rule domain may itself be a wildcard (CLB supports *.example.com), so the check
// is wildcard-aware in both directions: a wildcard declaration is served by any rule
// it covers, and a concrete name is served by any rule wildcard that covers it.
func (r *run) servedByRule(name string) bool {
	if r.rules[name] {
		return true
	}

	if group.IsWildcard(name) {
		for rd := range r.rules {
			if group.WildcardCovers(name, rd) {
				return true
			}
		}
		return false
	}
	for rd := range r.rules {
		if group.IsWildcard(rd) && group.WildcardCovers(rd, name) {
			return true
		}
	}
	return false
}

// build groups the names and computes each certificate's SAN.
