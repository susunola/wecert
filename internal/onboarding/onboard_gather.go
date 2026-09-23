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
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/spec"
)

// Split out so one concern lives in one file. Same package.

func (r *run) loadPrevious() error {
	doc, err := spec.LoadDocument(r.o.opts.DocumentPath)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			return nil // first run: no previous revision to protect
		}
		return fmt.Errorf(
			"the previous desired-state document %s exists but cannot be read (%w); refusing this round "+
				"rather than rebuilding it without the previous revision -- the previous revision is what keeps "+
				"an over-cap group's existing certificate instead of dropping it, so writing now could remove a "+
				"live certificate from the desired state. Fix the file's permissions/ownership (or move it aside "+
				"to declare a fresh start) and re-run",
			r.o.opts.DocumentPath, err)
	}
	r.prev = doc
	r.rep.PreviousRevision = doc.Revision
	return nil
}

// recoverBaselineFromDocument rebuilds the grace and fuse baseline when the state file is
// gone but a previous document is on disk.
//
// LoadState treats a missing state file as "first run", and on a genuine first run that is
// right. But the state file and the document are separate files: losing only the state
// (a cleared /var/lib cache, a restored document without its state, a typo in
// onboarding.statePath) left LastNames empty while the document still described the live
// desired state. An empty baseline disables all three of the guards that make deletion
// conservative, in the same round:
//
//   - the abrupt-change fuse returns early with no baseline to compare against, so a mass
//     disappearance is not noticed at all;
//   - applyGrace derives "newly absent" from LastNames, so nothing is absent and every
//     removal takes effect with a zero-second grace period;
//   - MarkAbsent never runs, so the report shows drop=0 and the removal is not recorded.
//
// The document itself is the evidence: it is the previous round's output, and the names it
// covers are the names that were live. Seeding from it restores the grace period and gives
// the fuse a baseline, so a name that really has gone still has to survive the usual
// checks before it is removed. This is the same principle the corrupt-state path already
// enforces by refusing to run -- the state must never silently read as "nothing was there".
func (r *run) recoverBaselineFromDocument() {
	if r.prev == nil || len(r.st.LastNames) > 0 {
		return
	}
	var names []string
	seen := make(map[string]bool)
	for i := range r.prev.Certificates {
		for _, d := range r.prev.Certificates[i].Domains {
			if !seen[d] {
				seen[d] = true
				names = append(names, d)
			}
		}
	}
	if len(names) == 0 {
		return
	}
	r.st.SetLastNames(names)
	if len(r.st.LastDeclared) == 0 {
		// The fuse compares declarations against declarations. Which of these names were
		// declared is not recoverable from the document, but using the covered set is the
		// documented fallback for a state file written before LastDeclared existed, and it
		// errs toward freezing rather than toward deleting.
		r.st.SetLastDeclared(names)
	}
	r.o.log.Warn("the onboarding state file is missing but a desired-state document exists; "+
		"rebuilding the grace-period and fuse baseline from the document, so removals are not "+
		"treated as a first run",
		"path", r.o.opts.StatePath, "document", r.o.opts.DocumentPath, "names", len(names))
}

// gather fetches declarations and guards.
//
// Where §5.1 lands: when the declaration source errors, the correct answer is to
// **keep the status quo**, not "desired state is empty". Once the desired state
// collapses, wecert re-issues a certificate with no domains, or strips domains from
// one, and live handshakes fail immediately -- far worse than not issuing.
func (r *run) gather(ctx context.Context) {
	raw, err := r.o.src.Declarations.ListDeclarations(ctx)
	if err != nil {
		r.freeze(fmt.Sprintf("declaration source failed: %v", err))
		return
	}

	r.parse(raw)
	if r.rep.Frozen() {
		return
	}

	r.loadRules(ctx)
}

// loadRules reads the CLB guard.
func (r *run) loadRules(ctx context.Context) {
	r.rules = map[string]bool{}
	if r.o.src.Rules == nil {
		if r.o.opts.RequireRule {
			r.freeze("onboarding.requireCLBRule is on but no CLB rule source is configured")
		}
		return
	}

	domains, err := r.o.src.Rules.ListRuleDomains(ctx)
	if errors.Is(err, errIncompleteRuleList) {
		// Answering with the rules that did arrive would be read as "every other name has no
		// rule", and that is the shape that removes coverage of a name that is still served.
		r.guardUnavailable = true
		r.rep.GuardUnavailable = true
		r.rep.GuardIncomplete = true
		r.o.log.Warn("the CLB rule list came back incomplete, so this round treats the guard as "+
			"unavailable: no name will be removed, and additions are not checked against a list "+
			"that is known to be short",
			"err", err)
		return
	}
	if err != nil {
		// A broken guard is not "all rules are gone".
		//
		// §9 explicitly refuses "degrade to a single source when one is unavailable":
		// degradation makes safety vanish together with the source, exactly when it is
		// needed most. So nothing is removed this round and the guard counts as satisfied
		// (conservative direction: keep).
		//
		// Note the mechanism, because an earlier version of this comment said the judgement
		// "always freezes": it does not call freeze(). Setting guardUnavailable suppresses
		// deletions while leaving the rest of the round intact, so additions still converge.
		// Freezing outright would stop every certificate from being updated because one API
		// call failed — a worse trade than "no deletions today".
		r.guardUnavailable = true
		r.rep.GuardUnavailable = true
		r.o.log.Warn("CLB rule guard is unavailable this round; no name will be removed and the guard is treated as satisfied",
			"err", err)
		return
	}

	for _, d := range domains {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if n != "" {
			r.rules[n] = true
		}
	}
}

// parse turns raw TXT records into declarations.
//
// Unparseable records do not enter the desired state, and the first one for a hostname leaves a
// decision entry: silently dropping a declaration leaves a human doubting their sanity in front of
// the DNS console. The exception is a record whose hostname already has a usable declaration --
// the report carries one verdict per name, so that record is named in the journal instead (see the
// guard in the loop below).
func (r *run) parse(raw []RawDeclaration) {
	r.reasons = map[string]string{}
	byHost := map[string]*Declaration{}
	byHostRecord := map[string]string{}
	// rejected holds hostnames already thrown out by the conflict check, so a
	// later record for the same hostname cannot come back as a fresh first-seen.
	rejected := map[string]bool{}

	for _, rec := range raw {
		d, err := ParseDeclaration(rec.Zone, rec.Record, rec.Values)
		if err != nil {
			// Do not report a hostname as excluded when another record already gave it a usable
			// declaration. The mirror of this rule is the unreject below: a name that ends up
			// included must carry exactly one verdict, and which record the zone walk happened to
			// return first is not something the report should depend on.
			host := hostnameFromRecord(rec.Record)
			if _, usable := byHost[host]; usable {
				// Not silent, though: the decision list is the artifact an operator reads, and it
				// cannot carry this record without contradicting the declaration that won. The
				// journal is where "one of your records is broken and was ignored" has to show up,
				// or a typo'd wildcard=1 vanishes without a trace.
				r.o.log.Warn("a declaration record could not be parsed and was ignored because the same "+
					"name is declared by a record that does parse",
					"record", rec.Record, "zone", rec.Zone, "hostname", host, "err", err)
				continue
			}
			r.reject(host, fmt.Sprintf("unparseable declaration: %v", err))
			continue
		}
		if rejected[d.Hostname] {
			// Once two records for one hostname disagreed, the hostname is poisoned
			// for the round: accepting a third record would let whoever writes last
			// silently win the conflict. The exclusion is already recorded (the conflict is the
			// cause, and reject keeps a name's first reason), so there is nothing to add here --
			// only this record to refuse.
			continue
		}
		if prev, dup := byHost[d.Hostname]; dup {
			// Two declarations for the same hostname: allowed, but the metadata must
			// agree. Disagreement means someone wrote contradictory things in two zones,
			// and guessing which one is right would be wrong either way.
			if prev.Wildcard != d.Wildcard || prev.Profile != d.Profile ||
				prev.KeyType != d.KeyType || !sameBoolPtr(prev.Deploy, d.Deploy) {
				// Zones are in the message because the record name usually is not enough to tell
				// the two apart: the same name declared in a parent zone and in a delegated
				// subzone has the same record string, and the message used to print it twice.
				r.reject(d.Hostname, fmt.Sprintf(
					"conflicting declarations for the same name (%s in zone %s and %s in zone %s): "+
						"they disagree on wildcard/profile/keytype/deploy",
					byHostRecord[d.Hostname], prev.Zone, d.Record, d.Zone))
				rejected[d.Hostname] = true
				delete(byHost, d.Hostname)
				delete(byHostRecord, d.Hostname)
				continue
			}
			continue
		}
		// This record parsed and survived the conflict checks, so the hostname has a usable
		// declaration. Any exclusion recorded for it earlier in this loop is stale: the usual
		// case is a typo'd record in one zone and a valid one for the same name in another
		// (a parent zone and a delegated subzone), and leaving the exclusion in place showed the
		// same hostname twice in the report -- once as excluded and once as included -- while
		// stillDeclaredReason could quote the stale text for a name it carries.
		r.unreject(d.Hostname)
		byHost[d.Hostname] = d
		byHostRecord[d.Hostname] = d.Record
	}

	r.declarations = r.declarations[:0]
	for _, d := range byHost {
		r.declarations = append(r.declarations, d)
	}
	sort.Slice(r.declarations, func(i, j int) bool {
		return r.declarations[i].Hostname < r.declarations[j].Hostname
	})

	// Count of expanded declared names, for the report and the abrupt-change fuse.
	seen := make(map[string]bool, len(r.declarations)*2)
	for _, d := range r.declarations {
		for _, n := range d.Names() {
			seen[n] = true
		}
	}
	r.rep.Declared = len(seen)
}

// reject records a "this name was excluded" decision.
//
// One verdict per hostname: a name that is already excluded keeps the reason it was excluded for
// first, which is the cause. A third record for a name a conflict already poisoned, or a second
// rejection from a later stage, used to append another exclusion -- the report then listed the same
// hostname two or three times with different stories, in the artifact a human reads to find out
// what happened. The opposite transition (a name that ends up included) is unreject's job, and
// include calls it.
func (r *run) reject(hostname, reason string) {
	if _, excluded := r.excludedIdx[hostname]; excluded {
		return
	}
	r.excludedIdx[hostname] = len(r.rep.Decisions)
	r.rep.Decisions = append(r.rep.Decisions, spec.Decision{
		Hostname: hostname,
		Included: false,
		Reason:   reason,
	})
}

// include records a "this name is covered" decision.
//
// It drops any exclusion recorded for the name first, so the report cannot carry two opposite
// verdicts for one hostname whichever order the stages ran in. unreject is deliberately separate:
// the carry path needs to drop the exclusion and *then* decide the reason, and calling include
// there would add a second inclusion.
func (r *run) include(d spec.Decision) {
	r.unreject(d.Hostname)
	r.rep.Decisions = append(r.rep.Decisions, d)
}

// hostnameFromRecord does its best to extract the recognizable name from a record.
//
// Seeing "_wecert.bad.example.com" instead of "bad.example.com" in a report looks
// minor, but the report is a troubleshooting tool for humans: making someone strip
// a prefix in their head smears another layer over "I added the domain, why wasn't
// it issued?".
func hostnameFromRecord(record string) string {
	full := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record)), ".")
	if !strings.HasPrefix(full, DeclarationPrefix) {
		return full
	}
	// Normalise the way ParseDeclaration does, so that the name this reports is the same string
	// the declaration carries. Trimming one trailing dot and skipping group.Normalize meant a
	// record written "_wecert.api.example.com.." (or with stray whitespace) produced an exclusion
	// for "api.example.com." beside an inclusion for "api.example.com" -- one DNS name, two
	// verdicts, two spellings.
	host, err := group.Normalize(strings.TrimPrefix(full, DeclarationPrefix))
	if err != nil {
		// Not a name anything could be declared under, so there is nothing to match; the label
		// only has to be recognisable.
		return strings.TrimPrefix(full, DeclarationPrefix)
	}
	return host
}

// fuse is §5.2: the abrupt desired-state change fuse.
//
// It compares the **declaration set itself** (LastDeclared), not the result
// after guards and grouping. Because what it catches is "upstream returned
// incomplete data", whereas shrinking caused by guard filtering, the grace
// period or a grouping failure is our own, recorded decision.
//
// The covered set (LastNames) would be the wrong baseline: it includes
// grace-carried names, so a staged decommission (10 -> 7 -> 6 declarations)
// would see its own carries as "still declared" -- every step re-trips the fuse
// and MarkAbsent never runs again, wedging the round into a self-sustaining
// freeze.
//
// A normal decommission does not remove a third of the declarations. Losing a third
// at once is almost certainly an upstream fault (incomplete API response, changed
// permissions, zone read failure). Acting on that strips SANs in bulk. Freezing is
// safer than acting.
//
// Known limit, and it is deliberate: because the baseline is rebased on every round
// that passes, the fuse bounds the drop **per round**, not cumulatively. An upstream
// that loses a slice just under the threshold every round still erodes the set
// (10 -> 7 -> 5 -> 4 ...). Comparing against a fixed high-water mark instead would
// catch that, but every variant of it also counts the grace-carried names of a
// staged decommission as "lost" on each step, which re-trips the fuse, stops
// MarkAbsent from running, and wedges the round into a self-sustaining freeze --
// exactly the failure TestStagedDecommissionDoesNotWedgeTheFuse pins down. There is
// no local rule that separates "the source is eroding" from "the operator is
// decommissioning in stages": both are the same names staying gone. So the per-round
// bound is kept, and a sub-threshold drop is **reported** instead (DeclarationDrop)
// so that a run of them is visible to alerting rather than silent. The grace period
// and the CLB reference check are what bound the damage of each individual deletion.
