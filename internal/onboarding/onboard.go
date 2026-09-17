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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/spec"
)

// Report disposition modes.
const (
	// ModeWritten: the desired state changed and the document was written.
	ModeWritten = "written"

	// ModeUnchanged: the computed desired state is byte-for-byte equivalent to the
	// previous revision, but the document is rewritten to refresh generatedAt --
	// onboarding's liveness signal, whose absence would false-alarm wecert.
	ModeUnchanged = "unchanged"

	// ModeFrozen: this round reached no trustworthy conclusion; keep the previous
	// revision.
	ModeFrozen = "frozen"
)

// DeclarationLister enumerates every _wecert.* declaration in DNS.
type DeclarationLister interface {
	// ListDeclarations returns all declarations.
	//
	// A returned error means "this round could not read everything", not "there are
	// no declarations". The two must be treated differently: the former freezes, and
	// only the latter may be truly empty. Conflating them reads one API blip as
	// "every domain is gone".
	ListDeclarations(ctx context.Context) ([]RawDeclaration, error)
}

// RawDeclaration is one not-yet-parsed TXT record.
type RawDeclaration struct {
	// Zone is the DNS zone holding this record; reporting only.
	Zone string

	// Record is the full record name, like _wecert.api.example.com.
	Record string

	// Values are the values of all TXT records under that name.
	Values []string
}

// RuleLister enumerates the configured layer-7 domains.
type RuleLister interface {
	// ListRuleDomains returns the domains configured on all CLB rules.
	//
	// It is a **guard**, not a source: it only vetoes already-declared intent, it
	// never infers intent. As a source it would carry all the risk of inference; as
	// a guard its failure mode is far safer -- the worst case is "something that
	// should have been issued was not", never "something that should not have been
	// deleted got deleted".
	ListRuleDomains(ctx context.Context) ([]string, error)
}

// Sources are the external sources onboarding needs.
type Sources struct {
	// Declarations enumerates _wecert declarations. Required.
	Declarations DeclarationLister

	// Rules enumerates CLB rule domains. Optional, but strongly recommended: it is
	// the only guard against "declared in DNS but the rule is not in place yet".
	Rules RuleLister
}

// Options are the onboarding policy parameters.
//
// The defaults are deliberately conservative. The document is explicit in §8: the
// debounce window, grouping cap and abrupt-change threshold can only come from real
// drift data, and guessing wrong costs account-level rate limiting. So run in
// observe mode to gather data first, then tune here.
type Options struct {
	// DocumentPath is where the desired-state document is written.
	DocumentPath string

	// StatePath is the path to onboarding's own state file.
	//
	// Empty means no persistence, and the consequence is stronger than "the grace period
	// recomputes every run": with nothing persisted, every removal takes effect on the
	// round that observes it. There is no AbsentSince entry to age, so the grace period is
	// bypassed rather than merely postponed, and the abrupt-change fuse has no baseline
	// either. RecoverBaselineFromDocument narrows the damage when a previous document is on
	// disk, but on a first run there is nothing to recover from.
	//
	// Suitable only for one-off troubleshooting, never for a system left running.
	StatePath string

	// ReportPath is where the decision report (JSON) is written. Empty means no report.
	ReportPath string

	// Generator is the generator identity written into the document, like
	// wecert-onboard/v0.5.0.
	Generator string

	// Profile / KeyType / Deploy are the defaults when a declaration does not
	// override them.
	Profile string
	KeyType string
	Deploy  bool

	// MaxNames is the per-certificate SAN cap. 0 means the default of 25, which is
	// deliberately aligned with tlsserver so a later profile switch needs no redesign --
	// it is *not* the profile's own cap (classic would be 100).
	MaxNames int

	// RequireRule means a declaration only takes effect when a CLB rule also serves
	// it (guard 1 required).
	//
	// It blocks two real problems: a declaration written before its rule exists
	// (causing a useless issuance), and a misspelled domain no rule serves at all.
	RequireRule bool

	// Allowlist restricts which registered domains may be issued. Empty means no
	// restriction.
	//
	// This is the §5.5 railing: sources only provide clues, authorization must be an
	// explicit act. It applies to whole registered domains, containing the blast
	// radius of accidents like "a script bulk-wrote 500 declarations".
	Allowlist []string

	// DropThreshold is the abrupt-change fuse threshold: freeze when the name set
	// loses more than this fraction in one round. 0 means DefaultDropThreshold.
	DropThreshold float64

	// GracePeriod is the deletion grace period. 0 means DefaultGracePeriod.
	//
	// Deletion is an order of magnitude more dangerous than addition: a wrong
	// addition issues one extra certificate, a wrong deletion breaks live handshakes.
	GracePeriod time.Duration

	// BudgetWindow / Budget are the quota budget: how many name-set changes are
	// allowed within the window. Budget 0 means DefaultBudget.
	BudgetWindow time.Duration
	Budget       int

	// Force skips the abrupt-change fuse, the quota budget, the deletion grace period
	// AND the "is a CLB rule still referencing this name?" check, writing exactly what
	// this round computed. The reference check is the last thing standing between this
	// flag and removing a name that is still being served, so it is named in the flag
	// help as well as here.
	//
	// It exists to give "yes, I really did cause this drop" an escape hatch. But it
	// must be an explicit human action -- automation must never carry it, or the gate
	// may as well not exist.
	Force bool

	// Now is injectable for testing.
	Now func() time.Time
}

// Defaults. All conservative; see the Options comments for why.
const (
	DefaultDropThreshold = 0.30
	DefaultGracePeriod   = 24 * time.Hour
	DefaultBudgetWindow  = 7 * 24 * time.Hour
	DefaultBudget        = 25
)

// Onboarder evaluates sources into a desired state.
type Onboarder struct {
	src  Sources
	opts Options
	log  *slog.Logger
}

// New constructs an onboarder.
func New(src Sources, opts Options, log *slog.Logger) (*Onboarder, error) {
	if src.Declarations == nil {
		return nil, errors.New("onboarding: a declaration source is required")
	}
	if opts.DocumentPath == "" {
		return nil, errors.New("onboarding: DocumentPath is required")
	}
	if opts.Profile == "" {
		opts.Profile = config.ProfileClassic
	}
	if opts.KeyType == "" {
		opts.KeyType = config.KeyTypeECDSAP256
	}
	if opts.MaxNames <= 0 {
		opts.MaxNames = 25 // Aligned with tlsserver so a future profile switch needs no redesign.
	}
	if opts.DropThreshold <= 0 {
		opts.DropThreshold = DefaultDropThreshold
	} else if math.IsNaN(opts.DropThreshold) || opts.DropThreshold >= 1 {
		// Mirror the config layer's [0,1) check: a CLI -drop-threshold flag reaches
		// Options directly, bypassing that validation, and a percentage written as
		// `30` would silently disable the abrupt-change fuse this guard exists for.
		//
		// NaN is rejected explicitly: every comparison against it is false, so it
		// satisfies this bound and the `<= 0` default above alike and would otherwise
		// pass straight through.
		return nil, fmt.Errorf(
			"onboarding: DropThreshold is a fraction in [0,1): got %v "+
				"(a value of 1 or more can never be exceeded, so the abrupt-change fuse would never fire)",
			opts.DropThreshold)
	}
	if opts.GracePeriod <= 0 {
		opts.GracePeriod = DefaultGracePeriod
	}
	if opts.BudgetWindow <= 0 {
		opts.BudgetWindow = DefaultBudgetWindow
	}
	if opts.Budget <= 0 {
		opts.Budget = DefaultBudget
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	if src.Rules == nil {
		// The deletion path then never fires: the reference check cannot run, so
		// every grace-expired name is carried forever. That is survivable (names
		// accumulate, nothing breaks), but nobody should discover it from a report
		// months later.
		log.Warn("no CLB rule source is configured: the deletion reference check cannot run, " +
			"so no name will ever be removed once declared")
	}

	// Normalize the allowlist to registered domains too, so nobody writes
	// "www.example.com" expecting it to match all of example.com.
	if len(opts.Allowlist) > 0 {
		for i, a := range opts.Allowlist {
			opts.Allowlist[i] = group.RegisteredDomain(strings.ToLower(strings.TrimSpace(a)))
		}
		// allowed() looks entries up with sort.SearchStrings, so this slice has to
		// be sorted. Sorting at the call site is not enough: normalising each entry
		// to its registered domain can reorder it (a.example.com -> example.com),
		// and an unsorted slice makes the binary search miss entries that really
		// are on the allowlist -- which silently drops names from certificates.
		sort.Strings(opts.Allowlist)
	}
	return &Onboarder{src: src, opts: opts, log: log}, nil
}

// Report is the complete result of one onboarding round, and the human-facing copy.
type Report struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Generator   string    `json:"generator"`
	Mode        string    `json:"mode"`

	// FreezeReasons explains why the round froze. Non-empty means no trustworthy
	// conclusion.
	FreezeReasons []string `json:"freezeReasons,omitempty"`

	// GuardUnavailable means the CLB guard is unavailable this round. No deletion
	// decisions are made this round.
	GuardUnavailable bool `json:"guardUnavailable,omitempty"`

	// GuardIncomplete means the guard ANSWERED, but short of what the API said existed. It is
	// reported apart from GuardUnavailable on purpose: both suppress removals, but this one is
	// not weather to retry -- it means the rule list itself is being truncated, and the names it
	// did not mention were never checked against anything.
	GuardIncomplete bool `json:"guardIncomplete,omitempty"`

	Declared          int `json:"declared"`
	Included          int `json:"included"`
	CoveredByWildcard int `json:"coveredByWildcard"`
	CarriedForward    int `json:"carriedForward"`
	Certificates      int `json:"certificates"`

	// DeclarationDrop is how many names the declaration set lost since the previous
	// round, whatever the verdict. The fuse only freezes above the threshold, so a
	// run of sub-threshold drops would otherwise erode the set silently; this makes
	// the pattern alertable.
	DeclarationDrop int `json:"declarationDrop,omitempty"`

	Revision         string          `json:"revision,omitempty"`
	PreviousRevision string          `json:"previousRevision,omitempty"`
	Decisions        []spec.Decision `json:"decisions"`

	// Document is the desired state this round computed. When frozen it may still be
	// the previous revision (for troubleshooting), but Commit will not write it.
	Document *spec.Document `json:"-"`

	// State is the state that should be persisted after this round.
	State *State `json:"-"`
}

// Frozen reports whether this round froze.
func (r *Report) Frozen() bool { return r.Mode == ModeFrozen }

// Run evaluates one round and writes no files.
func (o *Onboarder) Run(ctx context.Context) (*Report, error) {
	now := o.opts.Now()
	r := &run{
		o:   o,
		now: now,
		rep: &Report{
			GeneratedAt: now,
			Generator:   o.opts.Generator,
			Mode:        ModeWritten,
		},
	}

	// A corrupt state file must fail outright, never continue as empty state: that
	// zeroes every grace period, turning deletion from conservative into aggressive.
	st, err := o.loadState()
	if err != nil {
		return nil, err
	}
	r.st = st
	r.rep.State = st

	if err := r.loadPrevious(); err != nil {
		return nil, err
	}
	r.recoverBaselineFromDocument()
	r.gather(ctx)

	// The order is deliberate: judge the abrupt change from the raw declarations
	// first, then apply guards and the grace period. Reversing it would misread "our
	// own filtering" as "upstream collapsed".
	if !r.rep.Frozen() {
		r.fuse()
	}
	if !r.rep.Frozen() {
		r.resolve()
	}
	if !r.rep.Frozen() {
		r.build()
	}
	// An empty desired state is never written to disk.
	//
	// A "legitimately empty" file and a "generation failed, hence empty" file look
	// identical, and accepting the latter strips every domain from every certificate.
	// The risk is too asymmetric, so "I really do want to tear it all down" can only
	// be done explicitly and loudly by a human.
	if !r.rep.Frozen() && len(r.certs) == 0 {
		r.freeze("the desired state came out empty: an empty document is indistinguishable " +
			"from a failed generation, and acting on it would strip every name from every certificate; " +
			"to tear everything down, remove the declarations and stop renewing by hand")
	}
	if !r.rep.Frozen() {
		r.budget()
	}
	if !r.rep.Frozen() {
		r.assemble()
	}

	sortDecisions(r.rep.Decisions)
	return r.rep, nil
}

// Commit persists: the desired-state document, the onboarding state, the decision
// report.
//
// When frozen it writes only the report -- the report is exactly what tells a human
// why nothing moved this round.
func (o *Onboarder) Commit(rep *Report) error {
	if rep.Frozen() {
		// When frozen no state is touched: AbsentSince would advance, but this round
		// we do not know whether the names still exist; advancing it shortens the
		// grace period on noise.
		return o.writeReport(rep)
	}

	// The document goes first, the state second. A failure between the two leaves
	// the state one revision *behind* the document, which is the direction that
	// heals itself: the next round recomputes the same content and the revision
	// comparison in budget() recognises the document already carries it, counting
	// the round as unchanged instead of spending budget again. The reverse order
	// would leave the state ahead of the document -- claiming a revision that was
	// never written -- and no later round could ever detect that.
	if err := spec.WriteDocument(o.opts.DocumentPath, rep.Document); err != nil {
		return err
	}
	if o.opts.StatePath != "" {
		if err := rep.State.Save(o.opts.StatePath); err != nil {
			return err
		}
	}

	// The report is written LAST, and the order is the contract: it is the human-readable
	// claim about what this round did ("mode": "written", with a revision), so writing it
	// before the files it describes leaves a report announcing a revision that was never
	// written whenever a write fails in between -- and the operator reading the report has no
	// way to see that. Written last, the report exists exactly when the round completed.
	return o.writeReport(rep)
}

// writeReport persists the decision report, when a path is configured.
func (o *Onboarder) writeReport(rep *Report) error {
	if o.opts.ReportPath == "" {
		return nil
	}
	return writeJSONAtomic(o.opts.ReportPath, rep)
}

// run carries the intermediate state of one evaluation round.
type run struct {
	o   *Onboarder
	now time.Time

	rep *Report
	st  *State

	// prev is the previous document, the freeze target. May be nil (first run).
	prev *spec.Document

	// guardUnavailable means the CLB guard could not be read this round. Once true,
	// this round makes **no deletion decisions** -- see §9 "do not degrade when a
	// source is unavailable".
	guardUnavailable bool

	// rules is the set of domains on CLB rules. Names are kept as-is (may include
	// wildcards).
	rules map[string]bool

	// declarations are the successfully parsed declarations, sorted by hostname.
	declarations []*Declaration

	// reasons records why each expanded name is in or out of the final set.
	reasons map[string]string

	// eligible is the expanded name set that passed the allowlist and the guards.
	eligible map[string]bool

	// accepted records which declarations of this round contributed an eligible name.
	//
	// groupSettings aggregates profile/keyType/deploy per registered domain, and it must
	// only look at declarations that actually survived the guards: one excluded by guard 1
	// was excluded precisely because nothing serves it, so letting it dictate the group's
	// settings contradicts the decision the report just announced. That is not merely
	// cosmetic -- a single excluded declaration silently moved a served certificate onto a
	// different profile, and two excluded ones with different profiles froze the whole
	// round with "the desired state came out empty".
	accepted map[string]bool

	// certs are the certificates computed this round, sorted by certificate name.
	certs []config.Certificate
}

func (o *Onboarder) loadState() (*State, error) {
	if o.opts.StatePath == "" {
		return &State{AbsentSince: map[string]time.Time{}}, nil
	}
	return LoadState(o.opts.StatePath)
}

// loadPrevious reads the previous document.
//
// Not finding one is not an error: the first run has none.
//
// An existing document that cannot be loaded IS an error, and the round must stop. It used
// to log a warning and continue with r.prev == nil, which turned out to be destructive: the
// previous revision is the safety net for two decisions that can only remove names --
// overLimit and overSettingsConflict keep a group's old certificate and fall back to
// rejecting every one of its names only when there is something to keep. With no previous
// revision, a group that momentarily exceeds the SAN cap has all of its names rejected, the
// certificate leaves the written document, and wecert then treats it as an orphan that
// "will not be renewed and will expire". It does not self-heal either: the next round's
// previous revision is the document that already lost the certificate.
//
// Reaching that state needs an over-cap group AND an unloadable document (a group- or
// world-writable file after a careless rsync, a wrong owner after a one-off root run, a
// generatedAt skew after an NTP step), which is why it survived this long. The impact is
// live HTTPS loss, and the safe answer is available: refuse the round. Nothing is written,
// so the operator fixes the permissions and re-runs.
//
// This is the same call loadState makes for a corrupt state file, and for the same reason:
// continuing without the guard turns "conservative" into "aggressive" for deletions.
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
			r.freeze("guards.requireCLBRule is on but no CLB rule source is configured")
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
// Unparseable records do not enter the desired state, but they do leave a decision
// entry: silently dropping a declaration leaves a human doubting their sanity in
// front of the DNS console.
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
			r.reject(hostnameFromRecord(rec.Record), fmt.Sprintf("unparseable declaration: %v", err))
			continue
		}
		if rejected[d.Hostname] {
			// Once two records for one hostname disagreed, the hostname is poisoned
			// for the round: accepting a third record would let whoever writes last
			// silently win the conflict.
			r.reject(d.Hostname, fmt.Sprintf(
				"conflicting declarations for the same name: %s repeats a hostname already rejected for conflicting declarations",
				d.Record))
			continue
		}
		if prev, dup := byHost[d.Hostname]; dup {
			// Two declarations for the same hostname: allowed, but the metadata must
			// agree. Disagreement means someone wrote contradictory things in two zones,
			// and guessing which one is right would be wrong either way.
			if prev.Wildcard != d.Wildcard || prev.Profile != d.Profile ||
				prev.KeyType != d.KeyType || !sameBoolPtr(prev.Deploy, d.Deploy) {
				r.reject(d.Hostname, fmt.Sprintf(
					"conflicting declarations for the same name (%s and %s): they disagree on wildcard/profile/keytype/deploy",
					byHostRecord[d.Hostname], d.Record))
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
func (r *run) reject(hostname, reason string) {
	r.rep.Decisions = append(r.rep.Decisions, spec.Decision{
		Hostname: hostname,
		Included: false,
		Reason:   reason,
	})
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
		return record
	}
	return strings.TrimPrefix(full, DeclarationPrefix)
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
	for _, d := range r.rep.Decisions {
		if d.Hostname == name && !d.Included {
			return fmt.Sprintf("%s; the declaration is still there, so the name keeps its coverage "+
				"(removing coverage means removing the declaration)", d.Reason)
		}
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
	kept := r.rep.Decisions[:0]
	for _, d := range r.rep.Decisions {
		if d.Hostname == hostname && !d.Included {
			continue
		}
		kept = append(kept, d)
	}
	r.rep.Decisions = kept
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
func (r *run) build() {
	names := make([]string, 0, len(r.eligible))
	for n := range r.eligible {
		names = append(names, n)
	}
	sort.Strings(names)
	r.rep.Included = len(names)

	groups, err := group.GroupBy(names)
	if err != nil {
		// Reaching here means a name failed group.Normalize, although declarations were
		// validated long ago. The only possibility is a name left behind in state that
		// is no longer valid (rules tightened, say).
		r.freeze(fmt.Sprintf("cannot group the declared names: %v", err))
		return
	}

	for _, g := range groups {
		// The settings come first, because they decide the SAN cap.
		//
		// Cover used the configured default cap alone, so a group whose declarations ask for a
		// shorter profile (tlsserver / shortlived allow 25 identifiers) was split by the default
		// -- legal at 100 for classic -- and the resulting document was then rejected by
		// spec.WriteDocument on EVERY round for EVERY certificate: no document, no state, no
		// report, while Run still reported mode "written". Capping by the profile the group will
		// actually use routes that case through overLimit instead, which keeps the previous
		// revision for that certificate and says why.
		profile, keyType, deploy, err := r.groupSettings(g)
		if err != nil {
			r.overSettingsConflict(g, err)
			continue
		}

		cov, err := g.Cover(groupNameCap(r.o.opts.MaxNames, profile))
		if err != nil {
			if errors.Is(err, group.ErrTooManyNames) {
				r.overLimit(g, err)
				continue
			}
			r.freeze(fmt.Sprintf("certificate %q: %v", g.Name, err))
			return
		}

		r.certs = append(r.certs, config.Certificate{
			Name:    g.Name,
			Domains: cov.Domains,
			Profile: profile,
			KeyType: keyType,
			Deploy:  config.Deploy{Enabled: deploy},
		})

		for _, n := range append(append([]string(nil), g.Names...), g.Wildcards...) {
			reason := r.reasons[n]
			if coverer, ok := cov.Covered[n]; ok {
				// The wildcard note is ADDED to whatever reason the name already carries, not
				// written over it. Overwriting it hid the fact that a filter rejected this name
				// (the carried-by-declaration case): the report then said only "covered by the
				// wildcard", so the guard that is dropping it was invisible in the one artifact
				// an operator reads.
				note := fmt.Sprintf("covered by the declared wildcard %s, so it costs no extra issuance", coverer)
				if reason == "" {
					reason = note
				} else {
					reason += "; " + note
				}
				r.rep.CoveredByWildcard++
			} else if reason == "" {
				reason = "declared via a " + DeclarationPrefix + " TXT record"
				if r.o.opts.RequireRule && !group.IsWildcard(n) {
					reason += " and served by a CLB rule"
				}
			}
			r.rep.Decisions = append(r.rep.Decisions, spec.Decision{
				Hostname:    n,
				Included:    true,
				Reason:      reason,
				Certificate: g.Name,
			})
		}
	}
}

// overLimit handles a group that exceeds the SAN cap.
//
// The whole group must not be dropped: that makes wecert see a certificate vanish
// into thin air. The correct reaction is to keep the previous revision's certificate
// and shout the reason -- the fix (add a wildcard declaration, or move names to
// another group) can only be done by a human.
func (r *run) overLimit(g group.Group, cause error) {
	all := append(append([]string(nil), g.Names...), g.Wildcards...)

	if prev := r.previousCert(g.Name); prev != nil {
		r.certs = append(r.certs, *prev)
		for _, n := range all {
			r.rep.Decisions = append(r.rep.Decisions, spec.Decision{
				Hostname:    n,
				Included:    true,
				Reason:      fmt.Sprintf("kept at the previous revision: %v", cause),
				Certificate: g.Name,
			})
		}
		r.rep.CarriedForward += len(all)
		return
	}

	for _, n := range all {
		r.reject(n, fmt.Sprintf("cannot be expressed: %v", cause))
	}
}

func (r *run) previousCert(name string) *config.Certificate {
	if r.prev == nil {
		return nil
	}
	for i := range r.prev.Certificates {
		if r.prev.Certificates[i].Name == name {
			return &r.prev.Certificates[i]
		}
	}
	return nil
}

// groupNameCap is the SAN cap a group may use: the smaller of the configured onboarding cap and
// the cap of the profile the group will actually be issued with.
func groupNameCap(configured int, profile string) int {
	cap := configured
	if pm := config.ProfileMaxNames(profile); pm > 0 && (cap <= 0 || pm < cap) {
		cap = pm
	}
	return cap
}

// settingsStillApply reports whether a declaration a filter did not accept still contributes its
// profile / keyType / deploy settings.
//
// It does when the names it contributes are still covered this round: applyGrace carries a
// still-declared name whose filter rejected it, so the certificate keeps that name -- and it must
// also keep the settings that declaration asked for. Dropping them would rebuild the certificate
// from the onboarding defaults, which changes the document's revision, reissues the certificate,
// and can even turn deployment ON for a declaration that said deploy=0: the opposite of "the name
// keeps its coverage and nothing is reissued", and a second issuance on a guard wobble -- exactly
// what the carry exists to avoid.
func (r *run) settingsStillApply(d *Declaration) bool {
	for _, n := range d.Names() {
		if r.eligible[n] {
			return true
		}
	}
	return false
}

// groupSettings aggregates the metadata of the declarations in a group.
//
// Only declarations that survived the guards contribute: see run.accepted.
func (r *run) groupSettings(g group.Group) (profile, keyType string, deploy bool, err error) {
	profile, keyType, deploy = r.o.opts.Profile, r.o.opts.KeyType, r.o.opts.Deploy
	var profileSet, keyTypeSet, deploySet bool

	for _, d := range r.declarations {
		if !r.accepted[d.Hostname] && !r.settingsStillApply(d) {
			// Excluded this round (allowlist or guard 1) and NOT still covered: its settings
			// must not leak onto names it is not part of.
			continue
		}
		if group.RegisteredDomain(d.Hostname) != g.Registered {
			continue
		}
		if d.Profile != "" {
			if profileSet && profile != d.Profile {
				return "", "", false, fmt.Errorf("conflicting profile declarations %q and %q", profile, d.Profile)
			}
			profile = d.Profile
			profileSet = true
		}
		if d.KeyType != "" {
			if keyTypeSet && keyType != d.KeyType {
				return "", "", false, fmt.Errorf("conflicting keyType declarations %q and %q", keyType, d.KeyType)
			}
			keyType = d.KeyType
			keyTypeSet = true
		}
		if d.Deploy != nil {
			if deploySet && deploy != *d.Deploy {
				return "", "", false, fmt.Errorf("conflicting deploy declarations %t and %t", deploy, *d.Deploy)
			}
			deploy = *d.Deploy
			deploySet = true
		}
	}
	return profile, keyType, deploy, nil
}

func (r *run) overSettingsConflict(g group.Group, cause error) {
	if prev := r.previousCert(g.Name); prev != nil {
		r.certs = append(r.certs, *prev)
		for _, n := range append(append([]string(nil), g.Names...), g.Wildcards...) {
			r.rep.Decisions = append(r.rep.Decisions, spec.Decision{Hostname: n, Included: true, Certificate: g.Name, Reason: fmt.Sprintf("kept at the previous revision: %v", cause)})
		}
		r.rep.CarriedForward += len(g.Names) + len(g.Wildcards)
		return
	}
	for _, n := range append(append([]string(nil), g.Names...), g.Wildcards...) {
		r.reject(n, fmt.Sprintf("cannot choose group-level certificate settings: %v", cause))
	}
}

// budget is §5.4: the quota fuse.
//
// A domain-set change does **not** count as a renewal of the same name; it really
// spends "Certificates per Registered Domain" (50 / 7 days, shared across accounts).
// Half the allowance is kept in reserve, default budget 25/week; exceeding it freezes
// and alerts rather than gambling the user's quota away.
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

func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".onboard-report-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	// fsync before the rename, like the document writer and the state writer.
	//
	// Both of them do this; the report did not, so a crash (or a full disk losing the tail of the
	// page cache) could leave a renamed, truncated -- even zero-byte -- report behind after a round
	// that otherwise completed. The report is the artifact a human reads to find out what the round
	// decided, and "it exists exactly when the round completed" is the contract Commit documents.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	tmpName = ""
	return nil
}
