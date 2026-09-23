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
	"log/slog"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
)

// Split out so one concern lives in one file. Same package.

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
type Onboarder struct {
	src  Sources
	opts Options
	log  *slog.Logger
}

// New constructs an onboarder.
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
		excludedIdx: map[string]int{},
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

	// excludedIdx maps a hostname to the index of its exclusion in rep.Decisions.
	//
	// The report carries one verdict per hostname, which makes reject/unreject "find
	// the entry for this name" operations. Scanning the slice for each of them made a
	// round quadratic in the number of names -- reject runs once per filtered name and
	// include calls unreject for every covered one.
	excludedIdx map[string]int

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
