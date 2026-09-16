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
	// Empty means no persistence -- which downgrades the deletion grace period to
	// "recompute from scratch every run", so it never elapses. Suitable only for
	// one-off troubleshooting.
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

	// MaxNames is the per-certificate SAN cap. 0 means use the profile's own cap.
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

	// Force skips the abrupt-change fuse, the quota budget and the deletion grace
	// period, writing exactly what this round computed.
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

	Declared          int `json:"declared"`
	Included          int `json:"included"`
	CoveredByWildcard int `json:"coveredByWildcard"`
	CarriedForward    int `json:"carriedForward"`
	Certificates      int `json:"certificates"`

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

	r.loadPrevious()
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

// Commit persists: the desired-state document, the decision report, the onboarding
// state.
//
// When frozen it writes only the report -- the report is exactly what tells a human
// why nothing moved this round.
func (o *Onboarder) Commit(rep *Report) error {
	if o.opts.ReportPath != "" {
		if err := writeJSONAtomic(o.opts.ReportPath, rep); err != nil {
			return err
		}
	}
	if rep.Frozen() {
		// When frozen no state is touched: AbsentSince would advance, but this round
		// we do not know whether the names still exist; advancing it shortens the
		// grace period on noise.
		return nil
	}

	if err := spec.WriteDocument(o.opts.DocumentPath, rep.Document); err != nil {
		return err
	}
	if o.opts.StatePath != "" {
		if err := rep.State.Save(o.opts.StatePath); err != nil {
			return err
		}
	}
	return nil
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
// Not finding one is not an error: the first run has none. But if the file exists
// and cannot be parsed, the previous revision has already rotted, and that must be
// said out loud -- it means this round has no freeze target.
func (r *run) loadPrevious() {
	doc, err := spec.LoadDocument(r.o.opts.DocumentPath)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			return
		}
		r.o.log.Warn("previous desired-state document is unusable; there is no freeze target this round",
			"path", r.o.opts.DocumentPath, "err", err)
		return
	}
	r.prev = doc
	r.rep.PreviousRevision = doc.Revision
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
	if err != nil {
		// A broken guard is not "all rules are gone".
		//
		// §9 explicitly refuses "degrade to a single source when one is unavailable":
		// degradation makes safety vanish together with the source, exactly when it is
		// needed most. So the judgement always freezes -- no name is removed this
		// round, and the guard counts as satisfied (conservative direction: keep).
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

	for _, rec := range raw {
		d, err := ParseDeclaration(rec.Zone, rec.Record, rec.Values)
		if err != nil {
			r.reject(hostnameFromRecord(rec.Record), fmt.Sprintf("unparseable declaration: %v", err))
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
				delete(byHost, d.Hostname)
				delete(byHostRecord, d.Hostname)
				continue
			}
			continue
		}
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
// It compares the **declaration set itself**, not the result after guards and
// grouping. Because what it catches is "upstream returned incomplete data", whereas
// shrinking caused by guard filtering, the grace period or a grouping failure is our
// own, recorded decision.
//
// A normal decommission does not remove a third of the declarations. Losing a third
// at once is almost certainly an upstream fault (incomplete API response, changed
// permissions, zone read failure). Acting on that strips SANs in bulk. Freezing is
// safer than acting.
func (r *run) fuse() {
	if r.o.opts.Force {
		return
	}

	prev := r.st.LastNameSet()
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
	if ratio <= r.o.opts.DropThreshold {
		return
	}

	r.freeze(fmt.Sprintf(
		"the declared name set dropped from %d to %d (%.0f%%, threshold %.0f%%): "+
			"this is almost always an upstream failure rather than a real decommission, "+
			"so nothing was changed; pass -force if the drop is intentional",
		len(prev), len(now), ratio*100, r.o.opts.DropThreshold*100))
}

// resolve applies the allowlist, guard 1 and the deletion grace period to obtain
// the final set of names to cover.
func (r *run) resolve() {
	r.eligible = make(map[string]bool, len(r.declarations)*2)

	for _, d := range r.declarations {
		if !r.allowed(d.Hostname) {
			for _, n := range d.Names() {
				r.reject(n, fmt.Sprintf("registered domain %q is not in the allowlist",
					group.RegisteredDomain(d.Hostname)))
			}
			continue
		}

		// Guard 1 applies to concrete names only: a wildcard never appears as a
		// layer-7 rule domain, so demanding a rule for it would mean it never passes.
		if r.o.opts.RequireRule && !r.guardUnavailable && !r.rules[d.Hostname] {
			r.reject(d.Hostname, "no CLB rule serves this name (guard 1 not satisfied)")
			continue
		}

		for _, n := range d.Names() {
			r.eligible[n] = true
		}
	}

	// The abrupt-change fuse must run before eligible, hence its separate call right
	// after parse in Run. Here we only look at names "present last round, ineligible
	// now".
	r.applyGrace()
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

// referenced reports whether a name is still referenced by some CLB rule.
//
// With the guard unavailable it always counts as referenced: the conservative
// direction is to keep, not to delete.
func (r *run) referenced(name string) bool {
	if r.guardUnavailable || r.o.src.Rules == nil {
		return true
	}
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
		cov, err := g.Cover(r.o.opts.MaxNames)
		if err != nil {
			if errors.Is(err, group.ErrTooManyNames) {
				r.overLimit(g, err)
				continue
			}
			r.freeze(fmt.Sprintf("certificate %q: %v", g.Name, err))
			return
		}

		// Use the declared metadata when the whole group agrees on it, otherwise keep
		// the default and leave a record. Letting one subdomain's declaration quietly
		// retune the whole certificate is the kind of change nobody can explain later.
		profile, keyType, deploy := r.groupSettings(g)

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
				reason = fmt.Sprintf("covered by the declared wildcard %s, so it costs no extra issuance", coverer)
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

// groupSettings aggregates the metadata of the declarations in a group.
func (r *run) groupSettings(g group.Group) (profile, keyType string, deploy bool) {
	profile, keyType, deploy = r.o.opts.Profile, r.o.opts.KeyType, r.o.opts.Deploy

	for _, d := range r.declarations {
		if group.RegisteredDomain(d.Hostname) != g.Registered {
			continue
		}
		if d.Profile != "" {
			profile = d.Profile
		}
		if d.KeyType != "" {
			keyType = d.KeyType
		}
		if d.Deploy != nil {
			deploy = *d.Deploy
		}
	}
	return profile, keyType, deploy
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

	changed := rev != r.st.LastRevision
	if !changed {
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

// assemble builds the document and state.
func (r *run) assemble() {
	names := make([]string, 0, len(r.eligible))
	for n := range r.eligible {
		names = append(names, n)
	}
	sort.Strings(names)

	r.rep.Certificates = len(r.certs)
	r.st.SetLastNames(names)
	r.st.LastRevision = r.rep.Revision
	r.st.UpdatedAt = r.now

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
