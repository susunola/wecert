package onboarding

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
)

// ── test doubles ───────────────────────────────────────────────────────────

type fakeDeclarations struct {
	raw []RawDeclaration
	err error
}

func (f *fakeDeclarations) ListDeclarations(context.Context) ([]RawDeclaration, error) {
	return f.raw, f.err
}

type fakeRules struct {
	domains []string
	err     error
}

func (f *fakeRules) ListRuleDomains(context.Context) ([]string, error) {
	return f.domains, f.err
}

// clock lets the grace period and quota budget be tested without sleeping.
type clock struct{ t time.Time }

func newClock() *clock                   { return &clock{t: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)} }
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func decl(host string, values ...string) RawDeclaration {
	return RawDeclaration{Zone: "example.com", Record: DeclarationPrefix + host, Values: values}
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type harness struct {
	ob    *Onboarder
	decls *fakeDeclarations
	rules *fakeRules
	clock *clock
	opts  Options
}

func newHarness(t *testing.T, opts Options) *harness {
	t.Helper()

	dir := t.TempDir()
	if opts.DocumentPath == "" {
		opts.DocumentPath = filepath.Join(dir, "desired-state.yaml")
	}
	if opts.StatePath == "" {
		opts.StatePath = filepath.Join(dir, "onboard-state.json")
	}
	if opts.ReportPath == "" {
		opts.ReportPath = filepath.Join(dir, "report.json")
	}
	opts.Generator = "wecert-onboard/test"

	c := newClock()
	if opts.Now == nil {
		opts.Now = c.now
	}

	h := &harness{
		decls: &fakeDeclarations{},
		rules: &fakeRules{},
		clock: c,
		opts:  opts,
	}

	ob, err := New(Sources{Declarations: h.decls, Rules: h.rules}, opts, testLogger())
	if err != nil {
		t.Fatalf("constructing the onboarder failed: %v", err)
	}
	h.ob = ob
	return h
}

// run runs one round, persists it, and returns the report.
func (h *harness) run(t *testing.T) *Report {
	t.Helper()
	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if err := h.ob.Commit(rep); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	return rep
}

// document reads back the persisted document, to verify "nothing bad was written".
func (h *harness) document(t *testing.T) *spec.Document {
	t.Helper()
	doc, err := spec.LoadDocument(h.opts.DocumentPath)
	if err != nil {
		t.Fatalf("reading the document back failed: %v", err)
	}
	return doc
}

func (h *harness) domains(t *testing.T) []string {
	t.Helper()
	doc := h.document(t)
	if len(doc.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d: %+v", len(doc.Certificates), doc.Certificates)
	}
	return doc.Certificates[0].Domains
}

func decisionFor(rep *Report, hostname string) (spec.Decision, bool) {
	for _, d := range rep.Decisions {
		if d.Hostname == hostname {
			return d, true
		}
	}
	return spec.Decision{}, false
}

// ── declaration parsing ────────────────────────────────────────────────────

func TestParseDeclaration(t *testing.T) {
	d, err := ParseDeclaration("example.com", "_wecert.example.com",
		[]string{"v=wecert1, wildcard=1, profile=tlsserver, deploy=0"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname != "example.com" {
		t.Errorf("Hostname = %q", d.Hostname)
	}
	if !d.Wildcard {
		t.Error("wildcard=1 must take effect")
	}
	if d.Profile != "tlsserver" {
		t.Errorf("Profile = %q", d.Profile)
	}
	if d.Deploy == nil || *d.Deploy {
		t.Errorf("deploy=0 must take effect, got %v", d.Deploy)
	}
	if got := d.Names(); len(got) != 2 || got[1] != "*.example.com" {
		t.Errorf("Names() = %v, must expand the wildcard", got)
	}
}

// A bare record is itself a declaration; this is the most common form.
func TestParseDeclarationAcceptsABareRecord(t *testing.T) {
	d, err := ParseDeclaration("example.com", "_wecert.api.example.com", []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname != "api.example.com" || d.Wildcard {
		t.Errorf("a bare record must declare only itself: %+v", d)
	}
}

// A misspelled key must be an error, not ignored.
//
// Silently ignoring `wildard=1` yields "the wildcard was declared but never took
// effect", while the human keeps believing it did -- a silent divergence like that
// costs far more than a clear error.
func TestParseDeclarationRejectsUnknownKeys(t *testing.T) {
	_, err := ParseDeclaration("example.com", "_wecert.example.com", []string{"wildard=1"})
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("an unknown key must fail, got %v", err)
	}
}

func TestParseDeclarationRejectsBadVersion(t *testing.T) {
	if _, err := ParseDeclaration("example.com", "_wecert.example.com", []string{"v=wecert9"}); err == nil {
		t.Fatal("an unknown version must fail")
	}
}

func TestParseDeclarationRejectsConflictingKeys(t *testing.T) {
	_, err := ParseDeclaration("example.com", "_wecert.example.com",
		[]string{"wildcard=1", "wildcard=0"})
	if err == nil {
		t.Fatal("the same key given contradictory values must fail")
	}
}

// ── §5.1 source failure ≠ name gone ────────────────────────────────────────

// This is the one place in the entire design that can cause a disaster.
//
// A DNS enumeration API blip → returns empty → if read as "all these names are
// gone" → the desired state has no domains → a certificate with no domains is
// re-issued → live handshakes fail immediately. That is far worse than not
// issuing, so the correct reaction is to freeze.
func TestSourceFailureFreezesInsteadOfEmptying(t *testing.T) {
	h := newHarness(t, Options{})
	h.decls.raw = []RawDeclaration{decl("example.com")}
	h.rules.domains = []string{"example.com"}

	if rep := h.run(t); rep.Frozen() {
		t.Fatalf("the first round must not freeze: %v", rep.FreezeReasons)
	}
	before := h.domains(t)

	// The source dies.
	h.decls.err = errors.New("dnspod api timeout")

	rep := h.run(t)
	if !rep.Frozen() {
		t.Fatal("a source failure must freeze")
	}
	if len(rep.FreezeReasons) == 0 {
		t.Error("a freeze must carry a reason")
	}

	// The document must be unchanged character for character -- above all not emptied.
	after := h.domains(t)
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("the desired state changed while frozen: %v -> %v", before, after)
	}
}

// A freeze must not advance the deletion grace clock.
//
// AbsentSince is the ledger of "how long this name has been confirmed absent", but
// on a frozen round we have no idea whether the name still exists. Advancing it uses
// noise to shorten the grace period.
func TestSourceFailureDoesNotAdvanceTheGraceClock(t *testing.T) {
	h := newHarness(t, Options{DropThreshold: 0.9})
	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// b's declaration disappears while the source is healthy -- AbsentSince should be recorded.
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.run(t)

	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	since, ok := st.AbsentSince["b.example.com"]
	if !ok {
		t.Fatal("b.example.com must have its absence time recorded")
	}

	// More rounds pass, all with a failing source: AbsentSince must not move forward.
	h.clock.advance(time.Hour)
	h.decls.err = errors.New("boom")
	h.run(t)

	after, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.AbsentSince["b.example.com"]; !got.Equal(since) {
		t.Errorf("a freeze must not advance the absence time: %v -> %v", since, got)
	}
}

// ── §5.2 abrupt desired-state fuse ─────────────────────────────────────────

// A DropThreshold at or above 1 can never be exceeded, so the fuse would never
// fire. The config layer rejects it, but the CLI -drop-threshold flag reaches
// Options directly -- the constructor must hold the same line.
func TestDropThresholdAtOrAboveOneIsRejected(t *testing.T) {
	// New validates several required paths before it reaches the policy checks, so
	// they all have to be filled in. Otherwise every case below would fail for an
	// unrelated reason and the test would pass without the check it exists to pin.
	base := func() Options {
		dir := t.TempDir()
		return Options{
			DocumentPath: filepath.Join(dir, "desired-state.yaml"),
			StatePath:    filepath.Join(dir, "onboard-state.json"),
			ReportPath:   filepath.Join(dir, "report.json"),
			Generator:    "wecert-onboard/test",
		}
	}
	src := Sources{Declarations: &fakeDeclarations{}, Rules: &fakeRules{}}

	// The fuse compares a loss ratio that can never exceed 1, so a threshold at or
	// above 1 -- or a percentage written as `30` -- can never be exceeded. NaN is in
	// the list because every comparison against it is false, so it satisfies both
	// this bound and the `<= 0` default above.
	for _, v := range []float64{30, 1.5, 1, math.NaN()} {
		opts := base()
		opts.DropThreshold = v
		_, err := New(src, opts, testLogger())
		if err == nil {
			t.Errorf("New accepted DropThreshold=%v; the abrupt-change fuse could never fire", v)
			continue
		}
		if !strings.Contains(err.Error(), "DropThreshold") {
			t.Errorf("New rejected DropThreshold=%v for the wrong reason: %v", v, err)
		}
	}

	// 0 means "use the default", and anything in (0,1) is a real threshold.
	for _, v := range []float64{0, 0.3, 0.99} {
		opts := base()
		opts.DropThreshold = v
		if _, err := New(src, opts, testLogger()); err != nil {
			t.Errorf("New rejected a valid DropThreshold=%v: %v", v, err)
		}
	}
}

// A normal decommission does not remove a third of the set. Losing a third at once
// is almost certainly an upstream fault (incomplete API response, changed
// permissions, zone read failure). Acting on it strips SANs in bulk.
func TestAbruptDropFreezes(t *testing.T) {
	h := newHarness(t, Options{})

	var raw []RawDeclaration
	var rules []string
	for _, n := range []string{"a", "b", "c", "d"} {
		raw = append(raw, decl(n+".example.com"))
		rules = append(rules, n+".example.com")
	}
	h.decls.raw, h.rules.domains = raw, rules
	h.run(t)

	// One of four remains: a 75% drop, far above the 30% threshold.
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}

	rep := h.run(t)
	if !rep.Frozen() {
		t.Fatal("a drop above the threshold must freeze")
	}
	if !strings.Contains(strings.Join(rep.FreezeReasons, " "), "force") {
		t.Error("the freeze reason must tell a human how to confirm the drop was intentional")
	}
}

// A small drop must not trip the fuse, or normal decommissions could never proceed.
func TestSmallDropDoesNotFreeze(t *testing.T) {
	h := newHarness(t, Options{})

	var raw []RawDeclaration
	var rules []string
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		raw = append(raw, decl(n+".example.com"))
		rules = append(rules, n+".example.com")
	}
	h.decls.raw, h.rules.domains = raw, rules
	h.run(t)

	// One gone = 10%, below 30%.
	h.decls.raw = raw[:9]
	h.rules.domains = rules[:9]
	h.clock.advance(48 * time.Hour) // past the grace period

	if rep := h.run(t); rep.Frozen() {
		t.Fatalf("a 10%% drop must not freeze: %v", rep.FreezeReasons)
	}
}

// ── §5.3 deletion an order of magnitude more conservative than addition ────

// A vanished declaration must not immediately strip the domain from the certificate.
//
// A two-source design naturally makes state flap: a DNS query blips → delete at
// once → re-issue → DNS recovers → re-issue again. One rollout triggers three
// issuances and burns quota for nothing.
func TestRemovalWaitsForTheGracePeriod(t *testing.T) {
	// Raise the threshold to rule out the abrupt-change fuse and observe the grace
	// period alone.
	h := newHarness(t, Options{DropThreshold: 0.9})

	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// b's declaration is gone and no rule serves it any more, but the source is healthy.
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("must not freeze: %v", rep.FreezeReasons)
	}
	domains := h.domains(t)
	if len(domains) != 2 {
		t.Fatalf("b must stay during the grace period, got %v", domains)
	}
	d, ok := decisionFor(rep, "b.example.com")
	if !ok || !d.Included {
		t.Fatalf("b must be marked as kept: %+v", d)
	}
	if !strings.Contains(d.Reason, "grace period") {
		t.Errorf("the reason must mention the grace period, got %q", d.Reason)
	}

	// Only past the grace period is it actually removed.
	h.clock.advance(25 * time.Hour)
	h.run(t)

	if got := h.domains(t); len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("b must be removed after the grace period, got %v", got)
	}
}

// The grace clock must reset once a name comes back.
//
// Otherwise one blip carries the absence time forward forever and the grace period
// is a sham.
func TestReappearingNameResetsTheGraceClock(t *testing.T) {
	h := newHarness(t, Options{DropThreshold: 0.9})

	two := []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.decls.raw = two
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.run(t)

	h.clock.advance(time.Hour)
	h.decls.raw = two
	h.run(t)

	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, still := st.AbsentSince["b.example.com"]; still {
		t.Error("the absence marker must be cleared once the name is back")
	}
}

// A name still referenced by a CLB rule must not be torn down just because its
// declaration is gone -- that would cut live traffic immediately.
func TestRemovalIsBlockedWhileACLBRuleStillReferencesIt(t *testing.T) {
	h := newHarness(t, Options{DropThreshold: 0.9})

	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// The declaration is gone but the rule remains -- meaning traffic remains.
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.run(t) // this round records b's absence time for the first time

	// Past the grace period: only now does the reference check apply instead of the
	// grace branch.
	h.clock.advance(72 * time.Hour)

	rep := h.run(t)
	d, ok := decisionFor(rep, "b.example.com")
	if !ok || !d.Included {
		t.Fatalf("a rule still references it, so b must be kept: %+v", d)
	}
	if !strings.Contains(d.Reason, "CLB rule still references") {
		t.Errorf("the reason must say the reference check blocked it, got %q", d.Reason)
	}
	if got := h.domains(t); len(got) != 2 {
		t.Fatalf("b must still be in the certificate, got %v", got)
	}
}

// ── §5.5 explicit authorization and guards ─────────────────────────────────

// A declaration only takes effect when a CLB rule backs it (guard 1).
//
// It blocks two real problems: a declaration written before its rule exists (causing
// a useless issuance), and a misspelled domain no rule serves at all.
func TestGuardRequiresACLBRule(t *testing.T) {
	h := newHarness(t, Options{RequireRule: true})

	h.decls.raw = []RawDeclaration{decl("served.example.com"), decl("typo.example.com")}
	h.rules.domains = []string{"served.example.com"}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("must not freeze: %v", rep.FreezeReasons)
	}

	if got := h.domains(t); len(got) != 1 || got[0] != "served.example.com" {
		t.Fatalf("only names served by a rule may enter the certificate, got %v", got)
	}
	d, ok := decisionFor(rep, "typo.example.com")
	if !ok || d.Included {
		t.Fatalf("typo.example.com must be excluded: %+v", d)
	}
	if !strings.Contains(d.Reason, "no CLB rule") {
		t.Errorf("the reason must say the guard was not satisfied, got %q", d.Reason)
	}
}

// With the guard unreadable, no deletion decisions are made at all.
//
// §9 explicitly refuses "degrade to a single source when one is unavailable":
// degradation makes safety vanish together with the source, exactly when it is
// needed most.
func TestUnavailableGuardRemovesNothing(t *testing.T) {
	h := newHarness(t, Options{RequireRule: true, DropThreshold: 0.9})

	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// The rules API is down and b's declaration vanished too. Now we cannot tell
	// whether b is still served.
	h.rules.err = errors.New("clb api unreachable")
	h.decls.raw = []RawDeclaration{decl("a.example.com")}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("an unavailable guard must not freeze everything: %v", rep.FreezeReasons)
	}
	if !rep.GuardUnavailable {
		t.Error("the report must flag that the guard was unavailable this round")
	}
	if got := h.domains(t); len(got) != 2 {
		t.Fatalf("no name may be deleted while the guard is unavailable, got %v", got)
	}
}

// The allowlist is the §5.5 railing: sources only provide clues, authorization must
// be an explicit act.
func TestAllowlistLimitsWhichRegisteredDomainsMayBeIssuedFor(t *testing.T) {
	h := newHarness(t, Options{Allowlist: []string{"allowed.example"}})

	h.decls.raw = []RawDeclaration{
		{Zone: "allowed.example", Record: DeclarationPrefix + "allowed.example", Values: []string{""}},
		{Zone: "other.example", Record: DeclarationPrefix + "other.example", Values: []string{""}},
	}
	h.rules.domains = []string{"allowed.example", "other.example"}

	rep := h.run(t)
	if got := h.domains(t); len(got) != 1 || got[0] != "allowed.example" {
		t.Fatalf("a registered domain outside the allowlist must not enter the certificate, got %v", got)
	}
	if d, ok := decisionFor(rep, "other.example"); !ok || !strings.Contains(d.Reason, "allowlist") {
		t.Fatalf("other.example must be excluded by the allowlist: %+v", d)
	}
}

// The allowlist is matched with a binary search, so it has to be sorted -- and
// normalising each entry to its registered domain can *reorder* it, so sorting the
// caller's input is not enough and sorting must happen inside New.
//
// Unsorted, the binary search misses entries that really are on the allowlist, and
// the names are rejected with the misleading reason `registered domain "x" is not
// in the allowlist` -- naming a domain that is in fact listed.
func TestAllowlistIsSortedAfterNormalization(t *testing.T) {
	// Normalising these two gives ["example.com", "b.co.uk"], which is not in
	// ascending order even though the input was.
	h := newHarness(t, Options{Allowlist: []string{"a.example.com", "b.co.uk"}})

	h.decls.raw = []RawDeclaration{
		{Zone: "example.com", Record: DeclarationPrefix + "example.com", Values: []string{""}},
		{Zone: "b.co.uk", Record: DeclarationPrefix + "b.co.uk", Values: []string{""}},
	}
	h.rules.domains = []string{"example.com", "b.co.uk"}

	// Assert on the decisions before reading the document, so a regression fails
	// with the real reason instead of "the document does not exist".
	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, want := range []string{"example.com", "b.co.uk"} {
		if d, ok := decisionFor(rep, want); ok && !d.Included {
			t.Errorf("%s is on the allowlist but was excluded: %s", want, d.Reason)
		}
	}

	if err := h.ob.Commit(rep); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Two registered domains means two certificates, so collect across all of them.
	var got []string
	for _, c := range h.document(t).Certificates {
		got = append(got, c.Domains...)
	}
	for _, want := range []string{"example.com", "b.co.uk"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s is on the allowlist but is not in any certificate: %v", want, got)
		}
	}
}

// ── §6.1 wildcard-first ────────────────────────────────────────────────────

// This is the most valuable rule in the whole design: once *.example.com is
// declared, adding subdomains leaves the SAN set untouched, i.e. **0 issuances**.
//
// Without it, bulk-importing 50 subdomains is 50 re-issues -- straight into
// "50 certificates per registered domain per 7 days".
func TestWildcardCoverageMakesNewSubdomainsFree(t *testing.T) {
	h := newHarness(t, Options{})

	h.decls.raw = []RawDeclaration{
		decl("example.com", "wildcard=1"),
		decl("api.example.com"),
		decl("www.example.com"),
	}
	h.rules.domains = []string{"example.com", "api.example.com", "www.example.com"}

	first := h.run(t)
	if first.Frozen() {
		t.Fatalf("must not freeze: %v", first.FreezeReasons)
	}

	domains := h.domains(t)
	if len(domains) != 2 || domains[0] != "example.com" || domains[1] != "*.example.com" {
		t.Fatalf("the SAN set must be [example.com *.example.com], got %v", domains)
	}
	if first.CoveredByWildcard != 2 {
		t.Errorf("2 names must be covered by the wildcard, got %d", first.CoveredByWildcard)
	}

	// Now add a new subdomain, with its rule in place too.
	h.decls.raw = append(h.decls.raw, decl("foo.example.com"))
	h.rules.domains = append(h.rules.domains, "foo.example.com")

	second := h.run(t)
	if second.Mode != ModeUnchanged {
		t.Fatalf("the new subdomain is covered by the wildcard, so the desired state must not change, got %s (rev %s -> %s)",
			second.Mode, second.PreviousRevision, second.Revision)
	}
	if got := h.domains(t); len(got) != 2 {
		t.Fatalf("the SAN set must not grow from adding a subdomain, got %v", got)
	}
	if d, ok := decisionFor(second, "foo.example.com"); !ok || !strings.Contains(d.Reason, "wildcard") {
		t.Fatalf("the new subdomain must be explained as \"covered by the wildcard\": %+v", d)
	}
}

// ── §5.4 quota fuse ────────────────────────────────────────────────────────

func TestChangeBudgetFreezes(t *testing.T) {
	h := newHarness(t, Options{Budget: 1})

	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}
	h.run(t)

	// The second set change exhausts a budget of just 1.
	h.decls.raw = append(h.decls.raw, decl("b.example.com"))
	h.rules.domains = append(h.rules.domains, "b.example.com")

	rep := h.run(t)
	if !rep.Frozen() {
		t.Fatal("an exhausted budget must freeze")
	}
	if !strings.Contains(strings.Join(rep.FreezeReasons, " "), "budget") {
		t.Errorf("the reason must say the budget is exhausted: %v", rep.FreezeReasons)
	}
}

// ── empty desired state ────────────────────────────────────────────────────

// A "legitimately empty" file and a "generation failed, hence empty" file look
// identical, and writing the latter strips every domain from every certificate.
func TestEmptyDesiredStateIsRefused(t *testing.T) {
	h := newHarness(t, Options{})

	rep := h.run(t)
	if !rep.Frozen() {
		t.Fatal("an empty desired state must be refused")
	}
	if !strings.Contains(strings.Join(rep.FreezeReasons, " "), "empty") {
		t.Errorf("the reason must say the desired state is empty: %v", rep.FreezeReasons)
	}
}

// ── idempotence ────────────────────────────────────────────────────────────

// Run the same input twice and the second round's fingerprint must match the
// previous one -- otherwise every generated document diffs all over and
// reviewability drops to zero.
func TestSecondRunIsUnchanged(t *testing.T) {
	h := newHarness(t, Options{})
	h.decls.raw = []RawDeclaration{decl("example.com", "wildcard=1"), decl("api.example.com")}
	h.rules.domains = []string{"example.com", "api.example.com"}

	first := h.run(t)
	second := h.run(t)

	if second.Mode != ModeUnchanged {
		t.Fatalf("the second round must be unchanged, got %s", second.Mode)
	}
	if first.Revision != second.Revision {
		t.Errorf("the fingerprint must not change: %s vs %s", first.Revision, second.Revision)
	}
}

// One invalid declaration must not drag down the whole round: otherwise a single
// typo stops every certificate from updating.
func TestOneBadDeclarationDoesNotFreezeEverything(t *testing.T) {
	h := newHarness(t, Options{})

	h.decls.raw = []RawDeclaration{
		decl("good.example.com"),
		decl("bad.example.com", "wildard=1"), // misspelled key
	}
	h.rules.domains = []string{"good.example.com", "bad.example.com"}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("one bad declaration must not freeze the whole round: %v", rep.FreezeReasons)
	}
	if got := h.domains(t); len(got) != 1 || got[0] != "good.example.com" {
		t.Fatalf("the good declaration must still take effect, got %v", got)
	}
	if d, ok := decisionFor(rep, "bad.example.com"); !ok || d.Included {
		t.Fatalf("the bad declaration must be excluded with a reason: %+v", d)
	}
}

// When declarations in a group disagree on metadata, the default wins -- letting one
// subdomain's declaration quietly retune the whole certificate is the kind of change
// nobody can explain afterwards.
func TestGroupSettingsComeFromDeclarations(t *testing.T) {
	h := newHarness(t, Options{Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256})

	h.decls.raw = []RawDeclaration{decl("example.com", "profile=tlsserver, keytype=ecdsa-p384")}
	h.rules.domains = []string{"example.com"}
	h.run(t)

	c := h.document(t).Certificates[0]
	if c.Profile != config.ProfileTLSServer {
		t.Errorf("profile must come from the declaration, got %q", c.Profile)
	}
	if c.KeyType != config.KeyTypeECDSAP384 {
		t.Errorf("keyType must come from the declaration, got %q", c.KeyType)
	}
}

// Guard 1 must accept a name that a wildcard rule domain serves.
//
// CLB layer-7 rules support `*.example.com` as a rule domain, and the deletion-side
// check (referenced) already understood that -- while guard 1 did a flat map lookup.
// So one rule could be simultaneously "not serving" a name (rejecting the
// declaration, and freezing the round when it was the only one) and "still
// referencing" it (blocking deletion).
func TestGuardOneAcceptsANameServedByAWildcardRule(t *testing.T) {
	h := newHarness(t, Options{RequireRule: true})

	h.decls.raw = []RawDeclaration{
		{Zone: "example.com", Record: DeclarationPrefix + "www.example.com", Values: []string{""}},
	}
	h.rules.domains = []string{"*.example.com"}

	rep := h.run(t)

	if d, ok := decisionFor(rep, "www.example.com"); ok && !d.Included {
		t.Fatalf("www.example.com is served by the *.example.com rule but was rejected: %s", d.Reason)
	}
	if got := h.domains(t); len(got) != 1 || got[0] != "www.example.com" {
		t.Fatalf("domain set = %v, want [www.example.com]", got)
	}
}

func TestGroupSettingsConflictKeepsPreviousCertificate(t *testing.T) {
	h := newHarness(t, Options{Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256})
	h.rules.domains = []string{"api.example.com", "www.example.com"}
	h.decls.raw = []RawDeclaration{decl("api.example.com", "profile=tlsserver"), decl("www.example.com", "profile=tlsserver")}
	h.run(t)
	before := h.document(t)
	h.decls.raw = []RawDeclaration{decl("api.example.com", "profile=tlsserver"), decl("www.example.com", "profile=classic")}
	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("a group settings conflict should keep only that group, not freeze unrelated work: %v", rep.FreezeReasons)
	}
	after := h.document(t)
	if after.Revision != before.Revision || after.Certificates[0].Profile != config.ProfileTLSServer {
		t.Fatalf("conflicting group settings must keep the previous certificate: before=%+v after=%+v", before.Certificates, after.Certificates)
	}
}

// Regression: the fuse used to compare against the *covered* set (LastNames),
// which includes grace-carried names. A staged decommission (10 -> 7 -> 6
// declarations) then counted its own carries as still-declared: the second step
// re-tripped the fuse, MarkAbsent never ran again, and the round wedged into a
// self-sustaining freeze. The baseline must be the pure declaration set.
func TestStagedDecommissionDoesNotWedgeTheFuse(t *testing.T) {
	h := newHarness(t, Options{}) // default threshold 0.30, grace 24h

	names := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	set := func(prefixes []string) {
		h.decls.raw = nil
		h.rules.domains = nil
		for _, n := range prefixes {
			h.decls.raw = append(h.decls.raw, decl(n+".example.com"))
			h.rules.domains = append(h.rules.domains, n+".example.com")
		}
	}

	set(names)
	h.run(t)

	// Step 1: 10 -> 7. Exactly 30% lost -- at the threshold, not above it -- so it
	// must pass; the grace period then keeps the covered set at 10 names.
	set(names[:7])
	if rep := h.run(t); rep.Frozen() {
		t.Fatalf("a 30%% drop is at the threshold, not above it: %v", rep.FreezeReasons)
	}

	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	absentSince := map[string]time.Time{}
	for _, n := range []string{"h", "i", "j"} {
		since, ok := st.AbsentSince[n+".example.com"]
		if !ok {
			t.Fatalf("%s.example.com must be marked absent after step 1", n)
		}
		absentSince[n] = since
	}
	if got := len(st.LastDeclared); got != 7 {
		t.Fatalf("the declaration baseline must be 7 after step 1, got %d", got)
	}
	if got := len(st.LastNames); got != 10 {
		t.Fatalf("the covered set must still be 10 (grace carries), got %d", got)
	}

	// Step 2: 7 -> 6. Against the covered set this would look like a 40% drop and
	// freeze forever; against the declaration baseline it is 1 of 7.
	h.clock.advance(time.Hour)
	set(names[:6])
	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("the staged decommission wedged the fuse: %v", rep.FreezeReasons)
	}
	if got := len(h.domains(t)); got != 10 {
		t.Fatalf("everything stays covered inside the grace period, got %d names", got)
	}

	// The point of the whole exercise: the absence ledger kept running, and the
	// step-1 timestamps were not reset.
	st, err = LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	for n, since := range absentSince {
		if got := st.AbsentSince[n+".example.com"]; !got.Equal(since) {
			t.Errorf("%s.example.com's absence time must not reset: %v -> %v", n, since, got)
		}
	}
	if _, ok := st.AbsentSince["g.example.com"]; !ok {
		t.Error("g.example.com must be marked absent after step 2")
	}
}

// State files written before LastDeclared existed have only the covered set.
// That set must serve as the fuse's baseline for exactly one round -- a big
// drop must still freeze -- rather than the fuse going quiet until the next
// successful write.
func TestFuseFallsBackToLastNamesBeforeLastDeclaredExists(t *testing.T) {
	h := newHarness(t, Options{})

	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		h.decls.raw = append(h.decls.raw, decl(n+".example.com"))
		h.rules.domains = append(h.rules.domains, n+".example.com")
	}
	h.run(t)

	// Simulate a pre-upgrade state file: covered set present, LastDeclared absent.
	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	st.LastDeclared = nil
	if err := st.Save(h.opts.StatePath); err != nil {
		t.Fatal(err)
	}

	// Losing 5 of 10 is far above the threshold and must freeze even without a
	// LastDeclared baseline.
	h.decls.raw = h.decls.raw[:5]
	h.rules.domains = h.rules.domains[:5]
	if rep := h.run(t); !rep.Frozen() {
		t.Fatal("without LastDeclared the fuse must fall back to the covered set, not go quiet")
	}
}

// Once two records for one hostname disagree, the hostname is out for the
// round. A third record must not resurrect it as a fresh first-seen -- that
// would let whoever writes last silently win the conflict.
func TestThirdDeclarationForAConflictedHostnameIsRejectedToo(t *testing.T) {
	h := newHarness(t, Options{})

	h.decls.raw = []RawDeclaration{
		decl("ok.example.com"),
		decl("fight.example.com", "profile=classic"),
		decl("fight.example.com", "profile=tlsserver"),
		// Agrees with the first record; still must not be accepted.
		decl("fight.example.com", "profile=classic"),
	}
	h.rules.domains = []string{"ok.example.com", "fight.example.com"}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("a conflicted hostname must not freeze the round: %v", rep.FreezeReasons)
	}
	if got := h.domains(t); len(got) != 1 || got[0] != "ok.example.com" {
		t.Fatalf("the conflicted hostname must stay out, got %v", got)
	}
	rejections := 0
	for _, d := range rep.Decisions {
		if d.Hostname == "fight.example.com" && !d.Included &&
			strings.Contains(d.Reason, "conflicting declarations") {
			rejections++
		}
	}
	if rejections != 2 {
		t.Errorf("both the conflict and the later repeat must be rejected, got %d rejections in %+v",
			rejections, rep.Decisions)
	}
}

// Commit writes the document before the state. If the state save fails, the
// document on disk already carries the new revision while the state still holds
// the old one. The retry must recognise the document's revision as its own --
// otherwise every failed save double-counts the budget and restarts grace
// clocks.
func TestCommitStateSaveFailureDoesNotDoubleCountBudget(t *testing.T) {
	stateDir := t.TempDir()
	h := newHarness(t, Options{StatePath: filepath.Join(stateDir, "onboard-state.json")})

	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}
	h.run(t)

	// Add a name, then make the state save fail while the document write succeeds.
	h.decls.raw = append(h.decls.raw, decl("b.example.com"))
	h.rules.domains = append(h.rules.domains, "b.example.com")
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) })

	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if rep.Frozen() {
		t.Fatalf("must not freeze: %v", rep.FreezeReasons)
	}
	if err := h.ob.Commit(rep); err == nil {
		t.Fatal("the state save must fail in an unwritable directory")
	}

	// Retry with the same input: the computed revision matches the document on
	// disk, so the round is unchanged -- no new budget entry.
	rep, err = h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if rep.Mode != ModeUnchanged {
		t.Errorf("the retry must see the document's revision as its own, got mode %s", rep.Mode)
	}

	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(st.Changes); got != 1 {
		t.Errorf("the failed save must not double-count the budget: %d changes recorded, want 1", got)
	}
	if got := h.domains(t); len(got) != 2 {
		t.Errorf("the document written before the failure must still cover both names, got %v", got)
	}
}

// With no CLB rule source configured the reference check cannot run at all, so
// nothing is ever deleted. That is the safe direction -- but the carry reason
// must say the check could not run, not claim a rule still references the name.
func TestNilRuleSourceCarriesWithAnHonestReason(t *testing.T) {
	var logBuf bytes.Buffer
	dir := t.TempDir()
	c := newClock()
	decls := &fakeDeclarations{}
	ob, err := New(Sources{Declarations: decls}, Options{
		DocumentPath:  filepath.Join(dir, "desired-state.yaml"),
		StatePath:     filepath.Join(dir, "onboard-state.json"),
		Generator:     "wecert-onboard/test",
		DropThreshold: 0.9,
		Now:           c.now,
	}, slog.New(slog.NewTextHandler(&logBuf, nil)))
	if err != nil {
		t.Fatalf("constructing the onboarder failed: %v", err)
	}
	if !strings.Contains(logBuf.String(), "no CLB rule source") {
		t.Error("New must warn that deletion is disabled without a rule source")
	}

	run := func() *Report {
		t.Helper()
		rep, err := ob.Run(context.Background())
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}
		if err := ob.Commit(rep); err != nil {
			t.Fatalf("Commit failed: %v", err)
		}
		return rep
	}

	decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	run()

	decls.raw = []RawDeclaration{decl("a.example.com")}
	run() // records b's absence for the first time

	c.advance(72 * time.Hour) // past the grace period
	rep := run()

	d, ok := decisionFor(rep, "b.example.com")
	if !ok || !d.Included {
		t.Fatalf("without a rule source nothing may be deleted: %+v", d)
	}
	if !strings.Contains(d.Reason, "no CLB rule source is configured") {
		t.Errorf("the reason must say the reference check cannot run, got %q", d.Reason)
	}
	if strings.Contains(d.Reason, "still references") {
		t.Errorf("the reason must not claim a rule references the name, got %q", d.Reason)
	}
}
