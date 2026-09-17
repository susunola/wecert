package onboarding

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// Guard 1 must accept a wildcard declaration when a wildcard rule serves it.
//
// The check used to test only d.Hostname, so `_wecert.example.com wildcard=1` was
// rejected unless something served the bare apex -- even though *.example.com (the rule
// and the wildcard being declared) was served the whole time. When that was the only
// declaration the round then froze on "the desired state came out empty".
func TestGuardOneAcceptsAWildcardServedByAWildcardRule(t *testing.T) {
	h := newHarness(t, Options{RequireRule: true})

	h.decls.raw = []RawDeclaration{
		{Zone: "example.com", Record: DeclarationPrefix + "example.com", Values: []string{"wildcard=1"}},
	}
	h.rules.domains = []string{"*.example.com"}

	rep := h.run(t)

	if rep.Frozen() {
		t.Fatalf("a wildcard declaration served by a wildcard rule must not freeze the round: %v", rep.FreezeReasons)
	}
	got := h.domains(t)
	if len(got) != 2 || got[0] != "example.com" || got[1] != "*.example.com" {
		t.Fatalf("domain set = %v, want [example.com *.example.com]", got)
	}
}

// A declaration that guard 1 excludes must not dictate the group's settings.
//
// It was excluded precisely because nothing serves it, so its profile/keyType/deploy
// describe a certificate that is not being built. Letting it win silently moved a served
// certificate onto a different profile -- with a different SAN cap and renewal window --
// while the report said the declaration had been left out.
func TestExcludedDeclarationDoesNotSetTheGroupProfile(t *testing.T) {
	h := newHarness(t, Options{Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256, RequireRule: true})

	// www is served; staging is declared with a different profile but has no rule.
	h.decls.raw = []RawDeclaration{
		decl("www.example.com"),
		decl("staging.example.com", "profile=tlsserver"),
	}
	h.rules.domains = []string{"www.example.com"}

	rep := h.run(t)

	if d, ok := decisionFor(rep, "staging.example.com"); !ok || d.Included {
		t.Fatalf("staging.example.com should have been excluded by guard 1, got %+v", d)
	}
	c := h.document(t).Certificates[0]
	if c.Profile != config.ProfileClassic {
		t.Errorf("profile = %q, want %q: the excluded declaration's profile must not be applied",
			c.Profile, config.ProfileClassic)
	}
	if len(c.Domains) != 1 || c.Domains[0] != "www.example.com" {
		t.Errorf("domains = %v, want [www.example.com]", c.Domains)
	}
}

// Two excluded declarations that disagree must not freeze the round.
//
// groupSettings reports a conflict when declarations for one registered domain disagree
// on profile/keyType/deploy. Excluded declarations used to be aggregated anyway, so two
// unserved names with different profiles made every served name in that group ineligible
// and the round froze on "the desired state came out empty" -- an outage caused entirely
// by declarations that were supposed to have no effect.
func TestExcludedDeclarationsDoNotFreezeTheRound(t *testing.T) {
	h := newHarness(t, Options{Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256, RequireRule: true})

	h.decls.raw = []RawDeclaration{
		decl("www.example.com"),
		decl("a.example.com", "profile=tlsserver"),
		decl("b.example.com", "profile=classic"),
	}
	h.rules.domains = []string{"www.example.com"}

	rep := h.run(t)

	if rep.Frozen() {
		t.Fatalf("conflicting *excluded* declarations must not freeze the round: %v", rep.FreezeReasons)
	}
	if got := h.domains(t); len(got) != 1 || got[0] != "www.example.com" {
		t.Fatalf("domain set = %v, want [www.example.com]", got)
	}
}

// An accepted declaration must still win, so the fix above cannot have disabled the
// feature: settings from a declaration that really is part of the certificate still apply.
func TestAcceptedDeclarationStillSetsTheGroupProfile(t *testing.T) {
	h := newHarness(t, Options{Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256, RequireRule: true})

	h.decls.raw = []RawDeclaration{
		decl("www.example.com", "profile=tlsserver"),
		decl("staging.example.com", "profile=classic"), // excluded: no rule
	}
	h.rules.domains = []string{"www.example.com"}

	h.run(t)

	c := h.document(t).Certificates[0]
	if c.Profile != config.ProfileTLSServer {
		t.Errorf("profile = %q, want %q from the accepted declaration", c.Profile, config.ProfileTLSServer)
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

// A drop under the freeze threshold passes, but it must be **reported**: a run of
// them erodes the declaration set without ever tripping the fuse, and an operator
// cannot alert on a number nobody publishes.
func TestSubThresholdDropIsReportedNotJustAccepted(t *testing.T) {
	h := newHarness(t, Options{}) // default threshold 0.30

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
	if rep := h.run(t); rep.DeclarationDrop != 0 {
		t.Fatalf("the first round has no baseline, so it must report no drop, got %d", rep.DeclarationDrop)
	}

	set(names[:8])
	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("a 20%% drop is under the 30%% threshold: %v", rep.FreezeReasons)
	}
	if rep.DeclarationDrop != 2 {
		t.Errorf("a passing drop of 2 must still be reported, got %d", rep.DeclarationDrop)
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

// ── force + crash recovery ─────────────────────────────────────────────────

// forced returns an onboarder over the same sources, paths and clock with Force on,
// so a test can interleave forced and unforced rounds the way an operator would.
func (h *harness) forced(t *testing.T) *Onboarder {
	t.Helper()
	opts := h.opts
	opts.Force = true
	ob, err := New(Sources{Declarations: h.decls, Rules: h.rules}, opts, testLogger())
	if err != nil {
		t.Fatalf("constructing the forced onboarder failed: %v", err)
	}
	return ob
}

// crashCommit writes only the document, simulating a crash between Commit's two
// writes (the document goes first, the state second).
func (h *harness) crashCommit(t *testing.T, rep *Report) {
	t.Helper()
	if err := spec.WriteDocument(h.opts.DocumentPath, rep.Document); err != nil {
		t.Fatalf("writing the document failed: %v", err)
	}
}

// A -force round that writes the document but crashes before the state save leaves
// the fuse's baseline (LastDeclared) at the pre-force declarations. The unforced
// retry then re-trips the fuse on the very same drop -- and since a frozen round
// never persists state, every later retry freezes too, wedging until a human passes
// -force again. The document on disk already reflects the drop, though, so the drop
// is not upstream data loss: the retry must refresh the baseline and recover on its
// own.
func TestForceCrashUnforcedRetryDoesNotWedge(t *testing.T) {
	h := newHarness(t, Options{}) // default threshold 0.30, grace 24h

	h.decls.raw = []RawDeclaration{
		decl("a.example.com"), decl("b.example.com"), decl("c.example.com"), decl("d.example.com"),
	}
	h.rules.domains = []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	h.run(t)

	// A forced round drops to one name (75% -- would trip the fuse unforced), writes
	// the document, and "crashes" before the state save.
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	rep, err := h.forced(t).Run(context.Background())
	if err != nil {
		t.Fatalf("forced Run failed: %v", err)
	}
	h.crashCommit(t, rep)

	// The dropped names' rules are gone too, so the reference check may clear them.
	h.rules.domains = []string{"a.example.com"}

	// The unforced retry: the document already reflects the drop, so no freeze.
	rep = h.run(t)
	if rep.Frozen() {
		t.Fatalf("the unforced retry must not re-trip the fuse on a drop the document already carries: %v",
			rep.FreezeReasons)
	}

	// The fuse's baseline caught up with this round's declarations.
	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.LastDeclared; len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("the fuse baseline must catch up with the written document, got LastDeclared=%v", got)
	}

	// The crash also lost the absence ledger, so the grace period re-covers the
	// dropped names for one cycle -- the conservative direction.
	if got := h.domains(t); len(got) != 4 {
		t.Fatalf("the grace period must re-cover the dropped names first, got %v", got)
	}

	// Past the grace period the drop lands on its own, with no second -force.
	h.clock.advance(25 * time.Hour)
	rep = h.run(t)
	if rep.Frozen() {
		t.Fatalf("the round after the grace period must not freeze: %v", rep.FreezeReasons)
	}
	if got := h.domains(t); len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("the drop must land after the grace period without another -force, got %v", got)
	}
}

// The other way past the same crash: the operator answers the frozen retry with
// another -force. That round computes exactly the revision the document already
// carries, so budget() calls it unchanged -- but it must still refresh the state's
// declaration baseline, or the fuse keeps judging later rounds against the pre-force
// set.
func TestForceCrashForcedRetryHealsTheBaseline(t *testing.T) {
	h := newHarness(t, Options{})

	h.decls.raw = []RawDeclaration{
		decl("a.example.com"), decl("b.example.com"), decl("c.example.com"), decl("d.example.com"),
	}
	h.rules.domains = []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	h.run(t)

	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	forced := h.forced(t)
	rep, err := forced.Run(context.Background())
	if err != nil {
		t.Fatalf("forced Run failed: %v", err)
	}
	h.crashCommit(t, rep)

	// The forced retry recomputes the revision the document already carries.
	rep, err = forced.Run(context.Background())
	if err != nil {
		t.Fatalf("forced retry failed: %v", err)
	}
	if rep.Mode != ModeUnchanged {
		t.Fatalf("the forced retry must see the document's revision as its own, got mode %s", rep.Mode)
	}
	if err := forced.Commit(rep); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.LastDeclared; len(got) != 1 || got[0] != "a.example.com" {
		t.Errorf("the forced retry must refresh the declaration baseline, got LastDeclared=%v", got)
	}
	if st.LastRevision != rep.Revision {
		t.Errorf("the state revision must catch up with the document: %s, want %s", st.LastRevision, rep.Revision)
	}

	// And the next unforced round runs clean: no fuse trip, no grace-revert churn.
	h.rules.domains = []string{"a.example.com"}
	rep = h.run(t)
	if rep.Frozen() {
		t.Fatalf("the round after the forced retry must not freeze: %v", rep.FreezeReasons)
	}
	if got := h.domains(t); len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("the dropped names must stay dropped, got %v", got)
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

// The other direction of the same failed-save window: the document carries a
// revision the state never recorded, and the next round recomputes the *state's*
// revision -- a revert X -> Y -> X. The rewrite is a real name-set change wecert
// will act on, so it must spend budget like any other; recognising only "the
// document already carries it" would let a revert escape accounting entirely.
func TestRevertedWriteDoesNotEscapeTheBudget(t *testing.T) {
	stateDir := t.TempDir()
	h := newHarness(t, Options{StatePath: filepath.Join(stateDir, "onboard-state.json")})

	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}
	h.run(t) // revision X committed; one change recorded

	// Write revision Y ({a,b}) but lose the state save.
	h.decls.raw = append(h.decls.raw, decl("b.example.com"))
	h.rules.domains = append(h.rules.domains, "b.example.com")
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if err := h.ob.Commit(rep); err == nil {
		t.Fatal("the state save must fail in an unwritable directory")
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Revert to X: the document on disk says Y, the state says X, and this round
	// computes X. That is a change, not an unchanged round.
	h.decls.raw = h.decls.raw[:1]
	h.rules.domains = h.rules.domains[:1]
	rep = h.run(t)
	if rep.Mode != ModeWritten {
		t.Errorf("the revert must be counted as a change, got mode %s", rep.Mode)
	}

	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(st.Changes); got != 2 {
		t.Errorf("the revert must spend budget: %d changes recorded, want 2 (the first write and the revert)", got)
	}
	if got := h.domains(t); len(got) != 1 || got[0] != "a.example.com" {
		t.Errorf("the document must be rewritten back to X, got %v", got)
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

// A group that exceeds the SAN cap must not simply vanish.
//
// group.ErrTooManyNames is explicitly documented as "callers must NOT read it as drop this
// group": dropping it makes wecert see a certificate disappear into thin air, and the fix
// (declare a wildcard for a busy sub-namespace, or move names to another group) is a human
// decision. With a previous revision the group keeps its old certificate instead; on a
// first run every name is rejected with the reason, so the operator is told.
func TestOverLimitKeepsTheGroupInsteadOfDroppingIt(t *testing.T) {
	const cap = 5

	// First run: no previous revision to carry forward, so every name is rejected loudly
	// rather than silently omitted.
	first := newHarness(t, Options{MaxNames: cap})
	for i := 0; i < 12; i++ {
		first.decls.raw = append(first.decls.raw,
			decl(fmt.Sprintf("h%02d.example.com", i)))
	}
	rep := first.run(t)
	if rep.Certificates != 0 {
		t.Errorf("a group over the cap must not produce a certificate on a first run, got %d",
			rep.Certificates)
	}
	included := 0
	for _, d := range rep.Decisions {
		if d.Included {
			included++
		}
	}
	if included != 0 {
		t.Errorf("no name may be reported as included when the group cannot be expressed, got %d", included)
	}
	if len(rep.Decisions) != 12 {
		t.Errorf("every name must get a decision explaining, got %d", len(rep.Decisions))
	}

	// Second run with a previous revision in place: the group keeps its old certificate,
	// and the report says so.
	second := newHarness(t, Options{MaxNames: cap})
	for i := 0; i < 3; i++ {
		second.decls.raw = append(second.decls.raw,
			decl(fmt.Sprintf("h%02d.example.com", i)))
	}
	if r := second.run(t); r.Certificates != 1 {
		t.Fatalf("the first run should have produced one certificate, got %d", r.Certificates)
	}
	for i := 3; i < 12; i++ {
		second.decls.raw = append(second.decls.raw,
			decl(fmt.Sprintf("h%02d.example.com", i)))
	}
	over := second.run(t)

	if over.Certificates != 1 {
		t.Errorf("the group must be carried forward from the previous revision, got %d certificates",
			over.Certificates)
	}
	if over.CarriedForward == 0 {
		t.Error("the report must say the names were carried forward, not silently keep the certificate")
	}
	kept := 0
	for _, d := range over.Decisions {
		if d.Included {
			kept++
		}
	}
	if kept != over.CarriedForward {
		t.Errorf("CarriedForward=%d but %d decisions report the names as kept: the counter and the "+
			"report disagree", over.CarriedForward, kept)
	}
}

// An existing document that cannot be loaded must fail the round, not silently rebuild the
// desired state without the previous revision.
//
// The previous revision is the safety net for the two decisions that can only remove names:
// overLimit and overSettingsConflict keep an over-cap (or conflicting) group's existing
// certificate and reject every one of its names only when there is nothing to keep. With
// r.prev == nil an over-cap group lost its certificate from the written document, wecert
// then treated it as an orphan that "will not be renewed and will expire", and it did not
// self-heal -- the next round's previous revision was the document that had already lost it.
//
// The trigger is an over-cap group plus an unloadable document (group-writable after a
// careless rsync, wrong owner after a one-off root run, generatedAt skew after an NTP step),
// so the impact is production HTTPS loss from two coincident abnormalities.
func TestUnloadableDocumentFailsTheRoundInsteadOfDroppingAnOverCapGroup(t *testing.T) {
	h := newHarness(t, Options{MaxNames: 3})

	// Round 1: a healthy group, written normally.
	for _, n := range []string{"a", "b", "c"} {
		h.decls.raw = append(h.decls.raw, decl(n+".example.com"))
	}
	if r := h.run(t); r.Certificates != 1 {
		t.Fatalf("round 1 should write one certificate, got %d", r.Certificates)
	}
	before, err := os.ReadFile(h.opts.DocumentPath)
	if err != nil {
		t.Fatalf("reading the document: %v", err)
	}

	// Make the document unloadable the way real life does: group-writable.
	if err := os.Chmod(h.opts.DocumentPath, 0o664); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	// The group is now over the cap, which is exactly when the previous revision matters.
	h.decls.raw = append(h.decls.raw,
		decl("d.example.com"), decl("e.example.com"), decl("f.example.com"))

	if _, err := h.ob.Run(context.Background()); err == nil {
		t.Fatal("an existing but unloadable document must fail the round: continuing without the " +
			"previous revision lets an over-cap group lose its live certificate")
	}

	after, err := os.ReadFile(h.opts.DocumentPath)
	if err != nil {
		t.Fatalf("reading the document back: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("a failed round must not touch the document:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// The control: a document that simply does not exist yet is a first run, not a failure.
// Without this, the test above could be satisfied by refusing every round.
func TestMissingDocumentIsStillAFirstRun(t *testing.T) {
	h := newHarness(t, Options{})
	h.decls.raw = []RawDeclaration{decl("a.example.com")}

	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("a missing document means first run, got %v", err)
	}
	if rep.Certificates != 1 {
		t.Errorf("the first run must still build the desired state, got %d certificates", rep.Certificates)
	}
}

// Losing the state file must not turn deletion from conservative into aggressive.
//
// The state file and the document are separate files, so losing only the state (a cleared
// cache directory, a document restored without its state, a typo in onboarding.statePath)
// left LastNames empty while the document still described the live desired state. An empty
// baseline disabled all three deletion guards in one round: the fuse returned early for lack
// of a baseline, applyGrace found nothing "newly absent" so the grace period was zero
// seconds, and MarkAbsent never ran so the report did not even record the removal.
//
// LoadState's own comment says a state file that cannot be read must never count as empty,
// "that zeroes every grace period". A missing file is even easier to reach than a corrupt
// one, so the same rule holds here: the document is the evidence for what was live.
//
// The drop is one name out of four on purpose. Four -> three is 25%, below the fuse's 30%
// threshold, so the round is NOT frozen and the grace path actually runs. That is what makes
// this test about the grace period rather than about freezing.
func TestLostStateFileDoesNotDeleteNamesWithoutAGracePeriod(t *testing.T) {
	h := newHarness(t, Options{})

	for _, n := range []string{"a", "b", "c", "d"} {
		h.decls.raw = append(h.decls.raw, decl(n+".example.com"))
	}
	if r := h.run(t); r.Certificates != 1 {
		t.Fatalf("round 1 should write one certificate, got %d", r.Certificates)
	}

	// The state file disappears; the document survives.
	if err := os.Remove(h.opts.StatePath); err != nil {
		t.Fatalf("removing the state file: %v", err)
	}

	// One name stops being declared: small enough to pass the fuse.
	h.decls.raw = []RawDeclaration{
		decl("a.example.com"), decl("b.example.com"), decl("c.example.com"),
	}

	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Frozen() {
		t.Fatalf("a 25%% drop must not trip the fuse, but the round froze: %v", rep.FreezeReasons)
	}

	// The grace clock must have started for the now-undeclared name.
	if _, ok := rep.State.AbsentSince["d.example.com"]; !ok {
		t.Error("d.example.com was live in the previous document but the round never started its " +
			"grace clock; with no baseline a name that stops being declared is removed at once")
	}

	// And it must still be in the document: the grace period is what keeps it served while
	// the absence is confirmed.
	doc := h.document(t)
	for _, d := range doc.Certificates[0].Domains {
		if d == "d.example.com" {
			return
		}
	}
	t.Errorf("d.example.com must still be covered during its grace period, got %v",
		doc.Certificates[0].Domains)
}

// A name that is still declared but filtered out by a guard must not also be reported as
// "no longer declared".
//
// The grace period's absent set was built from "covered last round AND not eligible now",
// which includes names that are declared right now but failed guard 1 (no CLB rule serves
// them) or the conflict check. Those got a second, factually false decision saying they were
// no longer declared and only absent for 0s -- and worse, carry() put them back into the
// eligible set, so the round kept converging on a name the guard had just rejected. That is
// exactly the certificate-without-a-rule that guard 1 exists to prevent.
// A guard that stops serving a still-declared name must not strip its coverage.
//
// The reversal is deliberate. Guard 1 is a NETWORK read and cannot express "my answer may be
// incomplete" (a region that did not answer, a rule that a partial list omitted), so a wobble in
// it used to change the document: the name left the certificate, wecert reissued without it, the
// guard recovered, and the name was issued all over again -- two issuances and two rounds without
// coverage, for a name that never stopped being declared. What the guard is for is preventing NEW
// coverage of a name no rule serves; that job is intact (see
// TestADeclarationWithNoRuleIsStillNotIssued).
func TestAGuardWobbleDoesNotStripCoverageOfADeclaredName(t *testing.T) {
	const served = "served.example.com"
	const unserved = "unserved.example.com"

	h := newHarness(t, Options{RequireRule: true})

	// Round 1: both names declared AND served by a rule, so both are covered.
	h.decls.raw = []RawDeclaration{decl(served), decl(unserved)}
	h.rules.domains = []string{served, unserved}
	first := h.run(t)
	if first.Certificates != 1 {
		t.Fatalf("round 1 should cover both names, got %d certificates", first.Certificates)
	}
	if got := h.domains(t); len(got) != 2 {
		t.Fatalf("round 1 domains = %v, want both names", got)
	}

	// Round 2: the rule for `unserved` disappears from the guard, but its declaration stays.
	h.rules.domains = []string{served}
	second := h.run(t)

	d, ok := decisionFor(second, unserved)
	if !ok {
		t.Fatalf("%s must still be reported; decisions: %+v", unserved, second.Decisions)
	}
	if !d.Included {
		t.Errorf("%s is still declared, so it keeps its coverage; got excluded: %s", unserved, d.Reason)
	}
	if !strings.Contains(d.Reason, "no CLB rule serves this name") {
		t.Errorf("the report must still say why the guard did not accept it, got %q", d.Reason)
	}
	if strings.Contains(d.Reason, "no longer declared") {
		t.Errorf("a name that is declared right now was reported as no longer declared: %s", d.Reason)
	}
	// Exactly one verdict for this hostname: an exclusion plus a carry would show the same name
	// twice with opposite answers.
	var verdicts int
	for _, x := range second.Decisions {
		if x.Hostname == unserved {
			verdicts++
		}
	}
	if verdicts != 1 {
		t.Errorf("%s must get exactly one decision, got %d: %+v", unserved, verdicts, second.Decisions)
	}

	// The document is unchanged, which is the whole point: the same revision means no reissue.
	if second.Revision != first.Revision {
		t.Errorf("a guard wobble changed the revision (%s -> %s), so wecert reissues the certificate "+
			"without the name -- and reissues again when the guard recovers",
			first.Revision, second.Revision)
	}
	if got := h.domains(t); len(got) != 2 {
		t.Errorf("the covered set must not shrink on a guard wobble, got %v", got)
	}

	// Round 3: the rule comes back. Nothing changed, so nothing is issued again.
	h.rules.domains = []string{served, unserved}
	third := h.run(t)
	if third.Revision != first.Revision {
		t.Errorf("recovery changed the revision (%s -> %s); the guard's own recovery must not cost "+
			"a second issuance", first.Revision, third.Revision)
	}
	if got := h.domains(t); len(got) != 2 {
		t.Errorf("domains after recovery = %v, want both names", got)
	}
}

// The guard's actual job -- "do not issue a name no rule serves" -- must survive the carry.
//
// A declaration that was never covered has no coverage to keep, so it is excluded as before: the
// carry applies to names that are in the certificate, not to new ones.
func TestADeclarationWithNoRuleIsStillNotIssued(t *testing.T) {
	h := newHarness(t, Options{RequireRule: true})

	h.decls.raw = []RawDeclaration{decl("new.example.com")}
	h.rules.domains = []string{"other.example.com"}

	rep := h.run(t)
	d, ok := decisionFor(rep, "new.example.com")
	if !ok {
		t.Fatalf("the declaration must be reported; decisions: %+v", rep.Decisions)
	}
	if d.Included {
		t.Errorf("a name that was never covered and that no CLB rule serves must not be issued, got %q", d.Reason)
	}
	// Nothing is covered, so the round refuses to write an empty document (an empty one is
	// indistinguishable from a failed generation). That is the pre-existing behaviour and it is
	// what "the guard still prevents new coverage" looks like from the outside.
	if !rep.Frozen() {
		t.Errorf("with no name covered the round must freeze rather than write an empty document, mode=%s", rep.Mode)
	}
}

// Absence markers must not accumulate forever.
//
// MarkAbsent is reached only from the absent set, which comes from the previous round's
// COVERED names. Once a name has left the covered set and its grace period has expired, it
// never re-enters that set -- so nothing clears its marker, and MarkPresent only runs for
// names that come back. One entry therefore accumulated per name ever removed from a
// certificate, permanently, on a system whose hostnames churn by design.
//
// The marker legitimately survives the round that REMOVES the name (that round still has
// the name in its previous revision), so the guarantee is "reclaimed once the name has left
// the previous revision", not "reclaimed the moment it is removed".
func TestAbsenceMarkersAreReclaimedAfterRemoval(t *testing.T) {
	// The threshold is raised so that dropping one name of two (50%) does not trip the
	// abrupt-change fuse: this test is about the absence markers, not about freezing.
	h := newHarness(t, Options{GracePeriod: time.Hour, DropThreshold: 0.9})

	h.decls.raw = []RawDeclaration{decl("keep.example.com"), decl("doomed.example.com")}
	if r := h.run(t); r.Certificates != 1 {
		t.Fatalf("round 1 should cover both names, got %d", r.Certificates)
	}

	// Round 2: `doomed` stops being declared, so the grace clock starts.
	h.decls.raw = []RawDeclaration{decl("keep.example.com")}
	h.rules.domains = []string{"keep.example.com"}
	if r := h.run(t); r.State.AbsentSince["doomed.example.com"].IsZero() {
		t.Fatal("the grace clock must start for a name that stopped being declared")
	}

	// Round 3, past the grace period: the name is removed from the document. Its marker is
	// still needed this round -- it is what carried the elapsed time that justified removal.
	h.clock.advance(2 * time.Hour)
	h.run(t)

	// Round 4: `doomed` is no longer part of the previous revision, so its marker describes
	// nothing. This is where it must go.
	h.run(t)

	state, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if _, ok := state.AbsentSince["doomed.example.com"]; ok {
		t.Error("a name that has left the previous revision must not keep an absence marker; " +
			"otherwise the state file grows with every name ever removed from a certificate")
	}

	// Control: a name that IS currently absent must still have its marker, so this cannot be
	// satisfied by clearing the map.
	h.decls.raw = []RawDeclaration{decl("keep.example.com"), decl("flappy.example.com")}
	h.rules.domains = []string{"keep.example.com", "flappy.example.com"}
	h.run(t)
	h.decls.raw = []RawDeclaration{decl("keep.example.com")}
	h.run(t)

	state, err = LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if _, ok := state.AbsentSince["flappy.example.com"]; !ok {
		t.Error("a name that just stopped being declared must still get a grace clock")
	}
}

// The quota ledger must be pruned on every round, not only on rounds that consult it.
//
// ChangesWithin both counts and prunes, and it used to be reached only from the path that
// records a change -- so the -force path (records without counting) and the unchanged path
// (neither) never pruned. The ledger then grew without bound on a deployment whose name set
// never changed, which is the common steady state.
func TestQuotaLedgerIsPrunedOnEveryRound(t *testing.T) {
	h := newHarness(t, Options{})

	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.run(t)

	// Backdate the ledger far beyond the budget window, directly in the persisted state: the
	// next round finds the declarations unchanged, so it records nothing and never reaches the
	// budget check -- which was the only pruner before this fix.
	state, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	state.Changes = []time.Time{h.clock.now().Add(-30 * 24 * time.Hour)}
	if err := state.Save(h.opts.StatePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	h.run(t)

	after, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if n := len(after.Changes); n != 0 {
		t.Errorf("a change older than the budget window must be pruned even on a round that does "+
			"not consult the budget, got %d entries", n)
	}
}

// A declaration's profile/keyType value is rejected where it is written, so one typo cannot stop
// every certificate from updating.
//
// The values used to be copied into the certificate verbatim and validated only inside
// spec.WriteDocument at Commit: Run() reported "written", Commit then failed with `unknown profile
// "tlsserver2"`, and neither the document nor the state file was written -- every later round failed
// identically for EVERY certificate until a human edited DNS. This package's contract is that one
// bad declaration is recorded as a rejection and skipped (TestOneBadDeclarationDoesNotFreezeEverything).
func TestParseDeclarationRejectsUnknownProfileAndKeyType(t *testing.T) {
	if _, err := ParseDeclaration("example.com", "_wecert.api.example.com", []string{"profile=tlsserver2"}); err == nil {
		t.Error("an unknown profile must be refused where it is parsed, not at document-write time")
	} else if !strings.Contains(err.Error(), "tlsserver2") {
		t.Errorf("the error must name the offending value, got %q", err)
	}
	if _, err := ParseDeclaration("example.com", "_wecert.api.example.com", []string{"keytype=rsa-2048"}); err == nil {
		t.Error("an unknown keytype must be refused at parse time too")
	}

	// The real values still parse, including the empty/absent case (the key simply not appearing).
	for _, ok := range [][]string{
		{"profile=tlsserver", "keytype=ecdsa-p256"},
		{"keytype=rsa4096"},
		{""},
	} {
		if _, err := ParseDeclaration("example.com", "_wecert.api.example.com", ok); err != nil {
			t.Errorf("%v must parse: %v", ok, err)
		}
	}
}

// The report is a claim about what the round did, so it must be written last.
//
// It carries "mode": "written" and the revision, and it is the artifact a human reads to find out
// what onboarding decided. Writing it before the document and the state file meant a failure in
// between left a report announcing a revision that was never written -- and nothing in the report
// said so. Written last, the file exists exactly when the round finished, which is a property an
// operator can rely on without cross-checking two other files.
func TestAFailedCommitWritesNoReport(t *testing.T) {
	reportDir := t.TempDir()
	docDir := t.TempDir()
	reportPath := filepath.Join(reportDir, "report.json")

	h := newHarness(t, Options{
		DocumentPath: filepath.Join(docDir, "desired-state.yaml"),
		StatePath:    filepath.Join(docDir, "onboard-state.json"),
		ReportPath:   reportPath,
	})
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}

	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if rep.Frozen() {
		t.Fatalf("this round must not freeze: %v", rep.FreezeReasons)
	}

	// The desired-state document cannot be written, and the report is somewhere writable: the
	// only thing that can keep the report off disk is the order.
	if err := os.Chmod(docDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(docDir, 0o700) })

	if err := h.ob.Commit(rep); err == nil {
		t.Fatal("the document write must fail in an unwritable directory")
	}
	if _, err := os.Stat(reportPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a round that could not write revision %s must not leave a report claiming it did "+
			"(stat: %v)", rep.Revision, err)
	}

	// And the report is still written when the round does complete: "never write it" would
	// satisfy the check above.
	if err := os.Chmod(docDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := h.ob.Commit(rep); err != nil {
		t.Fatalf("Commit failed once the document was writable again: %v", err)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("a completed round must leave its report behind: %v", err)
	}
}

// A guard answer that is short of what the API reported must be its own signal.
//
// "The guard could not be read" and "the guard answered, but not about everything" both suppress
// removals, and an operator has to be able to tell them apart: the first is weather to retry, the
// second means the rule list itself is being truncated, and every name it did not mention was never
// checked against anything. Treating a short answer as a complete one is what let a guard bug
// become lost coverage; treating it as an ordinary error hides that the API is truncating.
func TestATruncatedGuardAnswerIsReportedAndRemovesNothing(t *testing.T) {
	// Grace period 0 and a high fuse threshold: the only thing standing between this round and a
	// removal is the guard's answer.
	h := newHarness(t, Options{DropThreshold: 0.9})

	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// b's declaration is gone, and the guard cannot be trusted this round: the API reported more
	// rules than it returned.
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}
	h.rules.err = errIncompleteRuleList

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("a truncated guard must not freeze the round: %v", rep.FreezeReasons)
	}
	if !rep.GuardIncomplete {
		t.Error("the report must say the guard answered INCOMPLETELY; without it, this is " +
			"indistinguishable from a transient read failure that an operator would just retry")
	}
	if !rep.GuardUnavailable {
		t.Error("an incomplete guard must also count as unavailable for the removal decisions")
	}
	if got := h.domains(t); len(got) != 2 {
		t.Errorf("a name must not be removed on the strength of a rule list that is known to be "+
			"short, got %v", got)
	}
	d, ok := decisionFor(rep, "b.example.com")
	if !ok || !d.Included {
		t.Errorf("b must be kept and reported as kept, got %+v", d)
	}
}

// A carried declaration must keep its settings, not just its name.
//
// applyGrace keeps a still-declared name whose filter rejected it, but groupSettings skipped every
// declaration the filters had not accepted -- so the certificate was rebuilt from the onboarding
// defaults. A declaration saying `profile=tlsserver, deploy=0` came back as the default profile
// with deployment ON: the revision changed, wecert reissued, and it began deploying a certificate
// the declaration explicitly said not to deploy. That is the opposite of the promise the carry
// makes ("the name keeps its coverage, nothing is reissued").
func TestACarriedDeclarationKeepsItsSettings(t *testing.T) {
	const name = "api.example.com"

	h := newHarness(t, Options{RequireRule: true})
	h.decls.raw = []RawDeclaration{decl(name, "profile=tlsserver", "deploy=0")}
	h.rules.domains = []string{name}
	first := h.run(t)

	doc := h.document(t)
	if len(doc.Certificates) != 1 {
		t.Fatalf("expected one certificate, got %d", len(doc.Certificates))
	}
	c := doc.Certificates[0]
	if c.Profile != config.ProfileTLSServer || c.Deploy.Enabled {
		t.Fatalf("the declaration's own settings must reach the document first, got profile=%s deploy=%v",
			c.Profile, c.Deploy.Enabled)
	}

	// The rule disappears; the declaration stays, so the name is carried.
	h.rules.domains = nil
	second := h.run(t)

	doc = h.document(t)
	if len(doc.Certificates) != 1 {
		t.Fatalf("expected one certificate, got %d", len(doc.Certificates))
	}
	c = doc.Certificates[0]
	if c.Profile != config.ProfileTLSServer {
		t.Errorf("the carried certificate's profile flipped to %q: the declaration's settings were "+
			"dropped, which changes the revision and reissues", c.Profile)
	}
	if c.Deploy.Enabled {
		t.Errorf("deployment was turned ON for a declaration that says deploy=0: the filter changed " +
			"what the declaration asked for")
	}
	if second.Revision != first.Revision {
		t.Errorf("a guard wobble changed the revision (%s -> %s): the certificate is reissued even "+
			"though nothing about the declaration changed", first.Revision, second.Revision)
	}
	if !containsAllDomains(h.domains(t), name) {
		t.Errorf("the carried name must stay covered, got %v", h.domains(t))
	}
}

// A group is capped by the profile it will actually be issued with.
//
// onboarding.maxNames is validated only as "not negative", and on its own it is legal for classic
// (100). A declaration asking for tlsserver inside such a group produced a certificate with more
// than 25 identifiers, which spec.WriteDocument then rejected -- on every round, for every
// certificate, with no document, no state and no report, while Run still reported "written". The
// cap has to come from the profile, and exceeding it has to be a reported decision (overLimit)
// rather than an unwritable document.
func TestAGroupIsCappedByTheProfileItWillUse(t *testing.T) {
	h := newHarness(t, Options{RequireRule: true, MaxNames: 100, DropThreshold: 0.9})

	names := make([]string, 0, 26)
	h.decls.raw = append(h.decls.raw, decl("api.example.com", "profile=tlsserver"))
	names = append(names, "api.example.com")
	for i := range 25 {
		host := "n" + itoa(i) + ".example.com"
		h.decls.raw = append(h.decls.raw, decl(host))
		names = append(names, host)
	}
	h.rules.domains = names

	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// The failure the fix removes: Commit rejecting a document Run called "written".
	if err := h.ob.Commit(rep); err != nil {
		t.Fatalf("Commit failed on a document the round reported as %s: %v. A cap that ignores the "+
			"profile produces a document no writer accepts, so every round fails for every "+
			"certificate", rep.Mode, err)
	}

	// And the reason is reported rather than silently dropped.
	var explained bool
	for _, d := range rep.Decisions {
		if strings.Contains(d.Reason, "max is 25") || strings.Contains(d.Reason, "cannot be expressed") {
			explained = true
		}
	}
	for _, r := range rep.FreezeReasons {
		if strings.Contains(r, "max is 25") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("the group exceeds the tlsserver cap, so the round must say so: decisions=%+v freeze=%v",
			rep.Decisions, rep.FreezeReasons)
	}
}

// containsAllDomains reports whether every wanted name is in got.
func containsAllDomains(got []string, want ...string) bool {
	for _, w := range want {
		var found bool
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// A hostname that ends up included must not also be reported as excluded.
//
// The parse loop records an exclusion for an unparseable record, and that exclusion was never
// cleared when another record for the SAME hostname parsed and was accepted -- which happens
// whenever the same name is declared in a parent zone and in a delegated subzone, one of them
// with a typo. The report is the artifact a human reads to find out what happened, and it said
// both things at once; stillDeclaredReason could also quote the stale text for a name it carries.
func TestAnIncludedHostnameIsNotAlsoReportedAsExcluded(t *testing.T) {
	const host = "api.example.com"
	h := newHarness(t, Options{RequireRule: true})

	// One record for api.example.com is a typo; another (from the delegated subzone) is valid.
	broken := RawDeclaration{Zone: "example.com", Record: DeclarationPrefix + host, Values: []string{"unknownkey=1"}}
	good := RawDeclaration{Zone: "sub.example.com", Record: DeclarationPrefix + host, Values: []string{"v=wecert1"}}
	h.decls.raw = []RawDeclaration{broken, good}
	h.rules.domains = []string{host}

	rep := h.run(t)

	var included, excluded int
	for _, d := range rep.Decisions {
		if d.Hostname != host {
			continue
		}
		if d.Included {
			included++
		} else {
			excluded++
		}
	}
	if included != 1 {
		t.Errorf("%s is declared by a valid record, so it must be included once, got %d: %+v",
			host, included, rep.Decisions)
	}
	if excluded != 0 {
		t.Errorf("%s must not be reported as excluded as well: the report would say two opposite "+
			"things about one name: %+v", host, rep.Decisions)
	}
}

// The wildcard note must not erase the reason a filter gave.
//
// A name that is covered by a declared wildcard AND was rejected by a filter this round (so it is
// carried) used to end up with only "covered by the declared wildcard ...": the guard that is
// dropping it disappeared from the report, which is the artifact an operator reads to find out why
// something is not being issued.
func TestAWildcardCoveredCarryKeepsItsFilterReason(t *testing.T) {
	const apex = "example.com"
	const api = "api.example.com"

	h := newHarness(t, Options{RequireRule: true})

	// Round 1: the wildcard and the concrete name are both declared and both served.
	h.decls.raw = []RawDeclaration{decl(apex, "wildcard=1"), decl(api)}
	h.rules.domains = []string{apex, api}
	h.run(t)

	// Round 2: the rule for api.example.com disappears, so guard 1 rejects that declaration --
	// but *.example.com is still declared and served, so the name stays covered by it.
	h.rules.domains = []string{apex}
	rep := h.run(t)

	d, ok := decisionFor(rep, api)
	if !ok {
		t.Fatalf("%s must still be reported: %+v", api, rep.Decisions)
	}
	if !d.Included {
		t.Fatalf("%s is still covered by the declared wildcard: %+v", api, d)
	}
	if !strings.Contains(d.Reason, "no CLB rule serves this name") {
		t.Errorf("the reason must still say a filter rejected it, got %q", d.Reason)
	}
	if !strings.Contains(d.Reason, "covered by the declared wildcard") {
		t.Errorf("and it must still say the wildcard covers it, got %q", d.Reason)
	}
	if rep.CoveredByWildcard == 0 {
		t.Error("the covered-by-wildcard count must include it")
	}
}
