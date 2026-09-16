package onboarding

import (
	"context"
	"errors"
	"io"
	"log/slog"
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
	dir := t.TempDir()
	opts := Options{
		DocumentPath:  filepath.Join(dir, "desired-state.yaml"),
		StatePath:     filepath.Join(dir, "onboard-state.json"),
		ReportPath:    filepath.Join(dir, "report.json"),
		DropThreshold: 30,
	}
	_, err := New(Sources{Declarations: &fakeDeclarations{}, Rules: &fakeRules{}}, opts, testLogger())
	if err == nil {
		t.Fatal("DropThreshold >= 1 must be rejected: the abrupt-change fuse would never fire")
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
