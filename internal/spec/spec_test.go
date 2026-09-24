package spec

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testDoc(t *testing.T) *Document {
	t.Helper()
	return &Document{
		APIVersion:  APIVersionV1,
		Kind:        KindDesiredState,
		GeneratedAt: time.Now(),
		Generator:   "wecert-onboard/test",
		Certificates: []config.Certificate{{
			Name:    "example-com",
			Domains: []string{"example.com", "*.example.com"},
		}},
	}
}

// An empty document is always rejected.
//
// A "legitimately empty" file and a "generation failed, hence empty" file look
// identical, and accepting the latter strips every domain from every certificate.
// The risk is far too asymmetric.
func TestValidateRejectsEmptyCertificates(t *testing.T) {
	t.Parallel()
	doc := testDoc(t)
	doc.Certificates = nil

	if err := doc.Validate(); err == nil {
		t.Fatal("an empty certificates list must be rejected")
	}
}

func TestValidateRequiresEnvelope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*Document)
		want   string
	}{
		{"apiVersion", func(d *Document) { d.APIVersion = "other/v9" }, "apiVersion"},
		{"kind", func(d *Document) { d.Kind = "Something" }, "kind"},
		{"generatedAt", func(d *Document) { d.GeneratedAt = time.Time{} }, "generatedAt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := testDoc(t)
			tc.mutate(doc)
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// Certificate names must derive from the grouping key.
//
// This is the only place on the contract boundary that can stop "the name
// follows the domain set" -- by the time wecert reads it, the orphan state
// already exists.
func TestValidateRejectsNameThatFollowsTheDomainSet(t *testing.T) {
	t.Parallel()
	doc := testDoc(t)
	doc.Certificates = []config.Certificate{{
		// The registered domain is example.com, so the name must be example-com.
		Name:    "example-com-plus-api",
		Domains: []string{"example.com", "api.example.com"},
	}}

	err := doc.Validate()
	if err == nil || !strings.Contains(err.Error(), "not stable") {
		t.Fatalf("expected a Name stability error, got %v", err)
	}
}

func TestValidateRejectsCrossRegisteredDomain(t *testing.T) {
	t.Parallel()
	doc := testDoc(t)
	doc.Certificates = []config.Certificate{{
		Name:    "example-com",
		Domains: []string{"example.com", "example.net"},
	}}

	err := doc.Validate()
	if err == nil || !strings.Contains(err.Error(), "registered domains") {
		t.Fatalf("expected a cross-registered-domain error, got %v", err)
	}
}

// The fingerprint covers certificate content only, ignoring timestamps and order.
// Otherwise it would change on every onboarding run and "did the desired state
// actually change?" could not be answered.
func TestRevisionIgnoresOrderAndTimestamps(t *testing.T) {
	t.Parallel()
	a := []config.Certificate{{Name: "example-com", Domains: []string{"example.com", "*.example.com"}}}
	b := []config.Certificate{{Name: "example-com", Domains: []string{"*.example.com", "example.com"}}}

	if Revision(a) != Revision(b) {
		t.Errorf("domain order must not affect the fingerprint: %s vs %s", Revision(a), Revision(b))
	}
	if Revision(a) == Revision([]config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}}) {
		t.Error("changing the domain set must change the fingerprint")
	}
}

func TestRevisionRejectsATamperedDocument(t *testing.T) {
	t.Parallel()
	doc := testDoc(t)
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}

	// Change the content but keep the old fingerprint -- the most common shape of
	// a hand edit.
	doc.Certificates[0].Domains = append(doc.Certificates[0].Domains, "a.b.example.com")
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Fatalf("expected a fingerprint mismatch error, got %v", err)
	}
}

func TestWriteAndLoadRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "desired-state.yaml")

	doc := testDoc(t)
	if err := WriteDocument(path, doc); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "# ") {
		t.Error("the document must start with the do-not-edit-by-hand header")
	}

	got, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != doc.Revision {
		t.Errorf("fingerprint lost: %q vs %q", got.Revision, doc.Revision)
	}
	if len(got.Certificates) != 1 || got.Certificates[0].Name != "example-com" {
		t.Errorf("certificate was not read back: %+v", got.Certificates)
	}
	// profile/keyType must be normalized to their defaults rather than left empty.
	if got.Certificates[0].Profile != config.ProfileClassic {
		t.Errorf("profile must be filled with the default, got %q", got.Certificates[0].Profile)
	}
}

// If the document is unreadable at startup, constructing the provider must fail.
//
// Allowing "starts up but has no desired state" means wecert quietly renews
// nothing until every certificate expires -- the worst kind of failure: silent,
// with all the consequences in production.
func TestNewFileFailsWhenTheDocumentIsMissing(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nope.yaml")
	if _, err := NewFile(path, testLogger()); err == nil {
		t.Fatal("NewFile must fail when the document is missing")
	}
}

// An unreadable document at runtime is not an empty desired state.
//
// This is the one place in the entire design that can cause a disaster: if a read
// failure were treated as "desired state is empty", wecert would strip domains
// from every certificate and handshakes would fail in production immediately.
// The correct reaction is to freeze on the last usable revision and keep
// converging on it.
func TestFileProviderFreezesOnUnreadableDocument(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "desired-state.yaml")
	if err := WriteDocument(path, testDoc(t)); err != nil {
		t.Fatal(err)
	}

	f, err := NewFile(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	good, err := f.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if good.Frozen {
		t.Fatal("a successful first read must not be frozen")
	}

	// The document is deleted (or chmod-ed, or truncated mid-write).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	frozen, err := f.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatalf("freezing must not return an error, got %v", err)
	}
	if !frozen.Frozen {
		t.Error("an unreadable document must be marked as frozen")
	}
	if frozen.FreezeReason == "" {
		t.Error("a frozen state must explain the reason")
	}
	if len(frozen.Certificates) != len(good.Certificates) {
		t.Fatalf("freezing must keep the previous certificates, got %d -> %d",
			len(good.Certificates), len(frozen.Certificates))
	}
	if frozen.Revision != good.Revision {
		t.Errorf("freezing must keep the previous revision, got %q -> %q", good.Revision, frozen.Revision)
	}
}

func TestDiffReportsAddRemoveAndChange(t *testing.T) {
	t.Parallel()
	enforced := &Result{Certificates: []config.Certificate{
		{Name: "example-com", Domains: []string{"example.com", "old.example.com"}},
		{Name: "gone-net", Domains: []string{"gone.net"}},
		{Name: "same-org", Domains: []string{"same.org"}},
	}}
	shadow := &Result{Certificates: []config.Certificate{
		{Name: "example-com", Domains: []string{"example.com", "new.example.com"}},
		{Name: "same-org", Domains: []string{"same.org"}},
		{Name: "fresh-io", Domains: []string{"fresh.io"}},
	}, Revision: "sha256:abc"}

	got := Diff(enforced, shadow)

	if len(got.AddCertificates) != 1 || got.AddCertificates[0] != "fresh-io" {
		t.Errorf("wrong certificates detected as added: %v", got.AddCertificates)
	}
	if len(got.RemoveCertificates) != 1 || got.RemoveCertificates[0] != "gone-net" {
		t.Errorf("wrong certificates detected as removed: %v", got.RemoveCertificates)
	}
	if len(got.ChangeCertificates) != 1 {
		t.Fatalf("exactly 1 changed certificate must be detected, got %v", got.ChangeCertificates)
	}
	ch := got.ChangeCertificates[0]
	if ch.Name != "example-com" {
		t.Errorf("wrong changed certificate name: %q", ch.Name)
	}
	if len(ch.Added) != 1 || ch.Added[0] != "new.example.com" {
		t.Errorf("wrong domains detected as added: %v", ch.Added)
	}
	if len(ch.Removed) != 1 || ch.Removed[0] != "old.example.com" {
		t.Errorf("wrong domains detected as removed: %v", ch.Removed)
	}
	if got.Empty() {
		t.Error("Empty must be false when there is a diff")
	}
}

func TestDiffIsEmptyWhenNothingChanged(t *testing.T) {
	t.Parallel()
	certs := []config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}}
	got := Diff(&Result{Certificates: certs}, &Result{Certificates: certs})
	if !got.Empty() {
		t.Errorf("no diff must be reported as empty: %+v", got)
	}
}

// The desired-state document *is* the desired state: whoever can rewrite it decides
// which domains are served and which quietly stop being renewed. LoadDocument therefore
// refuses a symlink rather than following it, and refuses a group- or world-writable
// file.
//
// Readability is deliberately not checked -- the file is written 0644 so an operator can
// read it, and only the write bits can change what it says.
func TestLoadDocumentRefusesASymlinkOrAWritableFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	body := "apiVersion: wecert/v1\nkind: DesiredState\ngeneratedAt: " +
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339) +
		"\ngenerator: wecert-onboard/test\ncertificates:\n  - name: example-com\n    domains: [example.com]\n"
	if err := os.WriteFile(good, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// 0644 has no write bit for group or other, so this must load.
	if _, err := LoadDocument(good); err != nil {
		t.Fatalf("a 0644 document must load: %v", err)
	}

	// Group- or world-writable must not.
	for _, perm := range []os.FileMode{0o664, 0o646, 0o666} {
		p := filepath.Join(dir, fmt.Sprintf("w%o.yaml", perm))
		if err := os.WriteFile(p, []byte(body), perm); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, perm); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(p); err == nil {
			t.Errorf("a %04o document must be refused: anything that can write it decides what is served", perm)
		}
	}

	// A symlink must not be followed, however harmless its target.
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDocument(link)
	if err == nil {
		t.Fatal("a symlinked document must be refused rather than followed")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("err = %v, want it to name the symlink", err)
	}
}

// A generatedAt in the future must be refused: the staleness alarm is
// time.Since(generatedAt) > maxStaleness, so a far-future date makes that comparison
// false forever -- and Revision covers only the certificates, so changing generatedAt
// alone trips no other check. It is the one signal this architecture has for "the
// generator died and no new name will ever be picked up".
func TestValidateRejectsAFutureGeneratedAt(t *testing.T) {
	t.Parallel()
	doc := testDoc(t)
	doc.GeneratedAt = time.Now().Add(24 * time.Hour)
	if err := doc.Validate(); err == nil {
		t.Fatal("a generatedAt a day in the future must be rejected")
	}

	// A little clock skew is still fine.
	doc = testDoc(t)
	doc.GeneratedAt = time.Now().Add(time.Minute)
	if err := doc.Validate(); err != nil {
		t.Fatalf("a minute of clock skew must be tolerated: %v", err)
	}
}

// A document inside a world-writable directory must be refused even when the file
// itself is 0644: WriteDocument installs the file by rename, so the directory's
// permissions -- not the file's -- decide who can replace its contents.
func TestLoadDocumentRefusesAWorldWritableDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inner := filepath.Join(dir, "docs")
	if err := os.Mkdir(inner, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inner, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inner, "desired-state.yaml")
	doc := testDoc(t)
	if err := WriteDocument(path, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDocument(path); err == nil {
		t.Fatal("a document in a world-writable directory must be refused")
	}
}

// ── provider entry points ────────────────────────────────────────────────────────────
//
// The providers are what the convergence loop actually talks to, and the three modes differ
// only in which one is wired up. Until now only the document loader and the diff were covered;
// the provider methods themselves were not, which is the layer where "observe mode signs
// nothing" and "an unreadable source freezes" have to hold.

// Static must copy the caller's slice: the config is shared with the running process, and a
// provider that aliases it would let a later mutation change the desired state underneath
// convergence.
func TestStaticCopiesTheCertificateSlice(t *testing.T) {
	t.Parallel()
	certs := []config.Certificate{{Name: "a", Domains: []string{"a.example.com"}}}
	st := NewStatic(certs)

	certs[0].Name = "mutated"
	got, err := st.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if got[0].Name != "a" {
		t.Errorf("the provider aliases the caller's slice: name became %q", got[0].Name)
	}
	if st.Kind() != config.ModeStatic {
		t.Errorf("Kind = %q, want %q", st.Kind(), config.ModeStatic)
	}
}

// The static result must carry a revision and per-name decisions, because the diagnostic
// endpoint and the shadow report both read them.
func TestStaticReportsRevisionAndDecisions(t *testing.T) {
	t.Parallel()
	st := NewStatic([]config.Certificate{{Name: "a", Domains: []string{"a.example.com"}}})
	res, err := st.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision == "" {
		t.Error("a revision is required: the shadow report compares against it")
	}
	if len(res.Decisions) != 1 || res.Decisions[0].Hostname != "a.example.com" {
		t.Errorf("decisions = %+v, want one for a.example.com", res.Decisions)
	}
	if res.Shadow != nil {
		t.Error("static mode has no shadow source, so Shadow must stay nil")
	}
}

// The File provider must satisfy the same interface as Static, so switching desiredState.mode
// needs no change to the convergence loop.
func TestFileProviderServesTheDocument(t *testing.T) {
	t.Parallel()
	doc := testDoc(t)
	path := writeDoc(t, doc)

	f, err := NewFile(path, testLogger())
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if f.Kind() != "document" {
		t.Errorf("Kind = %q, want document", f.Kind())
	}

	certs, err := f.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(certs) != len(doc.Certificates) {
		t.Fatalf("got %d certificates, want %d", len(certs), len(doc.Certificates))
	}

	res, err := f.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Frozen {
		t.Error("a readable document must not be reported as frozen")
	}
	if res.Revision != doc.Revision {
		t.Errorf("revision = %q, want the document's %q", res.Revision, doc.Revision)
	}
}

// An unreadable document must return the LAST GOOD revision marked frozen -- never an error and
// never an empty set. An empty desired state would strip every SAN from every certificate, so
// the failure has to degrade to "carry on with what we had".
func TestFileProviderFreezesOnAnUnreadableDocument(t *testing.T) {
	t.Parallel()
	doc := testDoc(t)
	path := writeDoc(t, doc)

	f, err := NewFile(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	// Read once successfully, so there is a last-good revision.
	if _, err := f.DesiredWithReasons(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	res, err := f.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatalf("an unreadable document must not be an error: %v", err)
	}
	if !res.Frozen {
		t.Error("the result must be marked frozen")
	}
	if res.FreezeReason == "" {
		t.Error("a freeze must say why, or the metric alerts with no explanation")
	}
	if res.Revision != doc.Revision {
		t.Errorf("revision = %q, want the last good %q", res.Revision, doc.Revision)
	}
	if len(res.Certificates) != len(doc.Certificates) {
		t.Errorf("got %d certificates, want the last good %d", len(res.Certificates), len(doc.Certificates))
	}
	// Desired() must inherit the same semantics rather than reporting an error.
	certs, err := f.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired on a frozen source: %v", err)
	}
	if len(certs) != len(doc.Certificates) {
		t.Errorf("Desired returned %d certificates while frozen, want the last good set", len(certs))
	}
}

// A document that is unreadable at startup must be an error, not a freeze: there is no last
// good revision, and starting with no desired state means renewing nothing.
func TestNewFileFailsWhenThereIsNothingToFallBackTo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := NewFile(path, testLogger()); err == nil {
		t.Fatal("NewFile on a missing document must fail, or enforce mode starts with no state")
	}
}

// ── Observer: the static -> enforce migration step ───────────────────────────────────

// Observe mode must converge on the PRIMARY source. It is a reporting step, and if the shadow
// ever won, switching to observe would change what is issued -- which is the one thing it
// promises not to do.
func TestObserverConvergesOnThePrimary(t *testing.T) {
	t.Parallel()
	primary := NewStatic([]config.Certificate{{Name: "primary", Domains: []string{"p.example.com"}}})
	shadowDoc := testDoc(t)
	shadow := NewStatic(shadowDoc.Certificates)

	o := NewObserver(primary, shadow, testLogger())
	if !strings.Contains(o.Kind(), "observe(") {
		t.Errorf("Kind = %q, want it to name the wrapped source", o.Kind())
	}

	certs, err := o.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(certs) != 1 || certs[0].Name != "primary" {
		t.Fatalf("observe mode must serve the primary source, got %+v", certs)
	}

	res, err := o.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Certificates) != 1 || res.Certificates[0].Name != "primary" {
		t.Errorf("the reported certificates must be the primary's, got %+v", res.Certificates)
	}
	if res.Shadow == nil {
		t.Fatal("observe mode must attach a shadow report; it is the whole output")
	}
	if res.Shadow.Empty() {
		t.Error("the two sources differ, so the report must not read as agreement")
	}
	if res.Shadow.Error != "" {
		t.Errorf("both sources are readable, so there is no error to report: %q", res.Shadow.Error)
	}
}

// An unreadable shadow must not fail the pass: during observation the document is often absent
// because generation has not started yet, and convergence has to carry on.
func TestObserverSurvivesAnUnreadableShadow(t *testing.T) {
	t.Parallel()
	primary := NewStatic([]config.Certificate{{Name: "primary", Domains: []string{"p.example.com"}}})
	// NewFile refuses to construct without a document, so the unreadable shadow is a provider
	// that reports the failure instead -- which is what a document that disappears mid-run
	// turns into.
	o := NewObserver(primary, failingProvider{}, testLogger())

	res, err := o.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatalf("a shadow failure must not fail the pass: %v", err)
	}
	if res.Shadow == nil || res.Shadow.Error == "" {
		t.Fatal("the failure must be recorded in the report, not silently dropped")
	}
	// Empty() means "a comparison was produced and it agrees". A report carrying an error is
	// therefore NOT empty: the whole point is that "we could not compare" must not read as
	// "they agree".
	if res.Shadow.Empty() {
		t.Error("a report carrying an error must not read as agreement")
	}
	if len(res.Certificates) != 1 {
		t.Error("convergence must still use the primary source")
	}
}

// failingProvider always fails, standing in for an unreadable source.
type failingProvider struct{}

func (failingProvider) Desired(context.Context) ([]config.Certificate, error) {
	return nil, fmt.Errorf("source is unreadable")
}
func (failingProvider) DesiredWithReasons(context.Context) (*Result, error) {
	return nil, fmt.Errorf("source is unreadable")
}

// spec.Desired must prefer the reporting path when a provider implements it, so callers get
// decisions and revisions rather than a bare certificate list.
func TestDesiredUsesTheReportingPathWhenAvailable(t *testing.T) {
	t.Parallel()
	withReasons := NewStatic([]config.Certificate{{Name: "a", Domains: []string{"a.example.com"}}})
	res, err := Desired(context.Background(), withReasons)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Decisions) == 0 {
		t.Error("the reporting path was not used: decisions are what make the diagnostics explain themselves")
	}

	// A bare Provider must still work, with a revision computed from the certificates.
	bare := &bareProvider{certs: []config.Certificate{{Name: "b", Domains: []string{"b.example.com"}}}}
	res, err = Desired(context.Background(), bare)
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision == "" {
		t.Error("a revision must be computed for a bare provider")
	}
	if len(res.Certificates) != 1 {
		t.Errorf("certificates = %+v", res.Certificates)
	}
}

// bareProvider implements only Provider, like a future source that does not report reasons.
type bareProvider struct{ certs []config.Certificate }

func (b *bareProvider) Desired(context.Context) ([]config.Certificate, error) { return b.certs, nil }

// KindOf must not panic on a provider that does not implement Named.
func TestKindOfFallsBackForAnUnnamedProvider(t *testing.T) {
	t.Parallel()
	if got := KindOf(&bareProvider{}); got != "unknown" {
		t.Errorf("KindOf = %q, want unknown", got)
	}
}

// writeDoc writes a valid document and returns its path.
func writeDoc(t *testing.T, doc *Document) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "desired-state.yaml")
	if err := WriteDocument(path, doc); err != nil {
		t.Fatalf("WriteDocument: %v", err)
	}
	return path
}

// A frozen shadow source is "no comparison", not "no differences".
//
// A file source never errors once it has read the document successfully: a later unreadable or
// invalid revision comes back frozen, with a nil error and the last good revision. Comparing
// against that and reporting a quiet diff is the false confidence observe mode exists to avoid --
// the gate that decides whether it is safe to switch to enforce watches shadow_errors_total and
// shadow_last_read, and both would look healthy while the document nobody can read is what the
// shadow is actually made of.
func TestObserverReportsAFrozenShadowAsNoComparison(t *testing.T) {
	t.Parallel()
	primary := NewStatic([]config.Certificate{{Name: "primary", Domains: []string{"p.example.com"}}})
	// A provider that answers with a frozen result and no error, which is exactly what File does
	// after its first successful read.
	o := NewObserver(primary, frozenProvider{}, testLogger())

	res, err := o.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatalf("a frozen shadow must not fail the pass: %v", err)
	}
	if res.Shadow == nil {
		t.Fatal("the shadow report must exist")
	}
	if res.Shadow.Error == "" {
		t.Error("a frozen shadow means no comparison was produced; reporting an empty error makes " +
			"the diff look fresh and quiet when it was computed against a document nobody can read")
	}
	if res.Shadow.Empty() {
		t.Error("a report that compared nothing must not read as agreement")
	}
}

// frozenProvider returns a frozen result with no error, like File after its first good read.
type frozenProvider struct{}

func (frozenProvider) Desired(context.Context) ([]config.Certificate, error) {
	return []config.Certificate{{Name: "shadow", Domains: []string{"s.example.com"}}}, nil
}
func (frozenProvider) DesiredWithReasons(context.Context) (*Result, error) {
	return &Result{
		Certificates: []config.Certificate{{Name: "shadow", Domains: []string{"s.example.com"}}},
		Revision:     "rev-1",
		Frozen:       true,
		FreezeReason: "document is unreadable",
	}, nil
}
