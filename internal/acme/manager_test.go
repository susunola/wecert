package acme

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

func TestParseOrderExpiresEmptyUsesFallback(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	got, err := parseOrderExpires("", now)
	if err != nil {
		t.Fatalf("empty expires should not error: %v", err)
	}
	want := now.Add(defaultOrderTTL)
	if !got.Equal(want) {
		t.Errorf("empty expires = %s, want fallback %s", got, want)
	}
}

func TestParseOrderExpiresRFC3339(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	raw := "2026-09-22T00:00:00Z"
	got, err := parseOrderExpires(raw, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestParseOrderExpiresGarbageUsesFallback(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	got, err := parseOrderExpires("not-a-timestamp", now)
	if err == nil {
		t.Fatal("expected error for garbage expires")
	}
	if !got.Equal(now.Add(defaultOrderTTL)) {
		t.Errorf("garbage expires should still return fallback, got %s", got)
	}
}

// A partially broken state store must not turn into a reissue of the full identifier set.
//
// Reconcile reads cert_fallback to learn whether a degradation is in force; the drift branch uses
// that answer to tell "the degraded certificate is missing names on purpose" from "the config
// changed". A failed read used to mean "no fallback", so the pass ordered the full -- known-bad --
// identifier set immediately, which is the oscillation the fallback exists to stop. The sibling
// decision in fallback.go holds on the very same failure.
func TestAnUnreadableFallbackRecordHoldsInsteadOfReissuing(t *testing.T) {
	store, m, fake, cert, dbPath := newDBFaultHarness(t)

	// A live certificate that covers only part of the config: exactly the drift the branch looks at.
	cert.Domains = []string{"example.com", "missing.example.com"}
	if err := store.PutCert(&state.CertState{
		Name:     cert.Name,
		NotAfter: time.Now().Add(60 * 24 * time.Hour),
		CertPEM:  selfSignedCertPEM(t, time.Now().Add(60*24*time.Hour), "example.com"),
	}); err != nil {
		t.Fatal(err)
	}

	dropTable(t, dbPath, "cert_fallback")

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("a failed fallback read must hold the certificate, not fail the pass: %v", err)
	}
	if fake.newOrderDomains != nil {
		t.Errorf("the full identifier set was ordered while the fallback state was unreadable: %v",
			fake.newOrderDomains)
	}
}

// Holding on an unreadable fallback must not turn into DROPPING names.
//
// The first version of the hold reused the "a degradation is in force" flag, which applyFallback
// also reads -- and that path skips the expiry gate, because a degradation already in force is
// continued whatever the remaining lifetime is. So a state-store blip could drop names from a
// certificate that is nowhere near expiry: the opposite of the conservative direction the hold was
// for. The two facts are now separate flags, and this test pins both halves: the fixture really
// would drop if a fallback were in force, and an unreadable record does not.
func TestAnUnreadableFallbackDoesNotDropNames(t *testing.T) {
	var logs bytes.Buffer
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(&logs, nil)))
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	yes := true
	m.SetFallbackPolicy(config.FailureFallback{
		Enabled:               &yes,
		AfterFailures:         3,
		MinIdentifierFailures: 2,
		MinNames:              1,
		BeforeExpiryDur:       168 * time.Hour,
		FailureWindowDur:      72 * time.Hour,
	})

	cert := &config.Certificate{
		Name: "site-example-com", Domains: []string{"example.com", "broken.example.com"},
		Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
	}
	// The live certificate covers only the healthy name: the degraded shape.
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: now.Add(60 * 24 * time.Hour),
		CertPEM:             selfSignedCertPEM(t, now.Add(60*24*time.Hour), "example.com"),
		ConsecutiveFailures: 20,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "broken.example.com", "NXDOMAIN", now); err != nil {
			t.Fatal(err)
		}
	}

	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}

	// The precondition, asserted rather than assumed: with a degradation in force this fixture
	// WOULD drop the failing name. Without this the rest of the test could pass vacuously.
	kept, dropped, _ := m.fallbackDomains(cert, st, true)
	if len(dropped) != 1 || dropped[0] != "broken.example.com" || len(kept) != 1 {
		t.Fatalf("the fixture must be a certificate that would drop its failing name "+
			"(kept=%v dropped=%v)", kept, dropped)
	}

	// Now make the degradation state unreadable.
	dropTable(t, dbPath, "cert_fallback")

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("a failed fallback read must hold the certificate, not fail the pass: %v", err)
	}
	if strings.Contains(logs.String(), "FALLING BACK") {
		t.Errorf("an unreadable fallback record must not drop names from a certificate that is "+
			"nowhere near expiry; log:\n%s", logs.String())
	}
	if fake.newOrderDomains != nil {
		t.Errorf("nothing may be ordered on an unreadable fallback: %v", fake.newOrderDomains)
	}
}

// newDBFaultHarness builds a manager over a state store whose file the test can damage.
//
// The Manager holds a concrete *state.Store, so a failing read has to come from the database
// itself. Dropping one table (through a second connection) is exactly that shape: one operation
// fails while the rest of the store keeps working, which is what a partially migrated or damaged
// database looks like.
func newDBFaultHarness(t *testing.T) (*state.Store, *Manager, *fakeAPI, *config.Certificate, string) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.SetNow(func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) })

	cert := &config.Certificate{
		Name:    "site-example-com",
		Domains: []string{"example.com"},
		Profile: config.ProfileClassic,
		KeyType: config.KeyTypeECDSAP256,
	}
	if err := config.NormalizeCertificates([]config.Certificate{*cert}); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return store, m, fake, cert, dbPath
}

// dropTable removes one table through a second connection to the same database file.
func dropTable(t *testing.T, path, table string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open a second connection: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("DROP TABLE " + table); err != nil {
		t.Fatalf("drop %s: %v", table, err)
	}
}

// A failed order read must schedule the retry like every other failed decision.
//
// Reconcile's own comment promises that a decision which failed schedules the retry, and this path
// returned the bare store error: no ConsecutiveFailures, no NextAttemptAt, no in-memory transient
// backoff. A state store failing exactly this read was then invisible in
// wecert_certificate_consecutive_failures and retried at the pass rate.
func TestAFailedOrderReadSchedulesTheRetry(t *testing.T) {
	store, m, _, cert, dbPath := newDBFaultHarness(t)

	if err := store.PutCert(&state.CertState{
		Name:     cert.Name,
		NotAfter: time.Now().Add(60 * 24 * time.Hour),
		CertPEM:  selfSignedCertPEM(t, time.Now().Add(60*24*time.Hour), "example.com"),
	}); err != nil {
		t.Fatal(err)
	}
	dropTable(t, dbPath, "orders")

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("an unreadable order row must be reported as a failed pass")
	}
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st.ConsecutiveFailures == 0 {
		t.Error("the failure must be counted: without it the pass is invisible in " +
			"wecert_certificate_consecutive_failures")
	}
	if st.NextAttemptAt.IsZero() {
		t.Error("the failure must schedule a retry, otherwise the next pass repeats it immediately")
	}
}

// A backward clock step must not silence the binding check.
//
// `now.Sub(last) < interval` treats a NEGATIVE duration as "checked recently", so after the clock
// moved backwards every later pass skipped the binding lookup: DeployConfirmed stayed false, and
// because probeCert returns early for a certificate that is not confirmed deployed, the network
// probe never ran either. The certificate was unverified until the wall clock caught up with the
// stored instant. A future instant means the clock moved, not that a check just happened.
func TestABackwardClockStepDoesNotSilenceTheBindingCheck(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	if !m.bindingCheckDue(cert.Name) {
		t.Fatal("the first check is always due")
	}
	if m.bindingCheckDue(cert.Name) {
		t.Fatal("a second check in the same instant is not")
	}

	// The clock steps back an hour: the stored instant is now in the future.
	now = now.Add(-time.Hour)
	if !m.bindingCheckDue(cert.Name) {
		t.Error("a stored instant in the future must be treated as due: the alternative is that no " +
			"binding lookup runs until the clock catches up, so DeployConfirmed stays false and the " +
			"network probe never runs for this certificate")
	}

	// And the ordinary interval still applies after that.
	if m.bindingCheckDue(cert.Name) {
		t.Error("the check must not run on every pass")
	}
	_ = store
}
