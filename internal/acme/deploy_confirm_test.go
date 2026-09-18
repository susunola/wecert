package acme

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // the driver the state store uses, for the second connection

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// fakeDeployer implements only Bindings -- this file tests the "confirm binding" step.
type fakeDeployer struct {
	bindings int
	// bindingsPartial makes the answer a lower bound: at least one region was not counted.
	bindingsPartial bool
	bindErr         error
	calls           int

	// deleted records the CertIds Delete was called with, and deleteErr makes it
	// fail, so the reclamation path can be pinned in both directions.
	deleted   []string
	deleteErr error
}

func (f *fakeDeployer) Deploy(_ context.Context, _, oldID string, _, _ []byte) (string, error) {
	return oldID, nil
}
func (f *fakeDeployer) Delete(_ context.Context, certID string) error {
	f.deleted = append(f.deleted, certID)
	return f.deleteErr
}
func (f *fakeDeployer) Bindings(_ context.Context, _ string) (int, bool, error) {
	f.calls++
	// complete defaults to true so the existing cases keep testing what they were written for; a
	// test that wants "at least one region went unanswered" sets it false.
	complete := true
	if f.bindingsPartial {
		complete = false
	}
	return f.bindings, complete, f.bindErr
}

// newConfirmHarness builds the state "issued and uploaded, binding not confirmed yet".
//
// The certificate is deliberately far from its renewal window and has no ARI, so
// Reconcile never touches the ACME client after the confirmation step -- a pure unit test.
func newConfirmHarness(
	t *testing.T, dep deploy.Deployer, mutate func(*state.CertState, *config.Certificate),
) (*Manager, *state.Store, *config.Certificate) {
	t.Helper()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, dep, log)

	cert := &config.Certificate{
		Name:    "confirm-test",
		Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic,
		Deploy:  config.Deploy{Enabled: true},
	}

	st := &state.CertState{
		Name:     cert.Name,
		NotAfter: time.Now().Add(80 * 24 * time.Hour),
		CertURL:  "https://acme.example/cert/1",
		CertPEM:  []byte("x"),
		KeyPEM:   []byte("x"),
		// The first issuance only uploads, so a CertId exists but DeployConfirmed is false.
		DeployedCertID:  "ap-uploaded",
		DeployConfirmed: false,
	}
	if mutate != nil {
		mutate(st, cert)
	}
	if err := store.PutCert(st); err != nil {
		t.Fatal(err)
	}

	return m, store, cert
}

// This is the heart of the fix: after a human binds it in the CLB console,
// convergence must set the flag on its own rather than wait up to 90 days for renewal.
func TestReconcileConfirmsBindingOnceBound(t *testing.T) {
	dep := &fakeDeployer{bindings: 2}
	m, store, cert := newConfirmHarness(t, dep, nil)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile should not fail: %v", err)
	}

	if dep.calls != 1 {
		t.Fatalf("should query the bindings once, got %d calls", dep.calls)
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !got.DeployConfirmed {
		t.Error("2 resources are bound, DeployConfirmed should be set")
	}
}

// Finding no binding is the normal "waiting for a human" state, not an error -- it must
// not count as a failure or enter exponential backoff, which would block it until bound.
func TestReconcileUnboundStaysUnconfirmedWithoutFailure(t *testing.T) {
	dep := &fakeDeployer{bindings: 0}
	m, store, cert := newConfirmHarness(t, dep, nil)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("an unbound certificate should not fail: %v", err)
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployConfirmed {
		t.Error("the flag should not be set when nothing is bound")
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("this is not a failure, so ConsecutiveFailures should be 0, got %d", got.ConsecutiveFailures)
	}
	if !got.NextAttemptAt.IsZero() {
		t.Errorf("this should not enter backoff, NextAttemptAt should be zero, got %s", got.NextAttemptAt)
	}
}

// A query failure must not hold up the renewal mainline: Reconcile still returns success.
func TestReconcileBindingQueryErrorDoesNotFailThePass(t *testing.T) {
	dep := &fakeDeployer{bindErr: errors.New("API blip")}
	m, store, cert := newConfirmHarness(t, dep, nil)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("a query failure should not fail the whole pass: %v", err)
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployConfirmed {
		t.Error("the flag should not be set when the query failed")
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("a confirmation failure is not a renewal failure, got %d", got.ConsecutiveFailures)
	}
}

// An already-confirmed certificate should not be queried on every convergence pass --
// that is a wasted API call, and once this is true it never flips back to false.
func TestReconcileSkipsQueryWhenAlreadyConfirmed(t *testing.T) {
	dep := &fakeDeployer{bindings: 3}
	m, _, cert := newConfirmHarness(t, dep, func(st *state.CertState, _ *config.Certificate) {
		st.DeployConfirmed = true
	})

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile should not fail: %v", err)
	}
	if dep.calls != 0 {
		t.Errorf("an already confirmed certificate should not query bindings again, queried %d times", dep.calls)
	}
}

// A certificate with deploy disabled is never uploaded, so there is nothing to confirm.
func TestReconcileSkipsQueryWhenDeployDisabled(t *testing.T) {
	dep := &fakeDeployer{bindings: 1}
	m, _, cert := newConfirmHarness(t, dep, func(st *state.CertState, c *config.Certificate) {
		c.Deploy.Enabled = false
		st.DeployedCertID = ""
	})

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile should not fail: %v", err)
	}
	if dep.calls != 0 {
		t.Errorf("bindings should not be queried when deploy is off, queried %d times", dep.calls)
	}
}

// Without a CertId the upload has not even happened yet, so there is nothing to query.
func TestReconcileSkipsQueryWhenNoCertID(t *testing.T) {
	dep := &fakeDeployer{bindings: 1}
	m, _, cert := newConfirmHarness(t, dep, func(st *state.CertState, _ *config.Certificate) {
		st.DeployedCertID = ""
	})

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile should not fail: %v", err)
	}
	if dep.calls != 0 {
		t.Errorf("bindings should not be queried without a CertId, queried %d times", dep.calls)
	}
}

// Confirmation must be persisted: a restart must not lose this conclusion, otherwise
// every restart falls back to "not deployed" -- and the metrics read exactly this flag.
func TestConfirmedBindingIsPersisted(t *testing.T) {
	dep := &fakeDeployer{bindings: 1}
	m, _, cert := newConfirmHarness(t, dep, nil)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	// Run one more pass: it is confirmed by now, so it must not query a second time.
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if dep.calls != 1 {
		t.Errorf("the flag must be persisted, so pass two must not query again; queried %d times total", dep.calls)
	}
}

// The Noop deployer (used when cloud deploy is off) must always report 0 and never fail.
func TestNoopDeployerReportsNoBindings(t *testing.T) {
	n, _, err := deploy.Noop{}.Bindings(context.Background(), "ap-whatever")
	if err != nil {
		t.Fatalf("Noop.Bindings should not fail: %v", err)
	}
	if n != 0 {
		t.Errorf("Noop.Bindings must always report 0, got %d", n)
	}
}

// ── reclamation: every uploaded CertId must end up somewhere ────────────────

// A certificate uploaded during a failed deploy is bound to nothing, so no later
// renewal will ever replace it: it occupies the account's uploaded-certificate
// quota until it is deleted. Recording it at the moment the deploy fails is the
// only thing that ever gets it back -- and losing that record is a slow,
// account-wide failure whose first symptom is "renewal stopped working".
func TestFailedDeployIsRecordedForReclaimAndThenReaped(t *testing.T) {
	dep := &fakeDeployer{}
	m, store, cert := newConfirmHarness(t, dep, nil)

	// The deploy failed after the upload, so the new CertId is an orphan.
	seedUploadedOrder(t, store, cert.Name, "ap-new", "ap-live")
	if err := m.discardOrder(context.Background(), cert.Name); err != nil {
		t.Fatalf("discarding an order that carries an uploaded certificate must record it: %v", err)
	}

	if got := listRetired(t, store, m, time.Hour); len(got) != 1 || got[0].CertID != "ap-new" {
		t.Fatalf("the orphaned certificate must be recorded for reclaim, got %+v", got)
	}

	// Inside the retention window nothing is deleted: that certificate is still the
	// rollback target if the new one goes wrong.
	m.ReapRetired(context.Background())
	if len(dep.deleted) != 0 {
		t.Fatalf("a certificate inside the retention window must not be deleted, got %v", dep.deleted)
	}

	// Past the window it is reclaimed, and the record goes with it so the next pass
	// does not attempt the same delete forever.
	base := time.Now()
	m.now = func() time.Time { return base.Add(2 * m.retention) }
	m.ReapRetired(context.Background())

	if len(dep.deleted) != 1 || dep.deleted[0] != "ap-new" {
		t.Fatalf("want the orphan deleted exactly once, got %v", dep.deleted)
	}
	if got := listRetired(t, store, m, 365*24*time.Hour); len(got) != 0 {
		t.Errorf("a reclaimed certificate must leave no record behind, got %+v", got)
	}
}

// A failed Delete must keep the record: the certificate still occupies quota, so
// the next pass has to try again.
func TestReapingKeepsTheRecordWhenDeleteFails(t *testing.T) {
	dep := &fakeDeployer{deleteErr: errors.New("API blip")}
	m, store, cert := newConfirmHarness(t, dep, nil)

	seedUploadedOrder(t, store, cert.Name, "ap-new", "ap-live")
	if err := m.discardOrder(context.Background(), cert.Name); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	m.now = func() time.Time { return base.Add(2 * m.retention) }
	m.ReapRetired(context.Background())

	if got := listRetired(t, store, m, 365*24*time.Hour); len(got) != 1 {
		t.Fatalf("a failed reclaim must leave the record for the next pass, got %+v", got)
	}
}

// Recording the certificate that is actually serving traffic would schedule the live certificate
// for deletion. Neither the live id nor "nothing was uploaded" may reach the reclaim list.
func TestDiscardingAnOrderNeverRetiresTheLiveCertificate(t *testing.T) {
	dep := &fakeDeployer{}
	m, store, cert := newConfirmHarness(t, dep, nil)

	// The order carries the id that is ALSO the live one.
	seedUploadedOrder(t, store, cert.Name, "ap-live", "ap-live")
	if err := m.discardOrder(context.Background(), cert.Name); err != nil {
		t.Fatal(err)
	}
	if got := listRetired(t, store, m, 365*24*time.Hour); len(got) != 0 {
		t.Fatalf("the live certificate must never be recorded for reclaim, got %+v", got)
	}

	// And an order that uploaded nothing at all.
	seedUploadedOrder(t, store, cert.Name, "", "ap-live")
	if err := m.discardOrder(context.Background(), cert.Name); err != nil {
		t.Fatal(err)
	}
	if got := listRetired(t, store, m, 365*24*time.Hour); len(got) != 0 {
		t.Fatalf("an order with no uploaded certificate must record nothing, got %+v", got)
	}
}

// listRetired reads the reclaim records further into the future than any retention
// window, so a record is returned whether or not it is due yet.
func listRetired(t *testing.T, store *state.Store, m *Manager, ahead time.Duration) []*state.RetiredCert {
	t.Helper()
	got, err := store.ListRetiredCertsBefore(m.now().Add(ahead))
	if err != nil {
		t.Fatalf("ListRetiredCertsBefore: %v", err)
	}
	return got
}

// The binding lookup must not run on every pass.
//
// Only a human can change the answer -- the certificate was uploaded but not yet bound in
// the console -- and the lookup is a two-call enumeration that polls asynchronously for
// up to 30 seconds, inside the serial convergence loop. An unbound certificate can sit
// that way for its whole 90-day life, so re-asking hourly is ~50-170 cloud calls a day
// for a fact that cannot have changed.
func TestBindingCheckIsThrottled(t *testing.T) {
	dep := &fakeDeployer{}
	m, _, _ := newConfirmHarness(t, dep, nil)

	m.bindingCheckEvery = time.Hour
	base := time.Now()
	m.now = func() time.Time { return base }

	if !m.bindingCheckDue("c") {
		t.Fatal("the first check must be due")
	}
	if m.bindingCheckDue("c") {
		t.Error("a second check inside the interval must be skipped, or every pass pays the enumeration")
	}

	// A different certificate has its own clock.
	if !m.bindingCheckDue("other") {
		t.Error("each certificate must be throttled independently")
	}

	base = base.Add(2 * time.Hour)
	if !m.bindingCheckDue("c") {
		t.Error("the check must become due again once the interval has passed")
	}
}

// The throttle has to be wired into the pass, not just available: five passes over an
// unconfirmed certificate must cost one enumeration, not five.
func TestReconcileLooksUpBindingsOncePerInterval(t *testing.T) {
	dep := &fakeDeployer{}
	m, _, cert := newConfirmHarness(t, dep, nil)

	m.bindingCheckEvery = time.Hour
	base := time.Now()
	m.now = func() time.Time { return base }

	for i := 0; i < 5; i++ {
		_ = m.Reconcile(context.Background(), cert)
	}
	if dep.calls != 1 {
		t.Errorf("Bindings ran %d times across 5 passes; want 1", dep.calls)
	}

	base = base.Add(2 * time.Hour)
	_ = m.Reconcile(context.Background(), cert)
	if dep.calls != 2 {
		t.Errorf("Bindings ran %d times; want a second lookup once the interval elapsed", dep.calls)
	}
}

// A reclaim record whose local delete fails must be retried, not wedged.
//
// The cloud delete already succeeded, so the certificate is gone from the account; what failed is
// only the local write that removes the row. The recorded trade (round 4 §3.2, "recorded, not
// changed") is that this is deliberately *not* treated as an error: the row stays, the pass warns,
// and the next pass issues the same Delete again. That second delete is idempotent -- Tencent's
// DeleteCertificate answers success for an id it does not hold -- so the row converges on the next
// pass instead of being stuck at "delete failed" forever.
//
// The write is made to fail at the SQL layer, which is the only place that reproduces "the cloud
// call worked and the disk write did not": a BEFORE DELETE trigger raises the error SQLite would
// raise on a full disk or a corrupt page, and the store's own error mapping turns it into the
// warning ReapRetired logs.
func TestAReclaimRecordWhoseLocalDeleteFailsIsRetriedTheNextPass(t *testing.T) {
	// Built here rather than through newConfirmHarness because the fault is injected through a
	// second connection to the same database file, so the test needs its path.
	dbPath := filepath.Join(t.TempDir(), "state.db")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dep := &fakeDeployer{}
	var logs bytes.Buffer
	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, dep,
		slog.New(slog.NewTextHandler(&logs, nil)))
	cert := &config.Certificate{
		Name: "reclaim-test", Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic, Deploy: config.Deploy{Enabled: true},
	}
	if err := store.PutCert(&state.CertState{Name: cert.Name, NotAfter: time.Now().Add(80 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// A reclaimed certificate, past the retention window.
	if err := store.AddRetiredCert("ap-orphan-1", cert.Name, nil, nil); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	m.SetNow(func() time.Time { return base.Add(2 * m.retention) })

	// The local write fails; the cloud call before it does not.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open the state database a second time: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TRIGGER refuse_reclaim_removal BEFORE DELETE ON retired_certificates
		BEGIN SELECT RAISE(ABORT, 'disk full (injected)'); END`); err != nil {
		t.Fatalf("install the failing write: %v", err)
	}

	// Pass one: the delete reaches the cloud, the record cannot be removed.
	m.ReapRetired(context.Background())
	if len(dep.deleted) != 1 || dep.deleted[0] != "ap-orphan-1" {
		t.Fatalf("the reaper must still issue the cloud delete, got %v", dep.deleted)
	}
	if got := listRetired(t, store, m, 365*24*time.Hour); len(got) != 1 {
		t.Fatalf("a failed local write must leave the record for the next pass, got %+v", got)
	}
	if !strings.Contains(logs.String(), "failed to remove the reclaim record") {
		t.Errorf("the failed write has to be reported, got:\n%s", logs.String())
	}

	// Pass two, with the database write still broken: the SAME id is deleted again and the pass
	// neither errors out nor drops the row.
	logs.Reset()
	m.ReapRetired(context.Background())
	if len(dep.deleted) != 2 || dep.deleted[1] != "ap-orphan-1" {
		t.Fatalf("the next pass must retry the same certificate id, got %v", dep.deleted)
	}
	if got := listRetired(t, store, m, 365*24*time.Hour); len(got) != 1 {
		t.Fatalf("the record must survive a failed removal, got %+v", got)
	}
	if !strings.Contains(logs.String(), "failed to remove the reclaim record") {
		t.Errorf("each pass has to warn while the write keeps failing, got:\n%s", logs.String())
	}

	// Once the disk recovers the next pass converges: the row goes, and no further delete is
	// issued for it -- so the retry is bounded by the outage, not permanent.
	if _, err := db.Exec(`DROP TRIGGER refuse_reclaim_removal`); err != nil {
		t.Fatal(err)
	}
	m.ReapRetired(context.Background())
	if len(dep.deleted) != 3 {
		t.Fatalf("the recovering pass still has to delete the record's certificate, got %v", dep.deleted)
	}
	if got := listRetired(t, store, m, 365*24*time.Hour); len(got) != 0 {
		t.Fatalf("a successful delete plus a successful write must clear the record, got %+v", got)
	}
	m.ReapRetired(context.Background())
	if len(dep.deleted) != 3 {
		t.Errorf("a cleared record must not be deleted again, got %v", dep.deleted)
	}
}

// seedUploadedOrder records an order that carries a certificate uploaded to the cloud, which is the
// shape a failed deploy leaves behind: the upload succeeded, the rebind did not.
func seedUploadedOrder(t *testing.T, store *state.Store, certName, uploadedID, liveID string) {
	t.Helper()
	if err := store.PutOrder(&state.Order{
		CertName: certName, OrderURL: "https://ca.test/order/1",
		FinalizeURL: "https://ca.test/finalize/1", Status: "pending",
		Identifiers: "a.example.com", DeploymentCertID: uploadedID,
	}); err != nil {
		t.Fatal(err)
	}
	if liveID == "" {
		return
	}
	if err := store.UpdateCert(certName, func(st *state.CertState) error {
		st.DeployedCertID = liveID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
