package acme

import (
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

// poisonCertRead makes store.GetCert fail while leaving every write to the row working:
// not_after is scanned into an int64, so a TEXT value breaks the read and nothing else.
// This is the same trick failAuthorizationWrites uses for the write side -- a fault the
// database itself produces, in the shape of a corrupt page.
func poisonCertRead(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open a second connection: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`UPDATE certificates SET not_after = 'corrupt'`); err != nil {
		t.Fatalf("poison the read: %v", err)
	}
	return db
}

// The P0 regression: Reconcile's first act is GetCert, and when that read fails the pass
// must record the failure WITHOUT touching the certificate material. The failure used to
// go through recordFailure with a CertState synthesised from nothing but the name, and
// PutCert's whole-row upsert then blanked cert_pem, key_pem, not_after, deployed_cert_id
// and ari_cert_id of the certificate currently in service.
func TestAFailedCertReadDoesNotEraseTheCertificateMaterial(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// core is nil on purpose: the read fails before any ACME call could be made.
	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{}, log)
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	// The row of a certificate that is live and serving.
	notAfter := now.Add(30 * 24 * time.Hour)
	certPEM := selfSignedCertPEM(t, notAfter, "example.com")
	keyPEM := []byte("the private key currently in service")
	if err := store.PutCert(&state.CertState{
		Name: "c", NotAfter: notAfter, CertURL: "https://ca.test/cert/1",
		CertPEM: certPEM, KeyPEM: keyPEM,
		ARICertID: "aki.serial", DeployedCertID: "deployed-1", DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}

	db := poisonCertRead(t, dbPath)
	if _, err := store.GetCert("c"); err == nil {
		t.Fatal("the fixture must break the certificate read, or this test proves nothing")
	}

	err = m.Reconcile(context.Background(), &config.Certificate{Name: "c", Domains: []string{"example.com"}})
	if err == nil || !strings.Contains(err.Error(), "read the certificate state") {
		t.Fatalf("the failed read must be the reported failure, got %v", err)
	}

	// GetCert is broken by the fixture, so the row is read back raw.
	var gotPEM, gotKey []byte
	var deployedID, ariCertID, lastError string
	var failures, nextAttempt int64
	if err := db.QueryRow(`SELECT cert_pem, key_pem, deployed_cert_id, ari_cert_id,
		consecutive_failures, next_attempt_at, last_error FROM certificates WHERE name = 'c'`).
		Scan(&gotPEM, &gotKey, &deployedID, &ariCertID, &failures, &nextAttempt, &lastError); err != nil {
		t.Fatalf("read the row back: %v", err)
	}

	if string(gotPEM) != string(certPEM) {
		t.Error("cert_pem was erased by recording a failure against an unreadable row")
	}
	if string(gotKey) != string(keyPEM) {
		t.Error("key_pem was erased by recording a failure against an unreadable row")
	}
	if deployedID != "deployed-1" || ariCertID != "aki.serial" {
		t.Errorf("deployed_cert_id / ari_cert_id were erased: %q / %q", deployedID, ariCertID)
	}

	// The failure bookkeeping is still written: the counter, the error and the backoff.
	if failures != 1 {
		t.Errorf("consecutive_failures = %d, want 1", failures)
	}
	if want := now.Add(time.Minute).Unix(); nextAttempt != want {
		t.Errorf("next_attempt_at = %d, want %d (the base backoff window)", nextAttempt, want)
	}
	if !strings.Contains(lastError, "read the certificate state") {
		t.Errorf("last_error = %q, want it to name the failed read", lastError)
	}

	// And once the read heals, the row is whole again: material plus the recorded failure.
	if _, err := db.Exec(`UPDATE certificates SET not_after = ?`, notAfter.Unix()); err != nil {
		t.Fatal(err)
	}
	st, err := store.GetCert("c")
	if err != nil {
		t.Fatalf("the row must be readable again once the poisoned column is restored: %v", err)
	}
	if st.ConsecutiveFailures != 1 || st.LastError == "" || len(st.CertPEM) == 0 || len(st.KeyPEM) == 0 {
		t.Errorf("the healed row must carry both the material and the recorded failure: %+v", st)
	}
}

// A stopped pass is not a business failure on this path either: no counter, no backoff.
func TestAFailedCertReadOnACancelledPassRecordsNothing(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	notAfter := time.Now().Add(30 * 24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name: "c", NotAfter: notAfter, CertPEM: selfSignedCertPEM(t, notAfter, "example.com"),
	}); err != nil {
		t.Fatal(err)
	}
	db := poisonCertRead(t, dbPath)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Reconcile(ctx, &config.Certificate{Name: "c", Domains: []string{"example.com"}}); err == nil {
		t.Fatal("the failed read must still be reported")
	}

	var failures int
	if err := db.QueryRow(`SELECT consecutive_failures FROM certificates WHERE name = 'c'`).
		Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 0 {
		t.Errorf("a cancelled pass must not count as a failure, got %d", failures)
	}
}
