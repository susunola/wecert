package acme

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// fakeDeployer implements only Bindings -- this file tests the "confirm binding" step.
type fakeDeployer struct {
	bindings int
	bindErr  error
	calls    int
}

func (f *fakeDeployer) Deploy(_ context.Context, _, oldID string, _, _ []byte) (string, error) {
	return oldID, nil
}
func (f *fakeDeployer) Delete(_ context.Context, _ string) error { return nil }
func (f *fakeDeployer) Bindings(_ context.Context, _ string) (int, error) {
	f.calls++
	return f.bindings, f.bindErr
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
	n, err := deploy.Noop{}.Bindings(context.Background(), "ap-whatever")
	if err != nil {
		t.Fatalf("Noop.Bindings should not fail: %v", err)
	}
	if n != 0 {
		t.Errorf("Noop.Bindings must always report 0, got %d", n)
	}
}
