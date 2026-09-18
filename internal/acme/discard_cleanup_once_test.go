package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// discardProbeHarness builds a certificate mid-lifetime with one stuck authorization row:
// the TXT probe errors, so reclaimUnpresentedTXT keeps the row and EVERY cleanupOrphanTXT
// pass over it costs one authoritative DNS lookup -- which is how the tests below count
// cleanups.
func discardProbeHarness(t *testing.T) (*Manager, *state.Store, *fakeSolver, *config.Certificate) {
	t.Helper()

	solver := &fakeSolver{lookupErr: errors.New("resolvers unreachable")}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// A live certificate far from its renewal window, so the pass ends at "not yet due"
	// rather than needing an ACME core (newTestManager leaves it nil).
	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutCert(&state.CertState{
		Name: "c", NotAfter: notAfter, CertPEM: selfSignedCertPEM(t, notAfter, "example.com"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", Presented: false,
	}); err != nil {
		t.Fatal(err)
	}

	cert := &config.Certificate{
		Name: "c", Domains: []string{"example.com"}, RenewBeforeDur: 30 * 24 * time.Hour,
	}
	return m, store, solver, cert
}

// discardOrder already runs cleanupOrphanTXT before deleting the order; a Reconcile branch
// that discards must not run it a second time on the way out. The duplicate pass re-probes
// every stuck row against the authoritative nameservers -- real DNS traffic, once per
// certificate per pass, for rows deliberately kept because the probe could not answer.
func TestDiscardingAnExpiredOrderDoesNotProbeTwice(t *testing.T) {
	m, store, solver, cert := discardProbeHarness(t)

	if err := store.PutOrder(&state.Order{
		CertName: "c", OrderURL: "https://ca.test/order/1", Status: "pending",
		ExpiresAt:   time.Now().Add(-time.Hour),
		Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("the expired order is discarded and renewal is not due: %v", err)
	}

	solver.mu.Lock()
	lookups := len(solver.lookups)
	solver.mu.Unlock()
	if lookups != 1 {
		t.Errorf("the stuck row was probed %d times in one pass; discardOrder already ran the "+
			"cleanup, so the wrap-up probe is a duplicate round of authoritative DNS traffic", lookups)
	}
	if o, _ := store.GetOrder("c"); o != nil {
		t.Error("the expired order must be discarded")
	}
	if as, _ := store.ListAuthorizations("c"); len(as) != 1 {
		t.Errorf("the stuck row must be KEPT (its token is the only clue to the record), %d remain", len(as))
	}
}

// The other discard branch -- the configured domains changed -- must not pay the duplicate
// either.
func TestDiscardingAStaleOrderDoesNotProbeTwice(t *testing.T) {
	m, store, solver, cert := discardProbeHarness(t)

	if err := store.PutOrder(&state.Order{
		CertName: "c", OrderURL: "https://ca.test/order/1", Status: "pending",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Identifiers: config.DomainKey([]string{"old.example.com"}),
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("the stale order is discarded and the live certificate matches the config: %v", err)
	}

	solver.mu.Lock()
	lookups := len(solver.lookups)
	solver.mu.Unlock()
	if lookups != 1 {
		t.Errorf("the stuck row was probed %d times in one pass; discardOrder already ran the "+
			"cleanup, so the wrap-up probe is a duplicate round of authoritative DNS traffic", lookups)
	}
	if o, _ := store.GetOrder("c"); o != nil {
		t.Error("the stale order must be discarded")
	}
}
