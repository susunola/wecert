package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// ---------- test doubles ----------

// fakeSolver records every TXT write and cleanup so tests can assert that cleanup actually happened.
type fakeSolver struct {
	mu        sync.Mutex
	presented []string // "identifier|token"
	cleaned   []string // "identifier|keyAuth"
	cleanErr  error
}

func (f *fakeSolver) Present(_ context.Context, domain, token, keyAuth string) (DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.presented = append(f.presented, domain+"|"+token)
	return DNSRecord{FQDN: "_acme-challenge." + domain + ".", Value: "txt-" + token}, nil
}

func (f *fakeSolver) WaitAll(context.Context, []DNSRecord) error { return nil }

func (f *fakeSolver) CleanUp(_ context.Context, domain, token, keyAuth string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cleanErr != nil {
		return f.cleanErr
	}
	f.cleaned = append(f.cleaned, domain+"|"+keyAuth)
	return nil
}

func (f *fakeSolver) cleanCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cleaned)
}

// fakeKeyAuth mimics api.Core's key authorization computation.
type fakeKeyAuth struct{ err error }

func (f fakeKeyAuth) GetKeyAuthorization(token string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "keyauth(" + token + ")", nil
}

// ---------- harness ----------

func newTestManager(t *testing.T, solver challengeSolver, ka keyAuthProvider) (*Manager, *state.Store) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// core is nil: the paths these cases take (cleaning up leftover TXT) skip the ACME client.
	return newManager(store, nil, solver, ka, deploy.Noop{}, log), store
}

// seedOrderWithAuthzs builds the state "order + authorizations already presented to DNS".
func seedOrderWithAuthzs(t *testing.T, store *state.Store, certName string, authzs []*state.Authorization) {
	t.Helper()

	if err := store.PutOrder(&state.Order{
		CertName:    certName,
		OrderURL:    "https://acme.example/order/1",
		FinalizeURL: "https://acme.example/finalize/1",
		Status:      "ready",
		Identifiers: "a.example.com,b.example.com",
	}); err != nil {
		t.Fatalf("PutOrder: %v", err)
	}
	for _, a := range authzs {
		if err := store.PutAuthorization(a); err != nil {
			t.Fatalf("PutAuthorization: %v", err)
		}
	}
}

// ---------- leak regression: the core of this file ----------

// The worst leak path: the order is already ready, so advance goes straight to
// finalize -> download, and solveChallenges -- the only caller of cleanup -- is skipped
// entirely. At teardown discardOrder deletes the authorization rows; if it does not clear
// DNS first, those _acme-challenge records can never be reclaimed.
func TestDiscardOrderClearsTXTBeforeDeletingRows(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// The wildcard and the apex share one TXT name, but each authorization holds its own value.
	seedOrderWithAuthzs(t, store, "c", []*state.Authorization{
		{CertName: "c", AuthzURL: "authz-apex", Identifier: "example.com",
			ChallengeToken: "tok-apex", TxtName: "_acme-challenge.example.com.",
			TxtValue: "val-apex", Presented: true, ChallengeSent: true},
		{CertName: "c", AuthzURL: "authz-wild", Identifier: "*.example.com",
			ChallengeToken: "tok-wild", TxtName: "_acme-challenge.example.com.",
			TxtValue: "val-wild", Presented: true, ChallengeSent: true},
	})

	if err := m.discardOrder(context.Background(), "c"); err != nil {
		t.Fatalf("discardOrder: %v", err)
	}

	if got := solver.cleanCount(); got != 2 {
		t.Errorf("discardOrder must clear 2 TXT records first, got %d -- this leaks zombie records", got)
	}

	// Cleanup must use the keyAuth derived from each record's own token; never mix them up.
	want := map[string]bool{
		"example.com|keyauth(tok-apex)":   true,
		"*.example.com|keyauth(tok-wild)": true,
	}
	for _, c := range solver.cleaned {
		if !want[c] {
			t.Errorf("unexpected cleanup: %q", c)
		}
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("the following cleanups did not happen: %v", want)
	}

	// Both the order and the authorization rows must be removed, so the next round can
	// rebuild around the new domains.
	if o, err := store.GetOrder("c"); err != nil || o != nil {
		t.Errorf("order was not deleted: %+v, err=%v", o, err)
	}
	if as, err := store.ListAuthorizations("c"); err != nil || len(as) != 0 {
		t.Errorf("authorization rows were not deleted: %d remain, err=%v", len(as), err)
	}
}

// Self-heal: the state store still holds "presented to DNS" authorizations but no matching
// order (the previous teardown only half-succeeded, or the process was killed).
// Reconcile should reclaim them once it reaches this point.
func TestCleanupOrphanTXTReclaimsLeftovers(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// Only authorization rows, no order row -- that is exactly what "orphaned" means.
	for _, a := range []*state.Authorization{
		{CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
			ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.",
			TxtValue: "v1", Presented: true},
		{CertName: "c", AuthzURL: "authz-2", Identifier: "b.example.com",
			ChallengeToken: "tok-2", TxtName: "_acme-challenge.b.example.com.",
			TxtValue: "v2", Presented: true},
	} {
		if err := store.PutAuthorization(a); err != nil {
			t.Fatal(err)
		}
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}

	if got := solver.cleanCount(); got != 2 {
		t.Errorf("should reclaim 2 leftover TXT records, got %d", got)
	}
	if as, err := store.ListAuthorizations("c"); err != nil || len(as) != 0 {
		t.Errorf("authorization rows should be empty after reclaiming, got %d, err=%v", len(as), err)
	}
}

// An authorization never presented to DNS must not trigger any DNS call; just delete the row.
func TestCleanupOrphanTXTDoesNotTouchDNSForUnpresented(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
		Status: "pending", Presented: false,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("an authorization never presented to DNS must not trigger cleanup, but it ran %d times", got)
	}
	if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
		t.Errorf("an authorization never presented to DNS should be deleted, but %d rows remain", len(as))
	}
}

// A failed cleanup must not block discarding the order -- getting stuck on an order that
// can never finalize is far worse than one leftover TXT; drop the rows to avoid endless retries.
func TestDiscardOrderProceedsEvenIfCleanupFails(t *testing.T) {
	solver := &fakeSolver{cleanErr: errors.New("DNSPod is down")}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	seedOrderWithAuthzs(t, store, "c", []*state.Authorization{
		{CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
			ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.",
			Presented: true},
	})

	if err := m.discardOrder(context.Background(), "c"); err != nil {
		t.Fatalf("a failed cleanup must not make discardOrder return an error: %v", err)
	}
	if o, _ := store.GetOrder("c"); o != nil {
		t.Error("the order should have been discarded")
	}
}

// When the key authorization cannot be computed (e.g. the account is in a bad state) the whole
// round must not be dragged down, but cleanup must not be falsely reported as successful either.
func TestCleanupSkipsWhenKeyAuthFails(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{err: errors.New("no account private key")})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
		ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.", Presented: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("the error must not be propagated: %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("CleanUp must not be called when keyAuth fails, but it ran %d times", got)
	}

	// Crucial: Presented must stay true, otherwise this record can never be located again.
	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 {
		t.Fatalf("the authorization row must not be deleted while cleanup is incomplete, %d remain", len(as))
	}
	if !as[0].Presented {
		t.Error("Presented must stay true, otherwise the next run cannot locate that TXT record")
	}
}

// Without a token the record cannot even be located, so the authorization row must be
// **kept**: its TxtName is the only clue for cleaning up by hand in the DNS console.
func TestCleanupKeepsRowWhenTokenMissing(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
		ChallengeToken: "", TxtName: "_acme-challenge.a.example.com.", Presented: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("CleanUp must not be called when the token is missing, but it ran %d times", got)
	}

	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 {
		t.Fatalf("the authorization row must be kept when the record cannot be located, %d remain", len(as))
	}
	if as[0].TxtName == "" {
		t.Error("the kept row must still carry TxtName, otherwise manual cleanup is impossible")
	}
}

// A cleanup on the success path must persist Presented = false, so teardown does not clean up twice.
func TestCleanupMarksUnpresented(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	a := &state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
		ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.", Presented: true,
	}
	if err := store.PutAuthorization(a); err != nil {
		t.Fatal(err)
	}

	m.cleanup(context.Background(), "c", []*state.Authorization{a})

	if got := solver.cleanCount(); got != 1 {
		t.Fatalf("expected exactly 1 cleanup, got %d", got)
	}
	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].Presented {
		t.Errorf("Presented should have been persisted as false: %+v", as)
	}
}

// ---------- domain changes: deciding an order is stale ----------

// Once the configured domains change, an in-flight order's identifier set no longer matches.
// This must be detected, otherwise we keep advancing an order whose finalize is doomed to fail.
func TestOrderMatchesConfig(t *testing.T) {
	order := &state.Order{
		CertName:    "c",
		Identifiers: config.DomainKey([]string{"a.example.com", "b.example.com"}),
	}

	cases := []struct {
		name    string
		domains []string
		want    bool
	}{
		{"exact match", []string{"a.example.com", "b.example.com"}, true},
		{"different order still matches", []string{"b.example.com", "a.example.com"}, true},
		{"different case still matches", []string{"A.example.com", "B.example.com"}, true},
		{"domain added -> no match", []string{"a.example.com", "b.example.com", "c.example.com"}, false},
		{"domain removed -> no match", []string{"a.example.com"}, false},
		{"domain replaced -> no match", []string{"a.example.com", "z.example.com"}, false},
	}

	for _, tc := range cases {
		cfg := &config.Certificate{Name: "c", Domains: tc.domains}
		if got := orderMatchesConfig(order, cfg); got != tc.want {
			t.Errorf("%s: orderMatchesConfig = %v, want %v (domains=%v)",
				tc.name, got, tc.want, tc.domains)
		}
	}
}

// Orders persisted by older versions have no identifiers field. Be conservative here: one more
// round of advancing beats discarding an order just because the information is unavailable
// (a fresh order burns the "5 certs per exact set of identifiers / 7 days" rate-limit quota).
func TestLegacyOrderWithoutIdentifiersIsNotDiscarded(t *testing.T) {
	order := &state.Order{CertName: "c", Identifiers: ""}
	cfg := &config.Certificate{Name: "c", Domains: []string{"whatever.example.com"}}

	if !orderMatchesConfig(order, cfg) {
		t.Error("a legacy order with empty identifiers must not be judged as needing to be discarded")
	}
}

// ---------- domain drift detection ----------

func leafWith(names ...string) *x509.Certificate {
	return &x509.Certificate{DNSNames: names}
}

func TestCoverageDrift(t *testing.T) {
	cases := []struct {
		name    string
		leaf    []string
		want    []string
		drifted bool
	}{
		{"exact match", []string{"a.com", "b.com"}, []string{"a.com", "b.com"}, false},
		{"order does not matter", []string{"b.com", "a.com"}, []string{"a.com", "b.com"}, false},
		{"case does not matter", []string{"A.COM"}, []string{"a.com"}, false},
		{"domain added to config -> drift", []string{"a.com"}, []string{"a.com", "b.com"}, true},
		{"domain removed from config -> drift", []string{"a.com", "b.com"}, []string{"a.com"}, true},
		{"whole set replaced -> drift", []string{"old.com"}, []string{"new.com"}, true},
		{"wildcard and apex together", []string{"a.com", "*.a.com"}, []string{"a.com", "*.a.com"}, false},
	}

	for _, tc := range cases {
		drifted, detail := CoverageDrift(leafWith(tc.leaf...), tc.want)
		if drifted != tc.drifted {
			t.Errorf("%s: drifted = %v, want %v (detail=%q)",
				tc.name, drifted, tc.drifted, detail)
		}
		if drifted && detail == "" {
			t.Errorf("%s: drift must come with a readable difference description", tc.name)
		}
	}
}

// The detail must distinguish "missing" from "extra", so troubleshooting knows which way to look.
func TestCoverageDriftDetailPointsBothDirections(t *testing.T) {
	_, detail := CoverageDrift(
		leafWith("keep.com", "stale.com"),
		[]string{"keep.com", "fresh.com"},
	)

	for _, want := range []string{"fresh.com", "stale.com"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the difference description should mention %q, got: %q", want, detail)
		}
	}
}
