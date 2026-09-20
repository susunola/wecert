package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// ---------- test doubles ----------

// fakeSolver records every TXT write and cleanup so tests can assert that cleanup actually happened.
type fakeSolver struct {
	mu        sync.Mutex
	presented []string // "identifier|token"
	records   []DNSRecord
	lookups   []string // domains LookupTXT was asked about
	// lookupFound/lookupErr script LookupTXT: found means "the interrupted pass's record
	// is still up in DNS", which the idempotent-present and orphan-reclaim paths act on.
	lookupFound bool
	lookupErr   error
	// waitErr scripts a WaitAll failure ("the records never confirmed propagated"),
	// which is what the resumed-row re-verification path in solveChallenges reacts to.
	waitErr error
	// propagationTimeout is what PropagationTimeout reports, for the tests that exercise the
	// "was this write given time to appear" decision.
	propagationTimeout time.Duration
	cleaned            []string // "identifier|keyAuth"
	cleanErr           error
}

func (f *fakeSolver) Present(_ context.Context, domain, token, keyAuth string) (DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.presented = append(f.presented, domain+"|"+token)
	rec := DNSRecord{FQDN: "_acme-challenge." + domain + ".", Value: "txt-" + token}
	f.records = append(f.records, rec)
	return rec, nil
}

func (f *fakeSolver) WaitAll(context.Context, []DNSRecord) error { return f.waitErr }

// PropagationTimeout is the window the reclaim probe uses as its floor for trusting a denial; the
// fake takes it from the test that built it (see fakeSolver.propagationTimeout).
func (f *fakeSolver) PropagationTimeout() time.Duration {
	if f.propagationTimeout > 0 {
		return f.propagationTimeout
	}
	return 5 * time.Minute
}

func (f *fakeSolver) CleanUp(_ context.Context, domain, token, keyAuth string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cleanErr != nil {
		return f.cleanErr
	}
	f.cleaned = append(f.cleaned, domain+"|"+keyAuth)
	return nil
}

func (f *fakeSolver) LookupTXT(_ context.Context, domain, keyAuth string) (DNSRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, domain)
	if f.lookupErr != nil {
		return DNSRecord{}, false, f.lookupErr
	}
	return DNSRecord{FQDN: "_acme-challenge." + domain + ".", Value: "txt-lookup"}, f.lookupFound, nil
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

// ---------- the release path must hold the per-name mutex ----------

// Releasing a lease has to happen under the same per-name mutex CleanUp holds.
//
// Regression: releaseStaleLeaseExcept took only the registry lock, so its "is any other value
// still live?" check and its remove were not ordered against CleanUp's check-then-act. The two
// interleaved like this: CleanUp sees value B live, skips the delete-all and returns; this call
// then removes B's lease. Nothing is live and nobody is left to delete, so the record stays in
// DNS with no row and no lease pointing at it -- invisible to cleanupOrphanTXT, which walks the
// authorization rows, and poisoning every later order that writes the same challenge name.
func TestReleaseStaleLeaseTakesThePerNameMutex(t *testing.T) {
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	const fqdn = "_acme-challenge.example.com."
	const value = "value-a"

	m, _ := newTestManager(t, &fakeSolver{}, fakeKeyAuth{})

	// Hold the name's mutex the way CleanUp does: across the check and the provider call.
	mu, release := challengeLeases.lock(fqdn)
	defer release()
	mu.Lock()
	defer mu.Unlock()
	challengeLeases.add(fqdn, value)

	done := make(chan struct{})
	go func() {
		m.releaseStaleLease(fqdn, value)
		close(done)
	}()

	// It must wait for the mutex rather than release the lease underneath a live CleanUp.
	select {
	case <-done:
		t.Fatal("released a lease without holding the per-name mutex: it ran while CleanUp's " +
			"check-then-act was in flight")
	case <-time.After(150 * time.Millisecond):
	}

	mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the release never ran after the mutex was freed; it is deadlocked")
	}
	mu.Lock()
}

// ---------- leak regression: the core of this file ----------

// The worst leak path: the order is already ready, so advance goes straight to
// finalize -> download, and solveChallenges -- the only caller of cleanup -- is skipped
// entirely. At teardown discardOrder deletes the authorization rows; if it does not clear
// DNS first, those _acme-challenge records can never be reclaimed.
func TestDiscardOrderClearsTXTBeforeDeletingRows(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// The wildcard and the apex share one TXT name, but each authorization holds its own
	// value. Both identifiers are the bare apex: production stores `cur.Identifier.Value`
	// (manager_flow.go), and RFC 8555 section 7.1.3 forbids the "*." prefix there --
	// seeding "*.example.com" here would test a shape the store never actually contains.
	seedOrderWithAuthzs(t, store, "c", []*state.Authorization{
		{CertName: "c", AuthzURL: "authz-apex", Identifier: "example.com",
			ChallengeToken: "tok-apex", TxtName: "_acme-challenge.example.com.",
			TxtValue: "val-apex", Presented: true, ChallengeSent: true},
		{CertName: "c", AuthzURL: "authz-wild", Identifier: "example.com",
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
		"example.com|keyauth(tok-apex)": true,
		"example.com|keyauth(tok-wild)": true,
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
// can never finalize is far worse than one leftover TXT. The order goes away, but the
// authorization rows whose records could not be reclaimed are **kept**: they carry the
// only clue (token, TxtName) to the record's value, and cleanupOrphanTXT retries them on
// the next round.
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

	// The row behind the failed cleanup must survive, still Presented=true: dropping it
	// would orphan the record for good, because the row is the only clue to its value.
	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 {
		t.Fatalf("the row of an unreclaimed TXT must be kept for the next round, %d remain", len(as))
	}
	if !as[0].Presented {
		t.Error("the kept row must stay Presented, otherwise the next round cannot locate the record")
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

// A row that says Presented=false but carries a token is the fingerprint of a pass that
// died between the DNS write and the state persist: the record may still be up. Deleting
// the row blind would orphan that TXT for good, so cleanupOrphanTXT must probe first and
// reclaim what it finds.
func TestCleanupOrphanTXTProbesAndReclaimsInterruptedPass(t *testing.T) {
	solver := &fakeSolver{lookupFound: true}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", Presented: false,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if got := solver.cleanCount(); got != 1 {
		t.Errorf("the probed-and-found TXT must be reclaimed before the row goes away, got %d cleanups", got)
	}
	if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
		t.Errorf("the row should be deleted once its record is reclaimed, %d remain", len(as))
	}
}

// The same row with nothing in DNS under its value: the write genuinely never happened,
// so no DNS call and the row is deleted.
func TestCleanupOrphanTXTProbeMissDeletesRow(t *testing.T) {
	solver := &fakeSolver{lookupFound: false}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", Presented: false,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("a probe that finds nothing must not clean anything up, got %d", got)
	}
	if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
		t.Errorf("the row should be deleted when DNS provably holds no record, %d remain", len(as))
	}
}

// A denial inside the propagation window keeps the row WITHOUT calling it a failed reclaim.
//
// The row is the safety net for a write that may still be in flight, so it stays -- but this is a
// deliberate wait, not a cleanup failure, and the caller's summary must not say otherwise. It fired
// as a WARN in the round-11 production run: a pass that happened to run three minutes after an
// issuance printed "some TXT records could not be reclaimed automatically" for a record that was
// already gone from DNS, and only an Info line above it explained the truth.
func TestCleanupOrphanTXTKeepsAYoungUnpresentedRowQuietly(t *testing.T) {
	solver := &fakeSolver{lookupFound: false}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	prepared := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return prepared.Add(30 * time.Second) })

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", Presented: false, ChallengePreparedAt: prepared,
	}); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	m.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}

	if as, _ := store.ListAuthorizations("c"); len(as) != 1 {
		t.Fatalf("the row must be kept inside the propagation window, %d remain", len(as))
	}
	if strings.Contains(logs.String(), "could not be reclaimed automatically") {
		t.Errorf("a deliberate wait must not be reported as a failed reclaim:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "propagation window") {
		t.Errorf("the wait must still be explained at Info level:\n%s", logs.String())
	}

	// Past the window the same row is verified absent and deleted, with no warning either.
	m.SetNow(func() time.Time { return prepared.Add(10 * time.Minute) })
	logs.Reset()
	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
		t.Errorf("past the window a proven-absent record's row must go, %d remain", len(as))
	}
	if strings.Contains(logs.String(), "could not be reclaimed automatically") {
		t.Errorf("nothing failed here either:\n%s", logs.String())
	}
}

// A failed probe proves nothing either way: keep the row (its token is the only clue to
// the record's value) and let the next round retry.
func TestCleanupOrphanTXTProbeErrorKeepsRow(t *testing.T) {
	solver := &fakeSolver{lookupErr: errors.New("resolvers unreachable")}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", Presented: false,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("nothing may be cleaned up on a failed probe, got %d", got)
	}
	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 {
		t.Fatalf("the row must be kept while the record's fate is unknown, %d remain", len(as))
	}
	if as[0].ChallengeToken != "tok-1" {
		t.Error("the kept row must still carry the token, otherwise the record can never be located")
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

// CleanupOrphan is the seam the reconcile loop calls for a certificate that left the
// desired state mid-issuance, and until now only the fake manager on the other side of that
// seam was tested -- reconcile_test asserted "CleanupOrphan was called once" against a
// double, so the real implementation had no coverage at all.
//
// The ordering the method documents is the thing worth pinning: the TXT records must come
// down BEFORE the authorization rows go away, because those rows hold the only record of
// which names to delete.
func TestManagerCleanupOrphanReclaimsTXTThenRows(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "gone-cert", AuthzURL: "authz-1", Identifier: "a.example.com",
		ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.",
		TxtValue: "v1", Presented: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{
		CertName: "gone-cert", OrderURL: "https://ca.test/order/1", Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.CleanupOrphan(context.Background(), "gone-cert"); err != nil {
		t.Fatalf("CleanupOrphan: %v", err)
	}

	if got := solver.cleanCount(); got != 1 {
		t.Errorf("the leaked challenge TXT record must be reclaimed, cleanCount=%d", got)
	}
	if as, err := store.ListAuthorizations("gone-cert"); err != nil || len(as) != 0 {
		t.Errorf("authorization rows must be gone, got %d, err=%v", len(as), err)
	}
	if o, err := store.GetOrder("gone-cert"); err != nil || o != nil {
		t.Errorf("the order row must be gone, got %+v, err=%v", o, err)
	}
}

// A certificate with nothing in flight is a no-op, not an error: the reconcile loop calls
// this for every name that leaves the desired state, including ones that never issued.
func TestManagerCleanupOrphanIsANoOpWithNothingInFlight(t *testing.T) {
	solver := &fakeSolver{}
	m, _ := newTestManager(t, solver, fakeKeyAuth{})

	if err := m.CleanupOrphan(context.Background(), "never-issued"); err != nil {
		t.Fatalf("CleanupOrphan on a certificate with no order and no authorizations must be a no-op, got %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("no DNS call belongs in a no-op cleanup, got %d", got)
	}
}

// hasTXTLease reports whether the registry still holds this exact value at this name.
//
// A non-destructive read on purpose: remove() answers "is another value still live", which is false
// both when the lease was released and when it was the last one, so it cannot tell the two apart.
func hasTXTLease(fqdn, value string) bool {
	challengeLeases.mu.Lock()
	defer challengeLeases.mu.Unlock()
	e := challengeLeases.entries[fqdn]
	return e != nil && e.values[value]
}

// privateLeaseRegistry gives one test its own registry, so its assertions do not depend on what
// other tests in this package left behind.
func privateLeaseRegistry(t *testing.T) {
	t.Helper()
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })
}

// A record proven absent must have its lease released.
//
// The registry holds a value until someone removes it, and while one is held every later cleanup at
// the name takes the "another challenge is still live" branch -- so the provider's delete-EVERY-TXT
// call never fires again for the rest of the process and every record written at that name
// afterwards stays in DNS until a restart. A probe that every reachable authority answered "no such
// value" is exactly the evidence that the lease is dead, and it is the same evidence the row
// deletion already rests on.
func TestAProvenAbsentRecordReleasesItsLease(t *testing.T) {
	privateLeaseRegistry(t)

	// The authority denies the record, which is what licenses deleting the row.
	solver, rec, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			resp := dnsReply(msg)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			return resp, nil
		})
	solver.newProvider = func(context.Context) (challenge.Provider, error) {
		return &recordingProvider{}, nil
	}

	// The value this row's token hashes to -- which is what the probe searches for and what an
	// interrupted Present registered.
	value := dns01.GetChallengeInfo("example.com", "keyauth(tok-1)").Value

	m, store := newTestManager(t, solver, fakeKeyAuth{})
	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", TxtName: rec.FQDN, TxtValue: value, Presented: false,
	}); err != nil {
		t.Fatal(err)
	}
	// What the interrupted Present left behind in this process.
	challengeLeases.add(rec.FQDN, value)
	if !hasTXTLease(rec.FQDN, value) {
		t.Fatal("the fixture must register the lease it is about to check")
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}

	if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
		t.Fatalf("the row is deleted on this evidence, so this test is not exercising the release: %d remain", len(as))
	}
	if hasTXTLease(rec.FQDN, value) {
		t.Error("the lease of a record proven absent must be released; while it is held, every later " +
			"cleanup at this name defers the provider's delete-all and no record written here is ever " +
			"collected again for the lifetime of this process")
	}
}

// A row repointed at a fresh challenge token must release the record its old token owned.
//
// This is the other half of the same leak, and the one the code next to it already worried about:
// after the token is refreshed, CleanUp derives a value the row no longer uses, so the old value's
// lease is never matched by any removal and stays in the registry forever. The record it stands for
// is not the new challenge's, so nothing later can collect it either.
func TestARefreshedChallengeTokenReleasesTheOldRecordsLease(t *testing.T) {
	privateLeaseRegistry(t)

	solver, _, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			// No record at the name yet: the pass writes the new value.
			resp := dnsReply(msg)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			return resp, nil
		})
	provider := &recordingProvider{}
	solver.newProvider = func(context.Context) (challenge.Provider, error) { return provider, nil }
	// The propagation wait is not what this test is about, and a zero budget fails it immediately
	// instead of spending the real one.
	solver.timeout = time.Millisecond

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	m := newManager(store, &fakeAPI{}, solver, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// The row as a failed propagation left it: the challenge written by an earlier round this
	// process ran, with its token and the value that token hashed to.
	oldValue := dns01.GetChallengeInfo("example.com", "keyauth(tok-1)").Value
	oldName := dns.Fqdn(dns01.GetChallengeInfo("example.com", "keyauth(tok-1)").EffectiveFQDN)
	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "https://ca.test/authz/1", Identifier: "example.com",
		ChallengeToken: "tok-1", TxtName: oldName, TxtValue: oldValue, Presented: false,
	}); err != nil {
		t.Fatal(err)
	}
	challengeLeases.add(oldName, oldValue)

	// The CA now offers a different challenge for the same authorization.
	fake := m.core.(*fakeAPI)
	fake.authzByURL = map[string]legoacme.Authorization{
		"https://ca.test/authz/1": {
			Status:     "pending",
			Identifier: legoacme.Identifier{Value: "example.com"},
			Challenges: []legoacme.Challenge{{
				Type: "dns-01", URL: "https://ca.test/chall/2", Token: "tok-2",
			}},
		},
	}

	st := &state.CertState{Name: "c"}
	cert := &config.Certificate{Name: "c", Domains: []string{"example.com"}}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
		Location: "https://ca.test/order/1",
	}
	// Whatever the propagation wait then decides, the refresh branch has run by the time this
	// returns.
	_, _ = m.solveChallenges(context.Background(), cert, st, order)

	if hasTXTLease(oldName, oldValue) {
		t.Error("a refreshed challenge token must release the lease of the record the old token " +
			"owned; otherwise every later cleanup at this name defers the provider's delete-all for " +
			"the rest of the process and the old record can never be collected")
	}
	if len(provider.presents) == 0 {
		t.Error("the new challenge must still be written: releasing a lease must not skip the write")
	}
}

// A value another presented row still claims must keep its lease.
//
// The release is only sound because of this check: a value can be dead for the row that is giving
// it up and still be the record a different certificate at the same name is waiting on, and
// dropping that lease would let the next cleanup's delete-EVERY-TXT call take out a record the CA
// is about to validate -- a billed authorization failure against the per-identifier limit.
func TestAStaleLeaseIsKeptWhileAnotherPresentedRowClaimsIt(t *testing.T) {
	privateLeaseRegistry(t)

	m, store := newTestManager(t, &fakeSolver{}, fakeKeyAuth{})

	const fqdn = "_acme-challenge.example.com."
	const value = "shared-value"
	challengeLeases.add(fqdn, value)

	// A different certificate's presented row still needs exactly this record.
	if err := store.PutAuthorization(&state.Authorization{
		CertName: "other", AuthzURL: "authz-other", Identifier: "example.com",
		ChallengeToken: "tok-2", TxtName: fqdn, TxtValue: value, Presented: true,
	}); err != nil {
		t.Fatal(err)
	}
	m.releaseStaleLease(fqdn, value)
	if !hasTXTLease(fqdn, value) {
		t.Fatal("a presented row still claims this record: releasing its lease lets the next cleanup " +
			"delete a record another certificate is waiting to be validated on")
	}

	// Once that row is gone the value is nobody's, and the lease must go.
	if err := store.DeleteAuthorization("other", "authz-other"); err != nil {
		t.Fatal(err)
	}
	m.releaseStaleLease(fqdn, value)
	if hasTXTLease(fqdn, value) {
		t.Error("no presented row claims the value any more, so a lease that is never released keeps " +
			"the name un-cleanable for the rest of the process")
	}
}

// A closed authorization must end the order, not be polled to the order's TTL.
//
// RFC 8555 section 7.1.6 defines deactivated, expired and revoked as closed: they can never become
// valid, so the order carrying one can never be finalized. With no case for them the pass treated
// the status as pending and re-presented a challenge (a real TXT write plus a propagation wait),
// POSTed AcceptChallenge for a closed authorization and polled it for the whole authzWait -- every
// pass, until the order's own 7-day TTL ran out. Discarding the order makes the next pass place a
// fresh one; no identifier failure is booked, because nothing about the name failed validation.
func TestAClosedAuthorizationDiscardsTheOrder(t *testing.T) {
	for _, status := range []string{"deactivated", "expired", "revoked"} {
		t.Run(status, func(t *testing.T) {
			solver := &fakeSolver{}
			store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })

			fake := &fakeAPI{authzByURL: map[string]legoacme.Authorization{
				"https://ca.test/authz/1": {
					Status:     status,
					Identifier: legoacme.Identifier{Value: "example.com"},
				},
			}}
			m := newManager(store, fake, solver, fakeKeyAuth{}, deploy.Noop{},
				slog.New(slog.NewTextHandler(io.Discard, nil)))

			if err := store.PutOrder(&state.Order{
				CertName: "c", OrderURL: "https://ca.test/order/1",
				FinalizeURL: "https://ca.test/finalize/1", Status: "pending",
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.PutAuthorization(&state.Authorization{
				CertName: "c", AuthzURL: "https://ca.test/authz/1", Identifier: "example.com",
			}); err != nil {
				t.Fatal(err)
			}

			cert := &config.Certificate{Name: "c", Domains: []string{"example.com"}}
			st := &state.CertState{Name: "c", NotAfter: time.Now().Add(24 * time.Hour)}
			order := legoacme.ExtendedOrder{
				Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
				Location: "https://ca.test/order/1",
			}

			done, err := m.solveChallenges(context.Background(), cert, st, order)
			if err == nil {
				t.Fatal("a closed authorization means the order cannot complete, so the pass must fail")
			}
			if done {
				t.Error("the pass must not report the challenges as solved")
			}
			if !strings.Contains(err.Error(), status) {
				t.Errorf("the error must name the status, got %v", err)
			}
			if o, err := store.GetOrder("c"); err != nil || o != nil {
				t.Errorf("the order must be discarded so the next pass places a fresh one (order=%+v err=%v)", o, err)
			}
			// Nothing about the name failed validation, so the identifier ledger must stay empty:
			// a booked failure would arm the pre-expiry fallback against a healthy identifier.
			if fails, err := store.ListIdentifierFailures("c"); err != nil {
				t.Fatal(err)
			} else if len(fails) != 0 {
				t.Errorf("no identifier failure belongs here, got %+v", fails)
			}
			if len(solver.presented) != 0 {
				t.Errorf("nothing may be written to DNS for a closed authorization, got %v", solver.presented)
			}
		})
	}
}

// A denial inside the propagation window is not proof that nothing was written.
//
// reclaimUnpresentedTXT exists for the pass that died between the DNS write and the state persist --
// but the same row shape appears for the pass that died between persisting the challenge and
// writing DNS, and the record alone cannot tell them apart. Deleting the row on a denial drops the
// only clue to a record that is about to appear, which then stays in DNS and can poison a later
// challenge at the same name (a wildcard and its apex share one). DNSPod's authoritative servers
// lag the API write -- measured at up to ~60s for a deletion this session -- so inside the
// propagation window the denial proves nothing.
func TestADenialInsideThePropagationWindowKeepsTheRow(t *testing.T) {
	const fqdn = "_acme-challenge.example.com."

	newHarnessFor := func(t *testing.T) (*Manager, *state.Store, *fakeSolver) {
		t.Helper()
		solver := &fakeSolver{lookupFound: false, propagationTimeout: 5 * time.Minute}
		m, store := newTestManager(t, solver, fakeKeyAuth{})
		m.SetNow(func() time.Time { return time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC) })
		return m, store, solver
	}

	t.Run("challenge prepared moments ago", func(t *testing.T) {
		m, store, _ := newHarnessFor(t)

		now := m.now()
		if err := store.PutAuthorization(&state.Authorization{
			CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
			ChallengeToken: "tok-1", TxtName: fqdn, TxtValue: "txt-lookup", Presented: false,
			ChallengePreparedAt: now.Add(-10 * time.Second),
		}); err != nil {
			t.Fatal(err)
		}

		if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
			t.Fatalf("cleanupOrphanTXT: %v", err)
		}
		if as, _ := store.ListAuthorizations("c"); len(as) != 1 {
			t.Errorf("the row must be kept: the write may still be propagating, and the row is the "+
				"only record of the value (rows now: %d)", len(as))
		}
	})

	t.Run("challenge prepared long ago", func(t *testing.T) {
		m, store, _ := newHarnessFor(t)

		now := m.now()
		if err := store.PutAuthorization(&state.Authorization{
			CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
			ChallengeToken: "tok-1", TxtName: fqdn, TxtValue: "txt-lookup", Presented: false,
			ChallengePreparedAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatal(err)
		}

		if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
			t.Fatalf("cleanupOrphanTXT: %v", err)
		}
		if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
			t.Errorf("past the propagation window a denial IS evidence the write never happened, so "+
				"the row must be deleted rather than kept forever (rows now: %d)", len(as))
		}
	})

	t.Run("row predates the column", func(t *testing.T) {
		m, store, _ := newHarnessFor(t)

		if err := store.PutAuthorization(&state.Authorization{
			CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
			ChallengeToken: "tok-1", TxtName: fqdn, TxtValue: "txt-lookup", Presented: false,
		}); err != nil {
			t.Fatal(err)
		}

		if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
			t.Fatalf("cleanupOrphanTXT: %v", err)
		}
		if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
			t.Errorf("a row with no timestamp has an unknown age, so the previous behaviour must "+
				"stand -- refusing to delete those would strand every legacy row (rows now: %d)", len(as))
		}
	})
}

// Choosing a challenge must record when it was chosen.
//
// reclaimUnpresentedTXT uses that age to decide whether an authoritative denial may be trusted: a
// challenge picked moments ago may simply not have propagated yet, and deleting the row then drops
// the only clue to a record that is about to appear. A row written without the timestamp would fall
// back to trusting every denial, which is the behaviour the window exists to replace.
func TestChoosingAChallengeRecordsWhenItWasChosen(t *testing.T) {
	privateLeaseRegistry(t)

	solver, _, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			resp := dnsReply(msg)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			return resp, nil
		})
	solver.newProvider = func(context.Context) (challenge.Provider, error) {
		return &recordingProvider{}, nil
	}
	solver.timeout = time.Millisecond

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	m := newManager(store, &fakeAPI{}, solver, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	fake := m.core.(*fakeAPI)
	fake.authzByURL = map[string]legoacme.Authorization{
		"https://ca.test/authz/1": {
			Status:     "pending",
			Identifier: legoacme.Identifier{Value: "example.com"},
			Challenges: []legoacme.Challenge{{
				Type: "dns-01", URL: "https://ca.test/chall/1", Token: "tok-1",
			}},
		},
	}

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "https://ca.test/authz/1", Identifier: "example.com",
	}); err != nil {
		t.Fatal(err)
	}

	cert := &config.Certificate{Name: "c", Domains: []string{"example.com"}}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
		Location: "https://ca.test/order/1",
	}
	_, _ = m.solveChallenges(context.Background(), cert, &state.CertState{Name: "c"}, order)

	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 {
		t.Fatalf("expected one authorization row, got %d", len(as))
	}
	if as[0].ChallengeURL == "" {
		t.Fatalf("the fixture must have picked a challenge: %+v", as[0])
	}
	if !as[0].ChallengePreparedAt.Equal(now) {
		t.Errorf("the row must record when the challenge was chosen, got %s want %s",
			as[0].ChallengePreparedAt, now)
	}
}

// A row whose token no longer hashes to its persisted value must not block its own cleanup.
//
// The registry has two writers for one row: registerRecoveredLeases registers the row's PERSISTED
// txt_value (that is the value recorded as being in DNS), while CleanUp removes the value derived
// from the challenge_token (that is what lego's provider deletes by). For a row written before the
// token was refreshed -- the shape removeAuthzTXT's own comment describes as real -- the two
// differ, so the lease that went in could never come out: every later cleanup at that name took the
// "another challenge is still live" branch, the provider's delete-all never fired again for the
// process lifetime, and the record that row owned stayed in DNS, consuming record quota and
// poisoning later challenges at the same name.
func TestARowWhoseTokenChangedDoesNotBlockItsOwnCleanup(t *testing.T) {
	privateLeaseRegistry(t)

	solver, rec, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			resp := dnsReply(msg)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			return resp, nil
		})
	provider := &recordingProvider{}
	solver.newProvider = func(context.Context) (challenge.Provider, error) { return provider, nil }
	solver.timeout = time.Millisecond

	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// The legacy shape: the row carries the value an older build wrote, while its token now hashes
	// to something else.
	staleValue := dns01.GetChallengeInfo("example.com", "keyauth(tok-old)").Value
	derived := dns01.GetChallengeInfo("example.com", "keyauth(tok-1)").Value
	if staleValue == derived {
		t.Fatal("the fixture must have two different values")
	}
	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", TxtName: rec.FQDN, TxtValue: staleValue, Presented: true,
	}); err != nil {
		t.Fatal(err)
	}
	// What a previous process would have registered for it.
	challengeLeases.add(rec.FQDN, staleValue)

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}

	if len(provider.cleanups) != 1 {
		t.Errorf("the provider's delete-all must fire: the only lease left at the name was this "+
			"row's own stale value, and holding it back leaves the record in DNS for the life of "+
			"the process (cleanups=%v)", provider.cleanups)
	}
	if hasTXTLease(rec.FQDN, staleValue) {
		t.Error("the row's stale lease must be released before its own cleanup runs")
	}
}

// The challenge's timestamp must be on disk before the DNS write it describes.
//
// A resumed row (Presented=false, a token from an earlier attempt) had the new challenge and the
// refreshed challenge_prepared_at only in memory until the end of the loop: a pass that died
// between the DNS write and that persist left a stored age OLDER than the write, and the reclaim
// probe -- which trusts an authoritative denial once the stored age exceeds the propagation window
// -- could then delete the row of a record that was still propagating, leaving the record in DNS.
// The first-visit path always persisted first; now both do.
func TestTheChallengeIsPersistedBeforeTheDNSWrite(t *testing.T) {
	privateLeaseRegistry(t)

	// The provider is installed below; the harness deliberately leaves newProvider nil so that a
	// test that forgets to install one fails loudly instead of silently writing to real DNS.
	solver, _, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			resp := dnsReply(msg)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			return resp, nil
		})
	solver.timeout = time.Millisecond

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{authzByURL: map[string]legoacme.Authorization{
		"https://ca.test/authz/1": {
			Status:     "pending",
			Identifier: legoacme.Identifier{Value: "example.com"},
			Challenges: []legoacme.Challenge{{
				Type: "dns-01", URL: "https://ca.test/chall/2", Token: "tok-2",
			}},
		},
	}}
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	old := now.Add(-30 * time.Minute)
	provider := &recordingProvider{}
	solver.newProvider = func(context.Context) (challenge.Provider, error) { return provider, nil }
	hookRan := false
	provider.onPresent = func() {
		hookRan = true
		// What is on disk at the moment the DNS write starts.
		stored, err := store.ListAuthorizationsForTest("c")
		if err != nil {
			t.Errorf("reading the row from inside Present: %v", err)
			return
		}
		if len(stored) != 1 {
			t.Errorf("expected one authorization row, got %d", len(stored))
			return
		}
		if !stored[0].ChallengePreparedAt.Equal(now) {
			t.Errorf("the row's challenge timestamp must be on disk before the DNS write, got %s "+
				"(the previous value was %s)", stored[0].ChallengePreparedAt, old)
		}
	}

	m := newManager(store, fake, solver, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.SetNow(func() time.Time { return now })

	// The resumed shape: a token from an earlier attempt, unpresented, with a stale timestamp.
	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "https://ca.test/authz/1", Identifier: "example.com",
		ChallengeToken: "tok-1", Presented: false, ChallengePreparedAt: old,
	}); err != nil {
		t.Fatal(err)
	}

	cert := &config.Certificate{Name: "c", Domains: []string{"example.com"}}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
		Location: "https://ca.test/order/1",
	}
	_, _ = m.solveChallenges(context.Background(), cert, &state.CertState{Name: "c"}, order)

	// Every assertion above runs inside the hook, so a fixture that never reaches the DNS write
	// would make this test pass without checking anything. The test-quality review caught exactly
	// that: replacing the pass's Present call with a local value kept it green.
	if !hookRan {
		t.Fatal("the fixture never reached the DNS write, so nothing above was asserted")
	}
}

// A first visit must persist the challenge before the DNS write too.
//
// This is the ordering the round-5 comment calls load-bearing: a pass that dies between the write
// and the end-of-loop persist leaves a record in DNS that only the row's token can locate, and on a
// first visit there is no earlier row to inherit a token from -- so if the row is not written
// first, the record is unfindable from the moment it exists. Deleting the firstVisit persist left
// the whole package green before this test existed.
func TestTheFirstVisitChallengeIsPersistedBeforeTheDNSWrite(t *testing.T) {
	privateLeaseRegistry(t)

	solver, _, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			resp := dnsReply(msg)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			return resp, nil
		})
	solver.timeout = time.Millisecond

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{authzByURL: map[string]legoacme.Authorization{
		"https://ca.test/authz/1": {
			Status:     "pending",
			Identifier: legoacme.Identifier{Value: "example.com"},
			Challenges: []legoacme.Challenge{{
				Type: "dns-01", URL: "https://ca.test/chall/1", Token: "tok-1",
			}},
		},
	}}
	m := newManager(store, fake, solver, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	hookRan := false
	solver.newProvider = func(context.Context) (challenge.Provider, error) {
		return &recordingProvider{onPresent: func() {
			hookRan = true
			stored, err := store.ListAuthorizationsForTest("c")
			if err != nil {
				t.Errorf("reading the row from inside Present: %v", err)
				return
			}
			if len(stored) != 1 {
				t.Errorf("the challenge has to be on disk before the record it describes: found %d rows",
					len(stored))
				return
			}
			if stored[0].ChallengeToken != "tok-1" {
				t.Errorf("the row must name the challenge being written, got token %q",
					stored[0].ChallengeToken)
			}
			if stored[0].Presented {
				t.Error("nothing has been confirmed presented at the moment of the write")
			}
			if !stored[0].ChallengePreparedAt.Equal(now) {
				t.Errorf("the challenge's age must be on disk with it, got %s want %s",
					stored[0].ChallengePreparedAt, now)
			}
		}}, nil
	}

	// Nothing in the store: this is a first visit, so there is no earlier token to inherit.
	cert := &config.Certificate{Name: "c", Domains: []string{"example.com"}}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
		Location: "https://ca.test/order/1",
	}
	_, _ = m.solveChallenges(context.Background(), cert, &state.CertState{Name: "c"}, order)

	if !hookRan {
		t.Fatal("the fixture never reached the DNS write, so nothing above was asserted")
	}
}

// refusingProvider refuses every write, so a pass stops between selecting the challenge and the
// record existing. Its CleanUp records calls, which is how a test sees whether the leftover record
// was reclaimed.
type refusingProvider struct {
	cleanups []string
}

func (p *refusingProvider) Present(string, string, string) error {
	return errors.New("DNSPod API: CreateRecord refused")
}

func (p *refusingProvider) CleanUp(domain, token, _ string) error {
	p.cleanups = append(p.cleanups, domain+"|"+token)
	return nil
}

// A failed write on the revisit path must not overwrite the clue to the record already in DNS.
//
// A resumed row (Presented=false, a token from an earlier attempt) carries the only pointer to the
// TXT record that attempt wrote: reclaimUnpresentedTXT derives the value it probes for from the
// row's token. The challenge this pass picked can be a different one -- the code says so itself,
// which is why releaseStaleLease and releaseRowStaleLease exist -- and then persisting the new
// token before the write means an ordinary DNSPod failure (no crash needed) leaves the old record
// with nothing naming it: recovery probes the new value, is authoritatively denied, drops the row,
// and the TXT stays in DNS for the rest of the certificate's life. The refreshed challenge age is
// still persisted first, because that is what bounds how early a denial may be trusted.
func TestAFailedWriteOnTheRevisitPathKeepsTheTokenThatNamesTheRecord(t *testing.T) {
	privateLeaseRegistry(t)

	oldValue := dns01.GetChallengeInfo("example.com", "keyauth(tok-1)").Value
	newValue := dns01.GetChallengeInfo("example.com", "keyauth(tok-2)").Value
	if oldValue == newValue {
		t.Fatal("the fixture needs two different challenge values")
	}

	// The authority holds exactly the record the interrupted attempt wrote, and serves it for every
	// query, so a probe for the new value is denied. (The harness's third argument is the value of
	// its own fixture, not the value the probe asks about, so it must not decide the answer.)
	solver, rec, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			return authTXT(msg, oldValue), nil
		})
	provider := &refusingProvider{}
	solver.newProvider = func(context.Context) (challenge.Provider, error) { return provider, nil }
	solver.timeout = time.Minute

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{authzByURL: map[string]legoacme.Authorization{
		"https://ca.test/authz/1": {
			Status:     "pending",
			Identifier: legoacme.Identifier{Value: "example.com"},
			Challenges: []legoacme.Challenge{{
				Type: "dns-01", URL: "https://ca.test/chall/2", Token: "tok-2",
			}},
		},
	}}
	m := newManager(store, fake, solver, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })
	preparedAgo := now.Add(-30 * time.Minute)

	// What an interrupted attempt leaves behind: the record it wrote, named by its token, and a row
	// that says the record was never confirmed as presented.
	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "https://ca.test/authz/1", Identifier: "example.com",
		ChallengeToken: "tok-1", TxtName: rec.FQDN, TxtValue: oldValue,
		Presented: false, ChallengePreparedAt: preparedAgo,
	}); err != nil {
		t.Fatal(err)
	}

	cert := &config.Certificate{Name: "c", Domains: []string{"example.com"}}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
		Location: "https://ca.test/order/1",
	}
	if _, err := m.solveChallenges(context.Background(), cert, &state.CertState{Name: "c"}, order); err == nil {
		t.Fatal("the provider refuses every write, so the pass must fail")
	}

	rows, err := store.ListAuthorizationsForTest("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected the row to survive the failed pass, got %d", len(rows))
	}
	if rows[0].ChallengeToken != "tok-1" {
		t.Errorf("the failed pass overwrote the token that names the record still in DNS: the row "+
			"names %q, but the only TXT at %s is the value tok-1 wrote (%q), and the token is the "+
			"only clue that locates it", rows[0].ChallengeToken, rec.FQDN, oldValue)
	}
	if !rows[0].ChallengePreparedAt.Equal(now) {
		t.Errorf("the refreshed challenge age must be on disk even when the write fails (that is "+
			"what keeps a denial from being trusted too early), got %s, want %s",
			rows[0].ChallengePreparedAt, now)
	}
	if rows[0].Presented {
		t.Error("nothing was written, so the row must not claim a record was presented")
	}

	// A later round, past the propagation window: recovery has to be able to find the record the row
	// names -- and a denial of the WRONG value must not be read as "there is nothing there".
	now = now.Add(2 * time.Hour)
	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if len(provider.cleanups) != 1 {
		t.Errorf("the record %s (value %q, written by tok-1) must still be reclaimed: the provider's "+
			"delete-all ran %d times, so it stays in DNS with no row naming it",
			rec.FQDN, oldValue, len(provider.cleanups))
	}
	after, err := store.ListAuthorizationsForTest("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Errorf("once the record is reclaimed the row is finished, %d left", len(after))
	}
}

// A state write that fails after the TXT was presented must not leave the record unnamed in DNS.
//
// The revisit path deliberately keeps the previous attempt's token on disk until the new record
// exists, so when the write that would name the new record fails, the row names the OLD value and
// nothing points at the new one: recovery probes the old value, is authoritatively denied, drops
// the row, and the new record stays in DNS with no row, no lease and no log line mentioning it. The
// pass now removes what it just wrote before reporting the failure.
//
// The write is made to fail deterministically with a SQLite trigger, which is the same shape as a
// full disk or a corrupt page: the read that loaded the row succeeded, the write does not.
func TestAFailedStateWriteTakesThePresentedRecordBackOut(t *testing.T) {
	privateLeaseRegistry(t)

	oldValue := dns01.GetChallengeInfo("example.com", "keyauth(tok-1)").Value
	newValue := dns01.GetChallengeInfo("example.com", "keyauth(tok-2)").Value

	// The authority denies the new value (so the pass writes) and afterwards serves whatever was
	// written, so the cleanup probe finds it.
	var written []string
	solver, rec, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			if len(written) == 0 {
				resp := dnsReply(msg)
				resp.Rcode = dns.RcodeNameError
				resp.Authoritative = true
				return resp, nil
			}
			return authTXT(msg, written...), nil
		})
	provider := &recordingProvider{}
	provider.onPresent = func() {}
	solver.newProvider = func(context.Context) (challenge.Provider, error) { return provider, nil }
	solver.timeout = time.Millisecond

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// One presented record per Present call, so the harness's authority can serve it back.
	provider.onPresent = func() {
		written = append(written, newValue)
	}

	fake := &fakeAPI{authzByURL: map[string]legoacme.Authorization{
		"https://ca.test/authz/1": {
			Status:     "pending",
			Identifier: legoacme.Identifier{Value: "example.com"},
			Challenges: []legoacme.Challenge{{
				Type: "dns-01", URL: "https://ca.test/chall/2", Token: "tok-2",
			}},
		},
	}}
	m := newManager(store, fake, solver, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "https://ca.test/authz/1", Identifier: "example.com",
		ChallengeToken: "tok-1", TxtName: rec.FQDN, TxtValue: oldValue,
		Presented: false, ChallengePreparedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// From here on, every UPDATE of an authorization row is refused: the pass's write fails.
	failAuthorizationWrites(t, dbPath)

	cert := &config.Certificate{Name: "c", Domains: []string{"example.com"}}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
		Location: "https://ca.test/order/1",
	}
	if _, err := m.solveChallenges(context.Background(), cert, &state.CertState{Name: "c"}, order); err == nil {
		t.Fatal("the state write is refused, so the pass must fail")
	}

	if len(provider.presents) == 0 {
		t.Fatal("the fixture must reach the DNS write, or this test proves nothing")
	}
	if len(provider.cleanups) != 1 {
		t.Errorf("the record written by this pass must be taken back out (%d cleanups, expects one "+
			"delete-all at %s): nothing else on disk or in the lease registry names it",
			len(provider.cleanups), rec.FQDN)
	}
}

// Releasing the LAST lease leaves no leaver to fire the provider's delete-all.
//
// This is the round-7 trade (LC-4) made concrete, and it is a real trade rather than a harmless one.
// The registry's contract is "the delete-EVERY-TXT call fires when the last value leaves": that is
// what lets one certificate's cleanup defer while another's record is still live at the same
// _acme-challenge name. releaseStaleLease only drops the value from the registry -- it deliberately
// does not call the provider, because a provider call outside the per-name mutex is the race the
// registry exists to prevent.
//
// So a release that empties the name (the record the released value owned was already deleted, or
// never written) leaves the values that an earlier leaver deferred on with nobody left to fire the
// call for them. Those records stay in DNS until some LATER challenge is presented at the same name
// and its cleanup is the last leaver -- which is why the trade is still the right one: the release
// is what keeps the name cleanable at all, and a lease nothing will ever remove blocks the delete-all
// for the rest of the process, which is strictly worse.
func TestReleasingTheLastLeaseLeavesNoLeaverToFireTheDeleteAll(t *testing.T) {
	privateLeaseRegistry(t)
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")

	p := &recordingProvider{}
	solver := &DNSSolver{
		newProvider: func(context.Context) (challenge.Provider, error) { return p, nil },
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		// Present resolves the zone before handing the write to the provider.
		recursiveNameservers: []string{"192.0.2.53:53"},
		exchange: func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
			return dnsReply(msg, &dns.SOA{Hdr: dns.RR_Header{
				Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}}), nil
		},
	}
	m, _ := newTestManager(t, solver, fakeKeyAuth{})
	ctx := context.Background()

	// Two certificates share one challenge name -- the shape that makes the registry necessary.
	recA, err := solver.Present(ctx, "shared.example.com", "tok-a", "keyauth-a")
	if err != nil {
		t.Fatalf("Present A: %v", err)
	}
	recB, err := solver.Present(ctx, "shared.example.com", "tok-b", "keyauth-b")
	if err != nil {
		t.Fatalf("Present B: %v", err)
	}
	if recA.FQDN != recB.FQDN || recA.Value == recB.Value {
		t.Fatalf("the fixture needs one name and two values, got %+v and %+v", recA, recB)
	}

	// A leaves first: the delete-all is deferred for B's record, which is the guard working.
	if err := solver.CleanUp(ctx, "shared.example.com", "tok-a", "keyauth-a"); err != nil {
		t.Fatalf("CleanUp A: %v", err)
	}
	if len(p.cleanups) != 0 {
		t.Fatalf("A's cleanup must defer while B's record is live, got %d provider calls", len(p.cleanups))
	}
	if !hasTXTLease(recA.FQDN, recB.Value) {
		t.Fatal("B is the last leaver and its lease has to still be held")
	}

	// B's own record is proven gone -- by the reclaim probe, or by a cleanup that already ran. The
	// value is nobody's, so the lease goes, and the promise that "the last leaver cleans up" is now
	// attached to a leaver that does not exist.
	m.releaseStaleLease(recB.FQDN, recB.Value)
	if hasTXTLease(recB.FQDN, recB.Value) {
		t.Fatal("no presented row claims the value, so the lease must be released")
	}
	if got := len(p.cleanups); got != 0 {
		t.Fatalf("releasing a lease must not touch the provider, got %d CleanUp calls", got)
	}

	// The name is now empty of leases, and the deferred delete-all has still never run: A's record
	// is the stranded one. What eventually collects it is the next cleanup at this name -- which,
	// with the registry empty, now fires the delete-all that A's first cleanup had to skip.
	if err := solver.CleanUp(ctx, "shared.example.com", "tok-a", "keyauth-a"); err != nil {
		t.Fatalf("CleanUp A again: %v", err)
	}
	if len(p.cleanups) != 1 {
		t.Fatalf("with the released lease gone, the next cleanup at the name is the delete-all that "+
			"collects the stranded record; got %d calls", len(p.cleanups))
	}
}

// failAuthorizationWrites makes every UPDATE of an authorization row fail, deterministically.
//
// A trigger is the closest thing to a full disk or a corrupt page that a test can arrange: the read
// that loaded the row succeeds, the write is refused by the database itself.
func failAuthorizationWrites(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open a second connection: %v", err)
	}
	defer db.Close()
	// Only the write that records a PRESENTED challenge fails: the earlier write of the
	// challenge age has to succeed, or the pass stops before it ever writes to DNS.
	if _, err := db.Exec(`CREATE TRIGGER r6_no_authorization_writes BEFORE UPDATE ON authorizations
		WHEN NEW.presented = 1
		BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatalf("create the fault trigger: %v", err)
	}
}
