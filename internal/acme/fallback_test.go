package acme

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// fallbackPolicy is an "enabled, small thresholds" policy meant for tests.
//
// BeforeExpiryDur / FailureWindowDur are set directly here: config.normalize would
// normally fill them in, while SetFallbackPolicy takes the struct as-is.
// fallbackPolicyPtr returns a pointer to it, so tests can pass nil for "not configured".
func fallbackPolicyPtr() *config.FailureFallback {
	p := fallbackPolicy()
	return &p
}

func fallbackPolicy() config.FailureFallback {
	on := true
	return config.FailureFallback{
		Enabled:               &on,
		AfterFailures:         3,
		BeforeExpiryDur:       7 * 24 * time.Hour,
		MinIdentifierFailures: 2,
		FailureWindowDur:      24 * time.Hour,
		MinNames:              1,
	}
}

// fallbackFixture builds a scenario with "three names, near expiry, repeated failures".
func fallbackFixture(t *testing.T, policy *config.FailureFallback) (*state.Store, *Manager, *config.Certificate, time.Time) {
	t.Helper()

	store, m, _, cert := newAPITestHarness(t,
		[]string{"a.example.com", "b.example.com", "c.example.com"})

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }

	if policy != nil {
		m.SetFallbackPolicy(*policy)
	}
	return store, m, cert, fixed
}

// The policy must be turned on explicitly: Enabled has to be set to true.
func TestFallbackIsOffByDefault(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, nil)

	for i := 0; i < 10; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{Name: cert.Name, NotAfter: now.Add(time.Hour), ConsecutiveFailures: 99}
	got, _ := m.applyFallback(cert, st, round{})
	if len(got.Domains) != 3 {
		t.Fatalf("no name should be dropped when the policy is off, got %v", got.Domains)
	}
}

// Below the failure threshold nothing moves: falling back deliberately gives up coverage,
// so it must not fire just because "this pass did not issue" -- that hits almost every certificate.
func TestFallbackWaitsForEnoughConsecutiveFailures(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 2, // threshold is 3
	}
	if got, _ := m.applyFallback(cert, st, round{}); len(got.Domains) != 3 {
		t.Fatalf("should not fall back below the failure threshold, got %v", got.Domains)
	}
}

// Nor may it fall back too early: trading a fully valid certificate for one that lacks names is a net loss.
func TestFallbackWaitsForTheExpiryWindow(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(30 * 24 * time.Hour), // still outside the 7-day window
		ConsecutiveFailures: 9,
	}
	if got, _ := m.applyFallback(cert, st, round{}); len(got.Domains) != 3 {
		t.Fatalf("should not fall back outside the expiry window, got %v", got.Domains)
	}
}

// With no live certificate the "keep the current one alive" argument does not hold -- that
// is not partial availability, it is issuing only some of the names.
func TestFallbackRefusesWithoutALiveCertificate(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{Name: cert.Name, ConsecutiveFailures: 9} // NotAfter is the zero value
	if got, _ := m.applyFallback(cert, st, round{}); len(got.Domains) != 3 {
		t.Fatalf("should not fall back without a live certificate, got %v", got.Domains)
	}
}

// When it is unknown which name is broken, nothing may be dropped -- dropping at random
// would sacrifice healthy names too, which is worse than not falling back at all.
func TestFallbackRefusesWithoutASpecificFailingIdentifier(t *testing.T) {
	_, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 9,
	}
	if got, _ := m.applyFallback(cert, st, round{}); len(got.Domains) != 3 {
		t.Fatalf("should not fall back without per-identifier failure records, got %v", got.Domains)
	}
}

// This is the core of the feature: drop only the names that fail repeatedly, keep the rest as-is.
func TestFallbackDropsOnlyTheFailingIdentifiers(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	// Name b fails repeatedly (3 times); name a blipped only once (1 time, below the threshold of 2).
	for i := 0; i < 3; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordIdentifierFailure(cert.Name, "a.example.com", "one blip", now); err != nil {
		t.Fatal(err)
	}

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(3 * 24 * time.Hour),
		ConsecutiveFailures: 4,
		ARICertID:           "YWJj.ZGVm",
	}

	got, _ := m.applyFallback(cert, st, round{})
	want := []string{"a.example.com", "c.example.com"}
	if len(got.Domains) != len(want) {
		t.Fatalf("domain set = %v, want %v", got.Domains, want)
	}
	for i := range want {
		if got.Domains[i] != want[i] {
			t.Fatalf("domain set = %v, want %v", got.Domains, want)
		}
	}

	// The original object must not be mutated: the caller still holds the one from the config.
	if len(cert.Domains) != 3 {
		t.Fatalf("the certificate passed in by the caller must not be mutated in place, got %v", cert.Domains)
	}

	// The fallback state must be persisted -- it is the only record that a certificate
	// missing some names is currently serving traffic.
	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb == nil {
		t.Fatal("fallback state must be persisted, otherwise nothing records that names are missing")
	}
	if len(fb.Dropped) != 1 || fb.Dropped[0] != "b.example.com" {
		t.Errorf("dropped names recorded = %v, want [b.example.com]", fb.Dropped)
	}
	if fb.Reason == "" {
		t.Error("fallback must carry a reason")
	}
}

// Refuse to fall back when too few names would remain: that is "everything is down"
// wearing a different face, yet it reads as if part of it were still available.
func TestFallbackRefusesWhenItWouldDropTooMany(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	// Names a and b both fail repeatedly, leaving only c -- and the minimum is 2.
	for _, id := range []string{"a.example.com", "b.example.com"} {
		for i := 0; i < 3; i++ {
			if err := store.RecordIdentifierFailure(cert.Name, id, "dns says no", now); err != nil {
				t.Fatal(err)
			}
		}
	}

	p := fallbackPolicy()
	p.MinNames = 2
	m.SetFallbackPolicy(p)

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 9,
	}

	if got, _ := m.applyFallback(cert, st, round{}); len(got.Domains) != 3 {
		t.Fatalf("must refuse to fall back when fewer names than the minimum remain, got %v", got.Domains)
	}
	if fb, _ := store.GetFallback(cert.Name); fb != nil {
		t.Error("a refused fallback must not leave a fallback record behind")
	}
}

// Old failure records do not count -- that is exactly the door to self-healing.
//
// A dropped name is never attempted again, so it never gets a success that could clear
// it; the only way out is for the record to age out.
func TestFallbackIgnoresStaleFailures(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	stale := now.Add(-48 * time.Hour) // the window is 24h
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", stale); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 9,
	}
	if got, _ := m.applyFallback(cert, st, round{}); len(got.Domains) != 3 {
		t.Fatalf("records older than the failure window must not count towards fallback, got %v", got.Domains)
	}
}

// Once the names recover it must walk itself back out and clear its ledger.
func TestFallbackClearsItselfOnceTheNamesAreHealthy(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name,
		Dropped:  []string{"b.example.com"},
		Since:    now.Add(-time.Hour),
		Reason:   "earlier",
	}); err != nil {
		t.Fatal(err)
	}

	// No identifier is failing in this pass, so use the full set.
	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 0,
	}
	if got, _ := m.applyFallback(cert, st, round{}); len(got.Domains) != 3 {
		t.Fatalf("should return to the full set, got %v", got.Domains)
	}

	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb == nil {
		t.Error("trying the full set must not clear fallback before a full certificate is issued")
	}
}

// A degraded certificate must not shake its own fallback loose.
//
// The regression this pins: a successful issuance for the reduced subset used to reset
// consecutive_failures and clear the identifier ledger, exactly like any other success.
// That erased the only evidence that an identifier was broken, so the very next pass
// saw "failures = 0" plus a live certificate and ordered the full set again -- once per
// backoff window, forever, spending a real order on an identifier set already known to
// be broken. Let's Encrypt allows 5 certificates per exact set of identifiers per 7 days,
// so a daily retry exhausts the account's quota within the week.
func TestFallbackStaysStickyAfterIssuingTheDegradedSubset(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t,
		[]string{"a.example.com", "b.example.com", "c.example.com"})

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	now := fixed
	m.now = func() time.Time { return now }
	m.SetFallbackPolicy(fallbackPolicy())

	// A live certificate for the full set, inside the pre-expiry window.
	liveNotAfter := fixed.Add(48 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: liveNotAfter, CertURL: "https://ca.test/cert/live",
		ConsecutiveFailures: 5,
	}); err != nil {
		t.Fatal(err)
	}
	// b.example.com is the identifier that keeps failing.
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", fixed); err != nil {
			t.Fatal(err)
		}
	}

	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}
	// A real CA issues a certificate that is fresh from *its* now, so the renewal pass must
	// get one whose notAfter really is later than the live certificate's -- download refuses
	// to deploy one that is not, which is correct and would otherwise mask the recovery path
	// being tested. The clock below moves three times, and this tracks it.
	fake.certNotAfterFn = func() time.Time { return now.Add(90 * 24 * time.Hour) }

	// The broken identifier is broken at the DNS level, so an order that includes it can
	// never be finalized. Modelling the CA as always succeeding would test a world where
	// the fallback has nothing to protect against.
	//
	// This hook also records every identifier set, and it can record them reliably because
	// NewOrder now fills newOrderDomains before calling enter.
	const broken = "b.example.com"
	var ordered [][]string
	// Set once the operator has done the expected thing (repaired the DNS) so phase 3 can
	// reach the "successful full-set issuance" that is the only thing allowed to clear the
	// fallback record. The retry has to be a *different* certificate URL: if the fake
	// handed back the one already live, download's idempotent backstop would short-circuit
	// before the new certificate was ever considered.
	fixedByName := false
	appendedFreshCert := false
	fake.beforeCall = func(call string) {
		if call != "NewOrder" {
			return
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		ordered = append(ordered, append([]string(nil), fake.newOrderDomains...))
		if fixedByName {
			fake.orderErr = nil
			if !appendedFreshCert {
				appendedFreshCert = true
				fake.orders = append(fake.orders, terminalOrder(
					"https://ca.test/order/2", "https://ca.test/finalize/2", "https://ca.test/cert/2"))
				// The polling pointer is exhausted and would otherwise keep handing back the
				// already-live order/1, which download's idempotent backstop reads as "this
				// certificate is already deployed" and short-circuits on.
				fake.orderIdx = len(fake.orders) - 1
			}
			return
		}
		for _, d := range fake.newOrderDomains {
			if d == broken {
				fake.orderErr = errors.New("CA: the authorization for " + broken + " is invalid")
				return
			}
		}
	}

	// Phase 1: while the failure evidence is fresh, the reduced set holds.
	//
	// The certificate the degraded issuance deploys is valid for 90 days, which puts it
	// months outside the pre-expiry window. The fallback must survive that: it is the
	// window that gates *entering* a degradation, not staying in one. Reading it the
	// other way cleared the fallback one pass after it was established and re-ordered the
	// broken full set on every pass.
	const passes = 5
	for pass := 0; pass < passes; pass++ {
		if err := m.Reconcile(context.Background(), cert); err != nil {
			t.Logf("pass %d failed as expected: %v", pass, err)
		}
		// No backoff skip: this asserts the decision, not the timer.
	}

	countFull := func() int {
		n := 0
		for _, set := range ordered {
			if len(set) == 3 {
				n++
			}
		}
		return n
	}
	if got := countFull(); got != 0 {
		t.Errorf("the full identifier set was ordered %d time(s) across %d passes while b.example.com is "+
			"permanently broken; the fallback must hold until the failure evidence ages out "+
			"(Let's Encrypt allows 5 per exact set per 7 days). Orders: %v", got, passes, ordered)
	}

	// The evidence that justifies the reduction must still be on disk.
	failures, err := store.ListIdentifierFailures(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) == 0 {
		t.Error("the identifier failure ledger was cleared by a degraded issuance, so the next pass " +
			"cannot tell that b.example.com is still broken")
	}

	// And the certificate that is live is the reduced one, so consecutive_failures must
	// not have been zeroed either.
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st.ConsecutiveFailures == 0 {
		t.Error("consecutive_failures was reset by a degraded issuance, which re-arms the fallback trigger " +
			"and lets the next pass re-order the full set")
	}
	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb == nil {
		t.Fatal("the fallback record must survive while the degraded certificate is serving")
	}
	// The record keeps when the degradation started rather than being refreshed by every
	// pass, so "degraded for three days" stays answerable.
	if !fb.Since.Equal(fixed) {
		t.Errorf("fallback since = %s, want the original %s: a refreshed timestamp makes the "+
			"duration of the degradation unreadable", fb.Since, fixed)
	}

	// Phase 2: once the failure evidence ages past the window, the degradation is over in
	// the sense that matters for *planning* -- the reduced set stops being forced -- but
	// nothing is ordered yet: this certificate is 90 days old-in-hand and its renewal time
	// is notAfter - renewBefore, 60 days out. The retry is bounded by evidence AND by the
	// renewal window, so an aged-out ledger does not become an hourly full-set order.
	now = fixed.Add(48 * time.Hour) // past fallbackPolicy's 24h FailureWindowDur
	before := countFull()
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Logf("recovery pass returned: %v", err)
	}
	if got := countFull() - before; got != 0 {
		t.Errorf("the aged-out evidence produced %d full-set order(s) while the replacement certificate is "+
			"nowhere near renewal; the renewal window, not the ledger, decides when to try again "+
			"(orders: %v)", got, ordered)
	}
	fb2, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb2 == nil {
		t.Fatal("the fallback record must survive while the degraded certificate is still the one serving: " +
			"it is the only record that names are missing")
	}

	// Phase 3: at the renewal time the full set is attempted again -- that is the
	// self-healing entry point -- and only a successful full-set issuance clears the
	// record. Trying is not recovery: clearing it on the attempt would make the next pass
	// order the full set again, once per backoff window, for a name that is still broken.
	now = fixed.Add(65 * 24 * time.Hour) // past notAfter - renewBefore (60 days)
	fixedByName = true                   // the fault the fallback was protecting against is gone
	before = countFull()
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Logf("renewal pass returned: %v", err)
	}
	if got := countFull() - before; got != 1 {
		t.Fatalf("the renewal pass must order the full set exactly once, got %d (orders: %v)", got, ordered)
	}
	last := ordered[len(ordered)-1]
	if len(last) != 3 {
		t.Fatalf("the final order must carry the full identifier set, got %v", last)
	}
	fb3, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb3 != nil {
		t.Errorf("a successful full-set issuance is the recovery signal, so the fallback record must be "+
			"cleared, got %+v", fb3)
	}
}

// The failure ledger has to be keyed by the name the operator wrote, which for a
// wildcard includes the "*.".
//
// RFC 8555 §7.1.3 forbids the "*." prefix in the authorization's own identifier:
// a `*.example.com` authorization carries `example.com` plus `wildcard: true`, which
// is why lego reconstructs the name with challenge.GetTargetedDomain. Keying the
// ledger on the raw identifier therefore books a wildcard failure against the apex.
//
// The fallback drops the domains whose literal string matches the ledger, so it
// would then shed the healthy apex and keep the wildcard that is actually failing.
// That is exactly backwards from its purpose -- it gives up coverage that works and
// still cannot issue -- and the certificate runs to expiry with neither name.
func TestWildcardFailureIsBookedAgainstTheWildcardNotTheApex(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com", "*.example.com"})

	const (
		apexAuthz     = "https://ca.test/authz/apex"
		wildcardAuthz = "https://ca.test/authz/wildcard"
	)
	fake.orders = []legoacme.ExtendedOrder{{
		Order: legoacme.Order{
			Status:         "pending",
			Finalize:       "https://ca.test/finalize/1",
			Authorizations: []string{apexAuthz, wildcardAuthz},
		},
		Location: "https://ca.test/order/1",
	}}
	fake.authzByURL = map[string]legoacme.Authorization{
		apexAuthz: {Status: "valid", Identifier: legoacme.Identifier{Value: "example.com"}},
		// The wildcard's own identifier is the bare apex; Wildcard carries the "*.".
		wildcardAuthz: {
			Status:     "invalid",
			Wildcard:   true,
			Identifier: legoacme.Identifier{Value: "example.com"},
		},
	}

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("an invalid authorization must fail the pass")
	}

	failures, err := store.ListIdentifierFailures(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 {
		t.Fatalf("want exactly one recorded failure, got %d: %+v", len(failures), failures)
	}
	if got := failures[0].Identifier; got != "*.example.com" {
		t.Errorf("the wildcard failure was booked against %q, want %q: the fallback would "+
			"drop the healthy apex and keep the broken wildcard", got, "*.example.com")
	}

	// And the consequence, through the real chain: the name the fallback sheds has to
	// be the wildcard. Dropping the apex instead would give up the name that still
	// works and still fail to issue.
	policy := fallbackPolicy()
	policy.MinIdentifierFailures = 1 // this test records a single failure
	m.SetFallbackPolicy(policy)

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            m.now().Add(3 * 24 * time.Hour), // inside the 7-day expiry window
		ConsecutiveFailures: 4,                               // above policy.AfterFailures
		ARICertID:           "YWJj.ZGVm",
	}
	got, _ := m.applyFallback(cert, st, round{})
	if len(got.Domains) != 1 || got.Domains[0] != "example.com" {
		t.Fatalf("after falling back the certificate should cover [example.com], got %v: "+
			"the failing wildcard is the name to drop, not the apex", got.Domains)
	}
}

// ── per-pass state must be local to the pass ────────────────────────────────────────

// The round intent that decides "hold the degraded set" versus "order the full set" is a
// value, not Manager state, and this pins the consequence: the SAME certificate and the
// SAME store produce two different decisions depending only on the value handed in.
//
// This is the invariant two concurrent certificates used to violate. The reconciler is
// serial per certificate NAME, not per process: startCert fans out one goroutine per
// certificate (capped at maxConcurrentStarts), the timer's RunAll overlaps them, and every
// one of them shares the single Manager built in main. While the flags lived on the
// Manager, a neighbour's pass could flip fallbackActive between this certificate's write
// and its read, and the degraded certificate would then re-order the very identifier set
// whose one broken name caused the fallback -- an order per pass straight into
// "5 certificates per exact set of identifiers / 7 days".
func TestFallbackDecisionDependsOnlyOnTheValueHandedIn(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: now.Add(90 * 24 * time.Hour),
		CertURL: "https://ca.test/cert/live", ConsecutiveFailures: 5,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name, Dropped: []string{"b.example.com"},
		Since: now, Reason: "one identifier keeps failing",
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}

	// A degradation is in force: the reduced set must be held, NOT the broken full set.
	held, heldRound := m.applyFallback(cert, st, round{fallbackActive: true})
	if got, want := held.Domains, []string{"a.example.com", "c.example.com"}; !equalStrings(got, want) {
		t.Errorf("with a degradation in force the pass must keep the reduced set %v, got %v", want, got)
	}
	if !heldRound.degraded || !heldRound.fallbackActive {
		t.Errorf("the returned round must report the reduction, got %+v", heldRound)
	}

	// The same inputs, minus "a degradation is in force": now the full set is tried. The
	// only difference is the value, which is the point -- nothing on the Manager can leak
	// between the two calls.
	tried, triedRound := m.applyFallback(cert, st, round{})
	if got := len(tried.Domains); got != 3 {
		t.Errorf("with no degradation in force the full set must be tried, got %d names: %v",
			got, tried.Domains)
	}
	if triedRound.degraded {
		t.Error("a round that ordered every name must not report itself degraded")
	}
}

// Two different certificates reconciled at the same time must not interfere. Run under
// -race this fails on the Manager-field version (manager.go's per-round writes), and the
// assertion catches the outcome rather than only the memory access.
func TestConcurrentReconcilesOfDifferentCertificatesDoNotInterfere(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t,
		[]string{"a.example.com", "b.example.com", "c.example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }
	m.SetFallbackPolicy(fallbackPolicy())

	// The certificate that must HOLD: a degraded certificate is live and the evidence is
	// still fresh, so no full-set order may be placed for it.
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(90 * 24 * time.Hour),
		CertURL: "https://ca.test/cert/live", ConsecutiveFailures: 5,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", fixed); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name, Dropped: []string{"b.example.com"},
		Since: fixed, Reason: "one identifier keeps failing",
	}); err != nil {
		t.Fatal(err)
	}

	// A neighbour with nothing wrong with it, whose pass touches the same code path.
	neighbour := *cert
	neighbour.Name = "neighbour-cert"
	neighbour.Domains = []string{"a.example.com", "b.example.com", "c.example.com"}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = m.Reconcile(context.Background(), cert) }()
		go func() { defer wg.Done(); _ = m.Reconcile(context.Background(), &neighbour) }()
	}
	wg.Wait()

	// The hold must have survived the neighbours: the degraded certificate still has its
	// fallback record and, crucially, its failure evidence was not erased.
	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb == nil {
		t.Error("the fallback record was cleared while a degraded certificate is serving: " +
			"the next pass will re-order the identifier set that is known to be broken")
	}
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st.ConsecutiveFailures == 0 {
		t.Error("consecutive_failures was cleared by a concurrent neighbour's pass, which re-arms " +
			"the fallback trigger and lets the next pass re-order the broken full set")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── a replacement may legitimately live LESS long than the certificate it replaces ──

// Switching a certificate to a shorter-lived profile must take effect at the next renewal.
//
// The gate used to be "the new notAfter must be strictly later than the live one". When ARI
// asks for renewal the live classic certificate (90d) still has weeks left, so a switch to
// shortlived (160h) produced a certificate with an EARLIER notAfter and every attempt was
// refused -- for as long as the live certificate outlived the new one, which is most of its
// remaining life. The profile change silently failed, consecutive_failures sat at the cap,
// and the renewal collapsed into the last few days of validity instead of happening 30 days
// early.
//
// The same shape breaks the whole fleet whenever the CA shortens lifetimes (Let's Encrypt
// has announced 90 -> 45 -> 6 days). The property to test is "issued after the live one",
// not "expires later".
func TestRenewalIsAcceptedWhenTheNewCertificateLivesLessLong(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com", "b.example.com"})

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	now := fixed
	m.now = func() time.Time { return now }

	// A healthy classic certificate with plenty of life left, issued a month ago.
	liveNotBefore := fixed.Add(-70 * 24 * time.Hour) // issued ~70 days ago
	// 20 days left. The classic renewal window opens at notAfter - renewBefore (30d), i.e.
	// 10 days ago -- and DeterministicTime adds up to renewBefore/8 (3.75d) of deterministic
	// jitter on top, so the window has to be open by more than the jitter for the renewal to
	// actually be due here.
	liveNotAfter := fixed.Add(20 * 24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name:     cert.Name,
		NotAfter: liveNotAfter,
		CertURL:  "https://ca.test/cert/live",
		CertPEM:  selfSignedCertAt(t, liveNotBefore, liveNotAfter, cert.Domains...),
		IssuedAt: liveNotBefore,
	}); err != nil {
		t.Fatal(err)
	}

	// The replacement is SHORTER lived (160h) but issued now -- a shortlived profile switch.
	shortNotAfter := fixed.Add(160 * time.Hour)
	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/2"),
	}
	fake.certNotAfter = shortNotAfter
	fake.certNotBefore = fixed

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("a genuinely newer certificate must be deployed even though it expires sooner, got %v", err)
	}

	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !st.NotAfter.Equal(shortNotAfter) {
		t.Errorf("the shorter-lived replacement must have been deployed: notAfter = %s, want %s",
			st.NotAfter, shortNotAfter)
	}
	if st.ConsecutiveFailures != 0 {
		t.Errorf("a successful renewal must clear the failure counter, got %d", st.ConsecutiveFailures)
	}
}

// The control: a stale certificate that is neither later-expiring nor issued after the live
// one must still be refused, so the fix cannot be satisfied by accepting everything.
func TestStaleCertificateIsStillRefused(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }

	// Live certificate has MORE life than the one the CA is about to hand back.
	liveNotBefore := fixed.Add(-70 * 24 * time.Hour)
	liveNotAfter := fixed.Add(20 * 24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name:     cert.Name,
		NotAfter: liveNotAfter,
		CertURL:  "https://ca.test/cert/live",
		CertPEM:  selfSignedCertAt(t, liveNotBefore, liveNotAfter, cert.Domains...),
		IssuedAt: liveNotBefore,
	}); err != nil {
		t.Fatal(err)
	}

	// The "replacement" expires sooner AND was issued BEFORE the live one: a stale artifact,
	// not a renewal.
	staleNotBefore := fixed.Add(-90 * 24 * time.Hour)
	staleNotAfter := fixed.Add(10 * 24 * time.Hour)
	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/2"),
	}
	fake.certNotAfter = staleNotAfter
	fake.certNotBefore = staleNotBefore

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a certificate that expires sooner and was issued earlier must be refused as stale")
	}

	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !st.NotAfter.Equal(liveNotAfter) {
		t.Errorf("the live certificate must be left in place, notAfter = %s, want %s", st.NotAfter, liveNotAfter)
	}
}
