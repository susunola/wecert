package acme

import (
	"testing"
	"time"

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
	got := m.applyFallback(cert, st)

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
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
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
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
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
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
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
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
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

	got := m.applyFallback(cert, st)

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

	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
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
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
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
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
		t.Fatalf("should return to the full set, got %v", got.Domains)
	}

	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb != nil {
		t.Errorf("the fallback record should be cleared after returning to the full set, got %+v", fb)
	}
}
