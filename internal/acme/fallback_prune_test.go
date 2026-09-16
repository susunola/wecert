package acme

import (
	"context"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/state"
)

// clearGaugeFor keeps the shared gauge clean between tests.
func clearGaugeFor(t *testing.T, certName string) {
	t.Helper()
	t.Cleanup(func() {
		metrics.CertificateFallbackActive.DeleteLabelValues(certName)
		metrics.CertificateFallbackDropped.DeleteLabelValues(certName)
	})
}

// A name dropped by a fallback and then removed from the configuration can never come back.
//
// "This name will not validate, take it out of the configuration" is the expected response to
// what a fallback reports, and the record has to stop waiting for it. Otherwise the record never
// satisfies the condition that clears it -- `containsAll(c.Domains, fb.Dropped)` in download --
// because that name is absent from c.Domains forever, so it sticks for the life of the
// certificate and wecert_certificate_fallback_active reports a degradation that ended.
//
// A degradation alert that can never clear is worse than no alert: it teaches whoever reads it
// to ignore the signal.
func TestFallbackRecordIsClearedWhenEveryDroppedNameLeftTheConfig(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, nil)
	clearGaugeFor(t, cert.Name)

	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name,
		// Configured names are a/b/c.example.com; this one is not among them.
		Dropped: []string{"gone.example.com"},
		Since:   now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	metrics.CertificateFallbackActive.WithLabelValues(cert.Name).Set(1)
	metrics.CertificateFallbackDropped.WithLabelValues(cert.Name).Set(1)

	m.applyFallback(cert, &state.CertState{Name: cert.Name, NotAfter: now.Add(24 * time.Hour)})

	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb != nil {
		t.Fatalf("the record only names a domain that is no longer configured, so nothing is "+
			"being waited for and it must be gone; it would otherwise report "+
			"wecert_certificate_fallback_active forever: %+v", fb)
	}
	if got := testutil.ToFloat64(metrics.CertificateFallbackActive.WithLabelValues(cert.Name)); got != 0 {
		t.Errorf("wecert_certificate_fallback_active = %v, want 0: the degradation cannot recur", got)
	}
}

// The counterpart: a dropped name that is still configured is still being waited for, so the
// record must survive. Pruning must not be a back door to clearing the fallback state.
func TestFallbackRecordIsKeptWhileTheDroppedNameIsStillConfigured(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, nil)
	clearGaugeFor(t, cert.Name)

	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name, Dropped: []string{"b.example.com"}, Since: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	m.applyFallback(cert, &state.CertState{Name: cert.Name, NotAfter: now.Add(24 * time.Hour)})

	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb == nil {
		t.Fatal("b.example.com is still configured, so the record must stay")
	}
	if got := testutil.ToFloat64(metrics.CertificateFallbackActive.WithLabelValues(cert.Name)); got != 1 {
		t.Errorf("wecert_certificate_fallback_active = %v, want 1 while a configured name is not covered", got)
	}
}

// A partial removal prunes only the names that left, and keeps the rest.
func TestFallbackRecordIsPrunedToTheNamesStillConfigured(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, nil)
	clearGaugeFor(t, cert.Name)

	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name,
		Dropped:  []string{"a.example.com", "gone.example.com"},
		Since:    now.Add(-time.Hour),
		Reason:   "earlier",
	}); err != nil {
		t.Fatal(err)
	}

	m.applyFallback(cert, &state.CertState{Name: cert.Name, NotAfter: now.Add(24 * time.Hour)})

	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb == nil {
		t.Fatal("a.example.com is still configured, so the record must not be cleared")
	}
	if len(fb.Dropped) != 1 || fb.Dropped[0] != "a.example.com" {
		t.Fatalf("Dropped = %v, want only the still-configured name [a.example.com]", fb.Dropped)
	}
	if fb.Since.IsZero() {
		t.Error("pruning must preserve when the degradation started")
	}
	if got := testutil.ToFloat64(metrics.CertificateFallbackDropped.WithLabelValues(cert.Name)); got != 1 {
		t.Errorf("the dropped gauge must follow the pruned record, got %v", got)
	}
}

// The whole point: with the record pruned, the ordinary clearing path becomes reachable again.
//
// download clears the record when it has just issued the full desired set and every name in the
// record is covered by it. Before the prune, a removed name made that test unsatisfiable and the
// record outlived the certificate. This drives the real path -- Reconcile through to download --
// so it pins the wiring, not just the helper.
func TestFallbackRecordClearsAfterAFullIssuanceOnceTheRemovedNameIsGone(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	clearGaugeFor(t, cert.Name)

	// A record naming the configured domain plus one that has since been removed. The prune
	// leaves the configured one, so the record survives into download -- which is exactly the
	// state that used to be permanent.
	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name,
		Dropped:  []string{"example.com", "gone.example.com"},
		Since:    time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	oldExpiry, newExpiry := time.Now().Add(24*time.Hour), time.Now().Add(90*24*time.Hour)
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: oldExpiry, CertURL: "https://ca.test/old",
		CertPEM: selfSignedCertPEM(t, oldExpiry, "example.com"), KeyPEM: []byte("old-key"),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{CertName: cert.Name, KeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}
	fake.certNotAfter = newExpiry
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{
		Status: "valid", Certificate: "https://ca.test/new"}, Location: "https://ca.test/order/new"}}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb != nil {
		t.Fatalf("a full certificate covering every still-configured dropped name was issued and "+
			"deployed, so the record must be gone; instead it outlives the certificate: %+v", fb)
	}
	if got := testutil.ToFloat64(metrics.CertificateFallbackActive.WithLabelValues(cert.Name)); got != 0 {
		t.Errorf("wecert_certificate_fallback_active = %v, want 0 after a full issuance", got)
	}
}
