package acme

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/state"
)

// A failed read of the fallback record must not be reported as "not degraded".
//
// The branch used to be `if err == nil && fb != nil { active=1 } else { active=0 }`, which
// collapses two very different situations: "there is no fallback record" and "the record could
// not be read". The second one asserted health from a failed read -- and it flips the gauge
// green exactly when the store is unavailable, which is when a live degradation is most likely
// to go unnoticed. wecert_certificate_fallback_active means "a certificate missing names is
// serving right now"; turning it off without evidence is a false green in the only alerting
// path the project has.
func TestFallbackGaugeIsNotResetWhenTheRecordCannotBeRead(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, nil)

	// Start from the degraded state, as a previous round would have left it.
	metrics.CertificateFallbackActive.WithLabelValues(cert.Name).Set(1)
	metrics.CertificateFallbackDropped.WithLabelValues(cert.Name).Set(2)
	t.Cleanup(func() {
		metrics.CertificateFallbackActive.DeleteLabelValues(cert.Name)
		metrics.CertificateFallbackDropped.DeleteLabelValues(cert.Name)
	})

	// Make the read fail. Closing the store is the closest thing to an unavailable database,
	// and it is what the caller cannot distinguish from "healthy" today.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// The policy is off, so this pass uses the full set and the read is what decides.
	st := &state.CertState{Name: cert.Name, NotAfter: now.Add(24 * time.Hour)}
	if got, _ := m.applyFallback(cert, st, round{}); len(got.Domains) != len(cert.Domains) {
		t.Fatalf("with the policy off the full set must be used, got %v", got.Domains)
	}

	if got := testutil.ToFloat64(metrics.CertificateFallbackActive.WithLabelValues(cert.Name)); got != 1 {
		t.Errorf("a failed read left wecert_certificate_fallback_active at %v, want it unchanged at 1: "+
			"reporting health from a failed read is a false green", got)
	}
	if got := testutil.ToFloat64(metrics.CertificateFallbackDropped.WithLabelValues(cert.Name)); got != 2 {
		t.Errorf("a failed read left wecert_certificate_fallback_dropped at %v, want it unchanged at 2", got)
	}
}

// The other two branches still work: no record means healthy, a record means degraded.
func TestFallbackGaugeFollowsTheRecordWhenItCanBeRead(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, nil)
	t.Cleanup(func() {
		metrics.CertificateFallbackActive.DeleteLabelValues(cert.Name)
		metrics.CertificateFallbackDropped.DeleteLabelValues(cert.Name)
	})
	st := &state.CertState{Name: cert.Name, NotAfter: now.Add(24 * time.Hour)}

	// No record: healthy.
	metrics.CertificateFallbackActive.WithLabelValues(cert.Name).Set(1)
	m.applyFallback(cert, st, round{})
	if got := testutil.ToFloat64(metrics.CertificateFallbackActive.WithLabelValues(cert.Name)); got != 0 {
		t.Errorf("with no fallback record the gauge must read 0, got %v", got)
	}

	// A record: degraded, and the count is the record's, not this round's.
	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name, Dropped: []string{"b.example.com"}, Since: now,
	}); err != nil {
		t.Fatal(err)
	}
	m.applyFallback(cert, st, round{})
	if got := testutil.ToFloat64(metrics.CertificateFallbackActive.WithLabelValues(cert.Name)); got != 1 {
		t.Errorf("with a fallback record the gauge must read 1, got %v", got)
	}
	if got := testutil.ToFloat64(metrics.CertificateFallbackDropped.WithLabelValues(cert.Name)); got != 1 {
		t.Errorf("the dropped count must come from the record, got %v", got)
	}
}
