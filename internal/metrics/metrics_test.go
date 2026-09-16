package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// A certificate that leaves the desired state must lose all of its series —
// including the reconcile counters — or they stay exported at their last value
// forever (a frozen not_after is a permanent expiry alert).
func TestDeleteCertSeries(t *testing.T) {
	const name = "gone"

	CertNotAfter.WithLabelValues(name).Set(1)
	CertDeployed.WithLabelValues(name).Set(1)
	CertConsecutiveFailures.WithLabelValues(name).Set(2)
	CertARIWindowStart.WithLabelValues(name).Set(3)
	CertificateFallbackActive.WithLabelValues(name).Set(1)
	CertificateFallbackDropped.WithLabelValues(name).Set(1)
	ReconcileTotal.WithLabelValues(name, "ok").Inc()
	ReconcileTotal.WithLabelValues(name, "error").Inc()
	ReconcilePanics.WithLabelValues(name).Inc()

	DeleteCertSeries(name)

	for _, tc := range []struct {
		name string
		vec  prometheus.Collector
	}{
		{"CertNotAfter", CertNotAfter},
		{"CertDeployed", CertDeployed},
		{"CertConsecutiveFailures", CertConsecutiveFailures},
		{"CertARIWindowStart", CertARIWindowStart},
		{"CertificateFallbackActive", CertificateFallbackActive},
		{"CertificateFallbackDropped", CertificateFallbackDropped},
		{"ReconcileTotal", ReconcileTotal},
		{"ReconcilePanics", ReconcilePanics},
	} {
		if n := testutil.CollectAndCount(tc.vec); n != 0 {
			t.Errorf("%s should have no series left for %q, got %d", tc.name, name, n)
		}
	}
}
