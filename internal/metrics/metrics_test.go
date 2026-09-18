package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// certLabelValues collects the values of the given label across every series a
// collector currently exports.
//
// ToFloat64 cannot answer "is this series gone": reading a deleted label set
// creates a fresh child, so it returns 0 either way. And CollectAndCount only
// answers "is the whole vec empty", which cannot catch over-deletion -- the
// failure mode where one name's delete takes another name's series with it.
func labelValues(t *testing.T, c prometheus.Collector, label string) map[string]bool {
	t.Helper()

	ch := make(chan prometheus.Metric, 32)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	out := make(map[string]bool)
	for m := range ch {
		var dtoM dto.Metric
		if err := m.Write(&dtoM); err != nil {
			t.Fatalf("reading a metric: %v", err)
		}
		for _, l := range dtoM.Label {
			if l.GetName() == label {
				out[l.GetValue()] = true
			}
		}
	}
	return out
}

// A certificate that leaves the desired state must lose all of its series —
// including the reconcile counters — or they stay exported at their last value
// forever (a frozen not_after is a permanent expiry alert). Just as important,
// the delete must not take any other certificate's series with it.
func TestDeleteCertSeries(t *testing.T) {
	const (
		gone  = "gone"
		stays = "stays"
	)

	for _, name := range []string{gone, stays} {
		CertNotAfter.WithLabelValues(name, "classic").Set(1)
		CertDeployed.WithLabelValues(name).Set(1)
		CertConsecutiveFailures.WithLabelValues(name).Set(2)
		CertARIWindowStart.WithLabelValues(name).Set(3)
		CertificateFallbackActive.WithLabelValues(name).Set(1)
		CertificateFallbackDropped.WithLabelValues(name).Set(1)
		ReconcileTotal.WithLabelValues(name, "ok").Inc()
		ReconcileTotal.WithLabelValues(name, "error").Inc()
		ReconcilePanics.WithLabelValues(name).Inc()
	}

	DeleteCertSeries(gone)

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
		values := labelValues(t, tc.vec, "cert")
		if values[gone] {
			t.Errorf("%s should have no series left for %q", tc.name, gone)
		}
		if !values[stays] {
			t.Errorf("%s must keep the series of %q -- deleting %q must not over-delete", tc.name, stays, gone)
		}
	}
}

// Probe series have the same reclamation rule per host: a dropped host's series
// must go, every other host's series must survive.
func TestDeleteProbeSeries(t *testing.T) {
	const (
		gone  = "gone.example.com"
		stays = "stays.example.com"
	)

	for _, host := range []string{gone, stays} {
		CertificateProbeMatch.WithLabelValues(host).Set(1)
		CertificateProbeNotAfter.WithLabelValues(host).Set(1)
		CertificateProbeTrusted.WithLabelValues(host).Set(1)
		CertificateProbeErrors.WithLabelValues(host).Inc()
	}

	DeleteProbeSeries(gone)

	for _, tc := range []struct {
		name string
		vec  prometheus.Collector
	}{
		{"CertificateProbeMatch", CertificateProbeMatch},
		{"CertificateProbeNotAfter", CertificateProbeNotAfter},
		{"CertificateProbeTrusted", CertificateProbeTrusted},
		{"CertificateProbeErrors", CertificateProbeErrors},
	} {
		values := labelValues(t, tc.vec, "host")
		if values[gone] {
			t.Errorf("%s should have no series left for %q", tc.name, gone)
		}
		if !values[stays] {
			t.Errorf("%s must keep the series of %q -- deleting %q must not over-delete", tc.name, stays, gone)
		}
	}
}
