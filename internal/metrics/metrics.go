// Package metrics exposes Prometheus metrics.
//
// The most important one is wecert_certificate_not_after_timestamp_seconds:
// expiry alerts should be built on it ((not_after - time()) < threshold),
// not on "did the renewal job report an error" — the latter stays silent when
// the program itself fails silently.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CertNotAfter is the certificate expiry time (unix seconds).
	CertNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_not_after_timestamp_seconds",
		Help: "notAfter of the live certificate, in unix seconds.",
	}, []string{"cert"})

	// CertDeployed reports whether the certificate was successfully deployed to
	// the cloud.
	CertDeployed = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_deployed",
		Help: "1 when the certificate is confirmed bound to a Tencent Cloud resource, 0 otherwise (including the period after the first upload while waiting for a manual bind).",
	}, []string{"cert"})

	// CertConsecutiveFailures is the consecutive failure count; staying above 0
	// needs a human to step in.
	CertConsecutiveFailures = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_consecutive_failures",
		Help: "Consecutive failures. Reset to 0 by a successful pass.",
	}, []string{"cert"})

	// CertARIWindowStart is the start of the ARI-suggested renewal window.
	CertARIWindowStart = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_ari_window_start_timestamp_seconds",
		Help: "Start of the ARI-suggested renewal window in unix seconds; 0 means not yet obtained.",
	}, []string{"cert"})

	// ReconcileTotal records the outcome of each certificate's pass.
	ReconcileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_reconcile_total",
		Help: "Reconcile passes, with result being ok or error.",
	}, []string{"cert", "result"})

	// ReconcilePanics counts passes that only completed because a panic inside
	// the manager was recovered.
	//
	// This is deliberately a separate metric from ReconcileTotal's "error" result,
	// not folded into it: an *error* is an expected, handled outcome (ACME said no,
	// the network blipped) and the backoff in recordFailure already reacts to it. A
	// *panic* means the code hit a case nobody anticipated -- a nil that should
	// never be nil, an index that should never be out of range -- and recovering
	// from it keeps every other certificate's renewal running, but it must alert a
	// human on its own: staying above 0 always means a bug, never routine churn.
	ReconcilePanics = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_reconcile_panics_total",
		Help: "Passes that only completed because a panic inside the reconcile manager was recovered. Any nonzero value is a bug, not routine churn -- alert on it directly.",
	}, []string{"cert"})

	// DesiredStateErrors counts passes that could not read the desired state at all.
	//
	// When it rises, the whole pass was skipped: no certificate was processed, but
	// none was mistakenly deleted either — which is exactly the invariant "a
	// source failure is not an empty desired state" made visible.
	DesiredStateErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wecert_desired_state_errors_total",
		Help: "Passes skipped because the desired state could not be read. Skipping is deliberate: an unreadable source is never treated as an empty desired state.",
	})

	// DesiredStateFrozen reports whether the desired state is frozen at the last
	// revision.
	//
	// While frozen, renewals continue as usual but new domains are not picked up.
	// Staying at 1 means the source never recovered.
	DesiredStateFrozen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_frozen",
		Help: "1 when the desired state is frozen on the last good revision (renewals continue, new names do not).",
	})

	// DesiredStateCertificates is the number of certificates in the current
	// desired state.
	DesiredStateCertificates = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_certificates",
		Help: "Number of certificates in the current desired state.",
	})

	// DesiredStateAge is the age of the desired-state document in seconds.
	//
	// It answers the question unique to this architecture: is the onboarding
	// component still alive? After it dies everything looks normal, only no new
	// domain ever enters.
	DesiredStateAge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_age_seconds",
		Help: "Age of the desired-state document in seconds. A growing value means the onboarding component stopped refreshing it.",
	})

	// DesiredStateShadowDiff is the number of differences between the shadow
	// source and what is enforced, in observe mode.
	//
	// It should sit at 0 for a long time before switching from static to enforce.
	DesiredStateShadowDiff = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_shadow_diff",
		Help: "In observe mode, the number of certificate-level differences between what is enforced and what the shadow source asks for. Should stay at 0 before switching to enforce.",
	})

	// OrphanedCertificates counts certificates present in the state store but gone
	// from the desired state.
	//
	// They will not be renewed and will eventually expire — a silent failure.
	// The desired-state deletion path already has a grace period and reference
	// checks; this metric is the last safety net.
	OrphanedCertificates = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_orphaned_certificates",
		Help: "Certificates present in the state store but absent from the desired state. They will not be renewed and will eventually expire.",
	})

	// ── Network-side probing ──────────────────────────────────────────────────────────
	//
	// This group is the only evidence that does not trust the cloud control
	// plane: the cloud API saying "bound successfully" and a browser actually
	// getting this certificate are two different things.

	// CertificateProbeMatch reports whether the certificate served on connect is
	// the one we deployed.
	//
	// 1 = yes. 0 = the name works but another certificate is being served (a rebind
	// that did not take effect, or another certificate winning SNI), or the
	// coverage differs from what was deployed.
	CertificateProbeMatch = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_match",
		Help: "1 when the certificate actually served for this host is the one that was deployed, 0 otherwise. Only set after a probe that completed.",
	}, []string{"host"})

	// CertificateProbeNotAfter is the expiry time read back from the network.
	//
	// The difference from wecert_certificate_not_after_timestamp_seconds is
	// crucial: that one comes from the state store ("what I think is deployed"),
	// this one from a real handshake ("what is actually being served"). The two
	// disagreeing is the shape of the problem.
	CertificateProbeNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_not_after_timestamp_seconds",
		Help: "notAfter read back from a real TLS handshake, in unix seconds. Compare against wecert_certificate_not_after_timestamp_seconds to see whether the rebind actually took effect.",
	}, []string{"host"})

	// CertificateProbeTrusted reports whether the chain validates against the
	// system roots. 0 is not necessarily broken (an internal CA is legitimate),
	// but browsers will warn.
	CertificateProbeTrusted = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_trusted",
		Help: "1 when the served chain validates against the system roots. 0 is not necessarily broken (an internal CA is legitimate) but browsers will warn.",
	}, []string{"host"})

	// CertificateProbeErrors counts probes that could not run at all.
	//
	// Distinct from probe_match=0: that one "ran and found the wrong certificate",
	// this one "could not even connect". When the machine running wecert cannot
	// dial out, this is what rises — it never makes your certificates look broken.
	CertificateProbeErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_certificate_probe_errors_total",
		Help: "Probes that could not be completed at all (resolve, dial or handshake failed). Distinct from probe_match=0, which means the probe succeeded and found the wrong certificate.",
	}, []string{"host"})

	// ── Pre-expiry degradation ──────────────────────────────────────────────────────────

	// CertificateFallbackActive reports that this certificate is being served by a
	// partial certificate with some names missing.
	//
	// Staying at 1 means some names never issue. It is a deliberate tradeoff
	// (partial availability beats total failure) but never a state to leave
	// alone — those names are still erroring outward.
	CertificateFallbackActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_fallback_active",
		Help: "1 when this certificate is being served by a partial certificate with some names dropped (failure fallback). Partial availability beats total failure, but this is not a state to leave unattended.",
	}, []string{"cert"})

	// CertificateFallbackDropped is how many names were dropped.
	CertificateFallbackDropped = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_fallback_dropped_names",
		Help: "How many names were dropped from the certificate currently served by the failure fallback. The names themselves are in the state store and in the logs.",
	}, []string{"cert"})
)
