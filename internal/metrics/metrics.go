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
	CertNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_not_after_timestamp_seconds",
		Help: "notAfter of the live certificate, in unix seconds.",
	}, []string{"cert"})

	CertDeployed = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_deployed",
		Help: "1 when the certificate is confirmed bound to a Tencent Cloud resource, 0 otherwise (including the period after the first upload while waiting for a manual bind).",
	}, []string{"cert"})

	CertConsecutiveFailures = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_consecutive_failures",
		Help: "Consecutive failures. Reset to 0 by a successful pass.",
	}, []string{"cert"})

	CertARIWindowStart = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_ari_window_start_timestamp_seconds",
		Help: "Start of the ARI-suggested renewal window in unix seconds; 0 means not yet obtained.",
	}, []string{"cert"})

	// RevocationPending counts revocation requests the CA has not accepted yet.
	//
	// A non-zero value is an outstanding security action, not a background task: the row exists
	// because someone decided a certificate must stop being trusted, and the request is retried on
	// every pass until the CA accepts it. Without this gauge the whole revocation path was invisible
	// to monitoring -- the daemon logged, and nothing could alert.
	RevocationPending = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_revocation_pending",
		Help: "Revocation requests recorded but not yet accepted by the CA. Non-zero means a certificate that should no longer be trusted still is.",
	})

	// RevocationQueryErrors counts passes that could not read the outstanding revocation requests.
	//
	// RevocationPending is deliberately left at its last value when that read fails, so a failure
	// shows up as a frozen gauge rather than a wrong one. This counter is what separates "the queue
	// is genuinely empty" from "we have been unable to look for a week".
	RevocationQueryErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wecert_revocation_query_errors_total",
		Help: "Passes that could not read the outstanding revocation requests. wecert_revocation_pending is stale whenever this is increasing.",
	})

	// RateLimitRemaining reports how much of a published CA rate limit is left, as a LOWER
	// BOUND.
	//
	// The value counts only what this program spent, while "certs per registered domain" and
	// "certs per exact set of identifiers" are global across all accounts, so the true
	// remainder can be smaller -- never larger. It is published anyway because the number an
	// operator needs before a bulk change ("do 40 issuances still fit in this week's 50?") was
	// previously unavailable from anywhere: Let's Encrypt documents the limits and their token
	// bucket refill rates but offers no endpoint to query the remainder.
	RateLimitRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_ratelimit_remaining_tokens",
		Help: "Estimated tokens left in a published CA rate limit, counting only this program's own spend (a lower bound; the per-domain limits are global across accounts).",
	}, []string{"limit", "scope"})

	// RateLimitBlocked reports 1 while the CA has reported a deadline for a limit, which is
	// authoritative in a way the estimate cannot be: it accounts for every other spend the
	// estimate cannot see.
	RateLimitBlocked = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_ratelimit_blocked",
		Help: "1 when the CA has refused a request against this rate limit and reported when it will accept one again.",
	}, []string{"limit", "scope"})

	ReconcileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_reconcile_total",
		Help: "Reconcile passes. result=ok when a pass ran and succeeded, error when it ran and failed, skipped when it deliberately did not run because the certificate is inside its retry backoff window.",
	}, []string{"cert", "result"})

	// LastReconcile is when the last full pass finished, so "is this daemon converging at all?"
	// is answerable.
	//
	// Not derivable from the counters above: wecert_reconcile_total stops moving both when nothing
	// is due and when the loop is wedged, and those call for opposite responses. Not derivable from
	// the exposition's _created timestamps either -- promhttp.Handler() writes the classic text
	// format, which carries none. 0 means no pass has finished since this process started, which is
	// itself the answer for a daemon that never got through one.
	LastReconcile = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_last_reconcile_timestamp_seconds",
		Help: "Unix time the last full reconcile pass finished; 0 means none has finished since startup.",
	})

	ReconcilePanics = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_reconcile_panics_total",
		Help: "Passes that only completed because a panic inside the reconcile manager was recovered. Any nonzero value is a bug, not routine churn -- alert on it directly.",
	}, []string{"cert"})

	DesiredStateErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wecert_desired_state_errors_total",
		Help: "Passes skipped because the desired state could not be read. Skipping is deliberate: an unreadable source is never treated as an empty desired state.",
	})

	DesiredStateFrozen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_frozen",
		Help: "1 when the desired state is frozen on the last good revision (renewals continue, new names do not).",
	})

	DesiredStateCertificates = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_certificates",
		Help: "Number of certificates in the current desired state.",
	})

	DesiredStateAge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_age_seconds",
		Help: "Age of the desired-state document in seconds. A growing value means the onboarding component stopped refreshing it.",
	})

	DesiredStateShadowDiff = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_shadow_diff",
		Help: "In observe mode, the number of certificate-level differences between what is enforced and what the shadow source asks for. Should stay at 0 before switching to enforce. Only meaningful while wecert_desired_state_shadow_errors_total is not increasing and _last_read is recent.",
	})

	// DesiredStateShadowErrors counts passes where the shadow source could not be read at
	// all, so no comparison happened.
	//
	// Without it the diff gauge simply kept its previous value -- including 0 -- while
	// nothing was being compared, and its own help text tells operators to gate the switch
	// to enforce on that 0. An observe-mode document that was readable at startup and then
	// disappeared produced exactly that false confidence.
	DesiredStateShadowErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wecert_desired_state_shadow_errors_total",
		Help: "Passes in which the shadow desired-state source could not be read, so no comparison was produced. Non-zero means wecert_desired_state_shadow_diff is stale.",
	})

	// DesiredStateShadowLastRead is the unix time of the last successful shadow
	// comparison (0 = never), so "is the diff gauge fresh?" is answerable.
	DesiredStateShadowLastRead = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_shadow_last_read_timestamp_seconds",
		Help: "Unix time of the last successful shadow comparison in observe mode. If this stops advancing, the diff gauge is stale regardless of its value.",
	})

	OrphanedCertificates = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_orphaned_certificates",
		Help: "Certificates present in the state store but absent from the desired state. They will not be renewed and will eventually expire.",
	})

	CertificateProbeMatch = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_match",
		Help: "1 when the certificate actually served for this host is the one that was deployed, 0 otherwise. Only set after a probe that completed.",
	}, []string{"host"})

	CertificateProbeNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_not_after_timestamp_seconds",
		Help: "notAfter read back from a real TLS handshake, in unix seconds. Compare against wecert_certificate_not_after_timestamp_seconds to see whether the rebind actually took effect.",
	}, []string{"host"})

	CertificateProbeTrusted = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_trusted",
		Help: "1 when the served chain validates against the system roots. 0 is not necessarily broken (an internal CA is legitimate) but browsers will warn.",
	}, []string{"host"})

	CertificateProbeErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_certificate_probe_errors_total",
		Help: "Probes that could not be completed at all (resolve, dial or handshake failed). Distinct from probe_match=0, which means the probe succeeded and found the wrong certificate.",
	}, []string{"host"})

	CertificateFallbackActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_fallback_active",
		Help: "1 when this certificate is being served by a partial certificate with some names dropped (failure fallback). Partial availability beats total failure, but this is not a state to leave unattended.",
	}, []string{"cert"})

	CertificateFallbackDropped = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_fallback_dropped_names",
		Help: "How many names were dropped from the certificate currently served by the failure fallback. The names themselves are in the state store and in the logs.",
	}, []string{"cert"})
)

// DeleteCertSeries removes every per-certificate series for a name that is no longer
// in the desired state.
//
// These vecs are only ever written for names in the *current* desired state, so
// nothing revisits the ones that left it: their series stay exported at their last
// value forever. The visible symptom is a not_after series frozen at its last value,
// which the documented expiry rule -- (not_after - now) < 21 days -- turns into a
// permanent alert for a certificate that no longer exists. Over a long-lived daemon
// that is also unbounded series growth, since certificate names are derived from
// registered domains and domains churn by design.
func DeleteCertSeries(name string) {
	for _, v := range []*prometheus.GaugeVec{
		CertNotAfter,
		CertDeployed,
		CertConsecutiveFailures,
		CertARIWindowStart,
		CertificateFallbackActive,
		CertificateFallbackDropped,
	} {
		v.DeleteLabelValues(name)
	}
	// ReconcileTotal carries a second label (result), so a full-label delete
	// cannot name it; a partial match on cert covers every result value.
	ReconcileTotal.DeletePartialMatch(prometheus.Labels{"cert": name})
	ReconcilePanics.DeleteLabelValues(name)
}

// DeleteProbeSeries removes every per-host probe series for a host that is no longer
// probed. See DeleteCertSeries for why the reclamation has to be explicit.
func DeleteProbeSeries(host string) {
	CertificateProbeMatch.DeleteLabelValues(host)
	CertificateProbeNotAfter.DeleteLabelValues(host)
	CertificateProbeTrusted.DeleteLabelValues(host)
	CertificateProbeErrors.DeleteLabelValues(host)
}
