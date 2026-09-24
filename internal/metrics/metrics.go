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
		Help: "notAfter of the live certificate, in unix seconds, by certificate and profile.",
		// The profile is a label because the profiles have different validities (90 days classic,
		// 45 tlsserver, 160 hours shortlived): an expiry warning expressed in days is either wrong
		// for a short-lived certificate for its whole life, or too late for it. With the label each
		// profile gets its own threshold.
	}, []string{"cert", "profile"})

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
		// Not "0 means not yet obtained": the reconcile loop DELETES this series when the window is
		// unset (reconcile.go, "an unset ARI window is 'no answer', not 1970"), so a rule written as
		// `== 0` would match nothing and never fire. Absence is the signal, and absence is what the
		// Help has to describe.
		Help: "Start of the ARI-suggested renewal window in unix seconds. The series is ABSENT when no window has been obtained (rather than 0, which would be 1970), so alert on its absence, not on a zero value.",
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

	// RateLimitRemaining reports how much of a published CA rate limit is left, as an UPPER
	// BOUND.
	//
	// The value counts only what this program spent, while "certs per registered domain" and
	// "certs per exact set of identifiers" are global across all accounts, so the true
	// remainder can be smaller -- never larger: it is "at most this much". (This comment and the
	// Help below said "a lower bound" until round 11; the wording is the same fact read backwards,
	// and it is the direction that matters, because "at least" invites spending quota that may not
	// be there. internal/ratelimit/tracker.go carries the full argument.) It is published anyway
	// because the number an operator needs before a bulk change ("do 40 issuances still fit in this
	// week's 50?") was previously unavailable from anywhere: Let's Encrypt documents the limits and
	// their token bucket refill rates but offers no endpoint to query the remainder.
	RateLimitRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_ratelimit_remaining_tokens",
		Help: "Estimated tokens left in a published CA rate limit, counting only this program's own spend. An UPPER BOUND: the per-registered-domain and per-exact-set limits are global across accounts, so the real remainder is at most this much. Read wecert_ratelimit_blocked for what the CA itself has refused.",
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

	BackupRemoteLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_backup_remote_last_success_timestamp_seconds",
		Help: "Unix time of the latest successful upload to a configured remote backup target; 0 means none has succeeded since process start.",
	}, []string{"target", "type"})

	BackupRemoteErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_backup_remote_errors_total",
		Help: "Remote state snapshot uploads that failed, by configured target and transport type.",
	}, []string{"target", "type"})

	// BackupRemoteConfiguredAt anchors the first-success alert. A target has no
	// success timestamp until its first upload, so comparing that timestamp with
	// time() alone would page immediately at process start.
	BackupRemoteConfiguredAt = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_backup_remote_configured_timestamp_seconds",
		Help: "Unix time this process configured a remote backup target.",
	}, []string{"target", "type"})

	BackupRemoteInterval = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_backup_remote_interval_seconds",
		Help: "Expected interval between remote state snapshot uploads, in seconds.",
	}, []string{"target", "type"})

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

	// TXTReclaimStuck is the DNS cleanup guardian queue: authorization rows whose _acme-challenge
	// TXT may still be in DNS and whose last reclaim could not be confirmed (authoritative NS
	// unreachable, or the provider cannot delete the record). Each row is retried every pass.
	TXTReclaimStuck = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_txt_reclaim_stuck",
		Help: "TXT challenge records whose cleanup could not be confirmed and is being retried (the DNS cleanup guardian queue). 0 means every leftover _acme-challenge has either been reclaimed or proven absent. Non-zero is safe to page on only together with the age gauge: a row stuck for five minutes is a retry, stuck for a day is an operator in the DNS console.",
	})

	// TXTReclaimStuckOldestSeconds is how long the oldest queue item has been stuck.
	TXTReclaimStuckOldestSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_txt_reclaim_stuck_oldest_seconds",
		Help: "Age in seconds of the oldest stuck TXT reclaim. 0 when the queue is empty. This is the number to alert on: wecert_txt_reclaim_stuck > 0 for one pass is noise (a flaky NS), the same oldest age climbing for hours means the record will not go away on its own.",
	})

	// BindingPatrolFindings counts the last full-binding patrol by kind
	// (confirmed / incomplete / drift / orphan_upload / unmanaged). The console maps
	// confirmed / incomplete / drift; orphan_upload and unmanaged are both drift to an
	// operator -- a cloud certificate that is not the one this deployment is serving.
	BindingPatrolFindings = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_binding_patrol_findings",
		Help: "Findings from the last periodic full-binding patrol, by kind. confirmed=incomplete=0 and drift=orphan_upload=unmanaged=0 means the account matches the state store. Non-zero drift after a console change is expected until the next deploy; non-zero orphan_upload means an upload lost its resume anchor.",
	}, []string{"kind"})

	// BindingPatrolLastRun is when the patrol last finished (unix seconds).
	BindingPatrolLastRun = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_binding_patrol_last_run_timestamp_seconds",
		Help: "Unix time the last full-binding patrol finished. If this stops advancing, the patrol is not running and the findings gauge is stale.",
	})

	OrphanedCertificates = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_orphaned_certificates",
		Help: "Certificates present in the state store but absent from the desired state. They are not renewed and their row is deliberately KEPT (so a re-added name resumes its history), so this gauge stays 1 until an operator deletes the row; it is not a transient condition.",
	})

	CertificateProbeMatch = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_match",
		Help: "1 when the certificate actually served for this host is the one that was deployed, 0 otherwise. 0 also covers a probe where SOME resolved addresses answered with the right certificate and others could not be reached: an unverified address is not a verified one, so read wecert_certificate_probe_errors_total next to it to tell the two apart.",
	}, []string{"host"})

	CertificateProbeNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_not_after_timestamp_seconds",
		Help: "notAfter read back from a real TLS handshake, in unix seconds. The series is ABSENT when the probe could not complete a handshake for this host, or completed only some of its addresses: a missing series means 'no answer for the whole host', not a stale one. To compare it with what was deployed, find the certificate whose SANs cover the host (the config, /hook/desired, or wecert_desired_state_certificates) and read wecert_certificate_not_after_timestamp_seconds{cert=...} -- the two families share no label, so there is no join.",
	}, []string{"host"})

	CertificateProbeTrusted = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_probe_trusted",
		Help: "1 when the served chain validates against the system roots. 0 is not necessarily broken (an internal CA is legitimate) but browsers will warn. The series is ABSENT when the probe could not complete a handshake for this host (or completed only some of its addresses), so a missing series is 'no answer' and a present one is a certificate the probe really read.",
	}, []string{"host"})

	CertificateProbeErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_certificate_probe_errors_total",
		Help: "Probe attempts that failed to resolve, dial or handshake. A non-zero value together with probe_match=0 means at least one address could not be checked -- an environment problem (a dead AAAA record, a firewall) rather than a wrong certificate; probe_match=0 with no such errors means every address answered and at least one served the wrong certificate.",
	}, []string{"host"})

	CertificateFallbackActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_fallback_active",
		// "in force", not "serving": the gauge is set when the degradation DECISION is taken (and
		// cleared only when a full certificate has been issued and deployed), so it covers the pass
		// that is about to issue the reduced set. That is deliberate -- the decision is the event an
		// operator can act on, and waiting for the deployment would hide a fallback whose own
		// issuance is failing -- but the help text used to claim the certificate was already being
		// served, which is not true for that first pass.
		Help: "1 while a failure fallback is in force for this certificate: names whose authorizations keep failing have been dropped, so the certificate it serves (or is about to serve) is partial. Partial availability beats total failure, but this is not a state to leave unattended.",
	}, []string{"cert"})

	CertificateFallbackDropped = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_fallback_dropped_names",
		// "in force", not "currently served", for the same reason as the sibling above: this is set
		// when the decision is taken, which is before the reduced certificate is issued or deployed.
		Help: "How many names the failure fallback has dropped for this certificate. The count describes the fallback IN FORCE, which on the first pass (and for as long as the reduced issuance keeps failing) is not yet what is being served: the previous, complete certificate is still live. The names themselves are in the state store and in the logs.",
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
	// CertNotAfter carries a second label (profile), and DeleteLabelValues requires exactly as many
	// values as the vector has labels -- passing one aborts the delete with an inconsistent-cardinality
	// panic, which is how a removed certificate's frozen expiry series survived reclamation. A partial
	// match names the cert label and removes every profile it was published under.
	CertNotAfter.DeletePartialMatch(prometheus.Labels{"cert": name})
	for _, v := range []*prometheus.GaugeVec{
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
// ClearProbeAnswer drops the two gauges that describe a certificate the probe READ, leaving
// probe_match and the error counter alone.
//
// It exists because "the probe cannot reach this host" is the one verdict for which those two values
// are not merely unproven but meaningless: keeping the last successful handshake's chain verdict and
// notAfter exports trusted=1 and a fresh-looking expiry for a host nobody can dial, which is the
// false green probe_match was already fixed for. DeleteProbeSeries is too blunt here -- it would take
// the error counter with it, and that counter is the evidence that the probe is the problem.
func ClearProbeAnswer(host string) {
	CertificateProbeNotAfter.DeleteLabelValues(host)
	CertificateProbeTrusted.DeleteLabelValues(host)
}

func DeleteProbeSeries(host string) {
	CertificateProbeMatch.DeleteLabelValues(host)
	CertificateProbeNotAfter.DeleteLabelValues(host)
	CertificateProbeTrusted.DeleteLabelValues(host)
	CertificateProbeErrors.DeleteLabelValues(host)
}
