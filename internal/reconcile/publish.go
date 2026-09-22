// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"sort"
	"time"
)

// Split from reconcile.go so one concern is one file. Same package.

func (r *Reconciler) publish(c *config.Certificate) {
	st, err := r.store.GetCert(c.Name)
	if err != nil {
		// Say so. Everything below this line either sets or deletes series, so a silent return
		// leaves wecert_certificate_not_after_timestamp_seconds -- the series this project
		// documents as THE expiry signal -- reporting the previous pass's value while
		// wecert_last_reconcile keeps advancing, i.e. a stale number that looks freshly written.
		// There is no dedicated staleness counter for this read; the journal is the signal.
		r.log.Warn("cannot read this certificate's state, so its metric series keep their previous "+
			"values (including the expiry timestamp the alerts watch)", "cert", c.Name, "err", err)
		return
	}
	if st == nil {
		return
	}

	// The name is in the desired state -- a pass is running for it right now -- so an orphan-clean
	// mark on it is stale, and it has to go before the series below are written.
	//
	// publishOrphans clears the mark too, and for the whole desired state at once. This second,
	// per-certificate clear is not redundant: StartCert and StartAll reconcile a name, or the whole
	// document, WITHOUT running a pass, so the orphan sweep never sees that the name came back. A
	// mark left behind there is not harmless -- the name would be skipped on its next departure,
	// keeping the order, the TXT records and the series written just below, forever.
	//
	// Free in the common case: the row was already read, and the write happens only when it carries
	// a mark.
	if !st.OrphanCleanedAt.IsZero() {
		if err := r.store.ClearOrphanCleaned(c.Name); err != nil {
			r.log.Warn("cannot clear the orphan-clean mark of a certificate that is back in the "+
				"desired state, so it would not be torn down again if it left",
				"cert", c.Name, "err", err)
		}
	}

	// A certificate that was never issued has no expiry, and the series must be ABSENT
	// rather than zero.
	//
	// The state schema documents `not_after = 0` as "never issued", and this exported the
	// zero straight through — so the series read as 1970-01-01. The alert rule this project
	// documents as the PRIMARY expiry signal is
	//
	//	(wecert_certificate_not_after_timestamp_seconds - time()) / 86400 < 21
	//
	// and for a never-issued certificate that evaluates to roughly -20,700 days, which is
	// far below 21: it fires. So the first deployment of every new certificate pages
	// someone about a certificate that does not exist yet, with an "overdue by 57 years"
	// value. A false alarm on the one signal documented as the thing to alert on is worse
	// than no signal, because it teaches the reader to ignore it.
	//
	// Deleting the series makes the alert's own arithmetic honest: a certificate with no
	// expiry has no answer, so it is absent from the comparison instead of being compared
	// as 1970. "Never issued" remains visible — `wecert_certificate_deployed` is 0 and
	// `wecert_certificate_consecutive_failures` carries the retry count.
	// The profile label is never empty: the alert rules select on it, and an empty value would
	// silently match none of them -- a certificate whose profile fell through (a document written
	// before the field existed, a certificate built by hand) would then have an expiry series no
	// rule looks at.
	profile := c.Profile
	if profile == "" {
		profile = config.ProfileClassic
	}
	// Drop every series this certificate has before publishing under the current
	// profile. The profile is a label, so after a profile change the OLD profile's
	// series otherwise stays at its last value forever -- nothing ever writes it again,
	// and the per-profile expiry alert keeps comparing a frozen timestamp. A partial
	// delete is the same mechanism DeleteCertSeries uses: DeleteLabelValues cannot
	// express "every profile of this cert".
	metrics.CertNotAfter.DeletePartialMatch(prometheus.Labels{"cert": c.Name})
	if !st.NotAfter.IsZero() {
		metrics.CertNotAfter.WithLabelValues(c.Name, profile).Set(float64(st.NotAfter.Unix()))
	}

	// Only a confirmed swap to the new certificate counts as "deployed": the first
	// upload still needs a manual bind, and the light must not turn green before
	// then or the expiry alert will think everything is fine.
	if st.DeployConfirmed && st.DeployedCertID != "" {
		metrics.CertDeployed.WithLabelValues(c.Name).Set(1)
	} else {
		metrics.CertDeployed.WithLabelValues(c.Name).Set(0)
	}

	metrics.CertConsecutiveFailures.WithLabelValues(c.Name).Set(float64(st.ConsecutiveFailures))

	// Same rule as not_after: an unset ARI window is "no answer", not 1970. A zero here
	// would make any dashboard or ratio comparing the ARI window against another timestamp
	// describe a window that opened 57 years ago.
	if st.ARIWindowStart.IsZero() {
		metrics.CertARIWindowStart.DeleteLabelValues(c.Name)
	} else {
		metrics.CertARIWindowStart.WithLabelValues(c.Name).Set(float64(st.ARIWindowStart.Unix()))
	}

	// The threshold scales with the profile: a fixed window is most of a shortlived
	// certificate's life, which would warn from issuance onwards, every pass.
	if !st.NotAfter.IsZero() {
		if left := time.Until(st.NotAfter); left < config.ExpiryWarningThreshold(c.Profile) {
			r.log.Warn("certificate approaching expiry",
				"cert", c.Name, "profile", c.Profile, "notAfter", st.NotAfter,
				"daysLeft", config.DaysUntil(st.NotAfter, time.Now()),
				"consecutiveFailures", st.ConsecutiveFailures, "lastError", st.LastError)
		}
	}
}

// sortedKeys returns a map's keys in a stable order.
//
// Stable because the published series feed an alert: an unstable order would not change the metric
// values, but it does change the order of the Reset-then-Set window, and a reader comparing two
// scrapes should not have to wonder whether a scope moved or a value changed.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
