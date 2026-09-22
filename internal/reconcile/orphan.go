// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
	"time"
)

// Split from reconcile.go so one concern is one file. Same package.

func (r *Reconciler) publishDesired(res *spec.Result) {
	metrics.DesiredStateCertificates.Set(float64(len(res.Certificates)))

	if res.Frozen {
		metrics.DesiredStateFrozen.Set(1)
		r.log.Warn("the desired state is frozen on the last good revision; "+
			"renewals still run against it, but nothing new will be picked up until the source recovers",
			"provider", spec.KindOf(r.provider), "revision", res.Revision, "reason", res.FreezeReason)
	} else {
		metrics.DesiredStateFrozen.Set(0)
	}

	// Document age is the failure signal unique to this architecture: after the
	// onboarding component dies, wecert keeps renewing from the old document quite
	// normally, everything looks fine, only no new domain ever enters.
	if !res.GeneratedAt.IsZero() {
		// Clamped at zero: a document written moments in the future -- a small NTP
		// correction between the generator and this process -- otherwise reports a negative
		// age, which is nonsense on a "how stale is this" gauge and would make the staleness
		// comparison below look satisfied for longer than it should. The skew itself is
		// bounded by spec's generatedAt check, so this only absorbs a small clock difference.
		age := time.Since(res.GeneratedAt)
		if age < 0 {
			age = 0
		}
		metrics.DesiredStateAge.Set(age.Seconds())
		if max := r.cfg.DesiredState.MaxStalenessDur; max > 0 && age > max {
			r.log.Error("the desired-state document is stale: the onboarding component has stopped refreshing it; "+
				"renewals keep working, but newly declared names will never be picked up",
				"generatedAt", res.GeneratedAt, "age", age.Round(time.Minute), "threshold", max)
		}
	}

	if res.Shadow != nil {
		if res.Shadow.Error == "" {
			metrics.DesiredStateShadowDiff.Set(float64(len(res.Shadow.AddCertificates) +
				len(res.Shadow.RemoveCertificates) + len(res.Shadow.ChangeCertificates)))
			metrics.DesiredStateShadowLastRead.Set(float64(time.Now().Unix()))
		} else {
			// No comparison was produced. Leaving the gauge at its previous value (often
			// 0) while incrementing nothing is how "we could not tell" reads as "they
			// agree" -- and the gauge's own help text tells operators to gate the switch
			// to enforce on that 0.
			metrics.DesiredStateShadowErrors.Inc()
		}
	}
}

// publishOrphans reports certificates present in the state store but no longer
// in the desired state.
//
// They will not be renewed and will quietly expire. The desired-state deletion
// path already has a grace period and reference checks; this is the last safety
// net — if something still slips through, at least it is visible before expiry
// rather than only when a site fails a handshake.
func (r *Reconciler) publishOrphans(ctx context.Context, res *spec.Result) {
	rows, err := r.store.ListOrphanRows()
	if err != nil {
		r.log.Warn("cannot list certificate names for the orphan check", "err", err)
		return
	}

	want := make(map[string]bool, len(res.Certificates))
	for i := range res.Certificates {
		want[res.Certificates[i].Name] = true
	}

	orphans := 0
	for i := range rows {
		row := rows[i]
		if want[row.Name] {
			// Back in the desired state, so the mark has to go: it says "left the desired state and
			// was torn down", and leaving it set would let it outlive the condition it describes.
			// The next departure would then be skipped, and the name would keep whatever the pass
			// that brought it back left behind -- an order, its TXT records, its metric series.
			//
			// One statement per name that actually came back: zero on a normal pass, bounded by the
			// churn of the document rather than by the size of the fleet. The orphans are the ones
			// that repeat every pass, so they are the ones whose statements had to stop (see
			// state.ListOrphanRows).
			if !row.OrphanCleanedAt.IsZero() {
				if err := r.store.ClearOrphanCleaned(row.Name); err != nil {
					// Not fatal, never silent: a mark that stays set is exactly the state that makes
					// the next departure invisible to the teardown.
					r.log.Warn("cannot clear the orphan-clean mark of a certificate that is back in "+
						"the desired state, so it would not be torn down if it left again",
						"cert", row.Name, "err", err)
				}
			}
			continue
		}
		// The gauge answers "present in the store but not in the desired state", so it
		// counts every orphan FOUND -- including one whose teardown is deferred below
		// because its own pass is in flight. Counting only the torn-down ones dropped
		// the gauge to 0 during exactly the rounds an orphan existed but could not yet
		// be reclaimed, contradicting the metric's own help text.
		orphans++

		// Already torn down, and nothing has happened to the name since: a pass for it would have
		// cleared the mark (publish does that from the row it reads anyway), so the state the
		// teardown acted on cannot have changed underneath it.
		//
		// The report line below is deliberately KEPT, because nothing else will ever mention that
		// this certificate stopped being renewed. What stops is the SQL: the teardown, the store
		// read that fed it and the probe reclamation it triggered all already ran, and repeating
		// them every pass for a state that cannot change is what made a fleet with thousands of
		// orphans cost thousands of statements per pass, forever.
		if !row.OrphanCleanedAt.IsZero() {
			r.reportOrphan(row.Name, row.NotAfter, orphans > orphanLogLimit)
			continue
		}

		// A name can be absent from the desired state while a pass for it is still in
		// flight -- that is exactly what removing a certificate mid-issuance looks like,
		// and the pass may be parked in WaitAll for minutes waiting on DNS propagation.
		//
		// Tearing it down underneath itself is destructive and pointless. The teardown
		// deletes the authorization rows and, because the DNS provider's delete removes
		// EVERY TXT value at the challenge name, fires delete-all at a record the running
		// pass is waiting on. That pass then fails with a propagation error and backs off,
		// or -- if it already passed AcceptChallenge -- sends the CA to validate a record
		// that no longer exists, which books an identifier failure and feeds the failure
		// fallback. Its order URL is gone too, so the retry re-orders into the
		// exact-set quota.
		//
		// So leave a claimed name alone: its own pass owns the teardown, and the next round
		// reaps it once the claim is released. This is the same check the convergence loop
		// below makes; this function used to skip it.
		//
		// The claim is TAKEN, not merely looked at. Reading the flag and releasing the lock
		// immediately left a window in which a webhook-triggered pass claims the name, and the
		// teardown that follows deletes the TXT records and the order that pass is waiting on --
		// the exact interleaving the paragraph above exists to prevent, and it needs a webhook
		// request to arrive during the store read a few lines down. Holding the claim for the
		// teardown closes it: a pass that starts meanwhile is refused (and retried by its caller)
		// rather than run against a name being dismantled. The teardown is not a convergence pass,
		// so it claims the name only for the length of this block.
		if !r.acquire(row.Name) {
			r.log.Info("skipping the orphan teardown: a pass for this certificate is still running",
				"cert", row.Name)
			continue
		}

		// Only the first few get their own line (see orphanLogLimit): the count is what an operator
		// acts on, and 500 of these every pass -- which is what a deployment that dropped a whole
		// generated document looks like -- buries every other line in the journal, forever, because
		// the row is deliberately kept.
		r.tearDownOrphan(ctx, row.Name, orphans > orphanLogLimit)
	}
	metrics.OrphanedCertificates.Set(float64(orphans))
	if orphans > orphanLogLimit {
		r.log.Error("more certificates are no longer in the desired state than are listed above; they "+
			"will not be renewed and will expire unless their declarations come back",
			"orphans", orphans, "listed", orphanLogLimit,
			"metric", "wecert_orphaned_certificates",
			"listThem", "sqlite3 <statePath> \"SELECT name FROM certificates ORDER BY name\" and "+
				"compare against the desired-state document")
	}
}

// orphanLogLimit bounds the per-pass orphan lines at Error.
//
// Why a bound at all: an orphan is loud on purpose (nothing else will ever mention that a
// certificate stopped being renewed), but the state is persistent by design -- the row is kept so a
// re-added name resumes its history -- so the line repeats on every pass. At 500 orphans that is
// 500 ERROR lines per pass and 12,000 per day from one deployment, which is how a journal stops
// being read. The first few are listed with their names and expiry; the rest are counted, and the
// count is exported as wecert_orphaned_certificates.
const orphanLogLimit = 10

// tearDownOrphan reclaims everything a certificate that left the desired state still holds.
//
// The claim on the name is already held by the caller (see publishOrphans); this function
// releases it on every path, including a panic in the middle of the teardown, so a failure here
// cannot wedge the name against every later pass.
func (r *Reconciler) tearDownOrphan(ctx context.Context, name string, counted bool) {
	defer r.release(name)

	st, stErr := r.store.GetCert(name)

	// Reclaim whatever an in-flight issuance left behind. Until now nothing
	// ever tore down an order whose certificate left the desired state
	// mid-flight: its challenge leases stayed on DNSPod forever, and a stale
	// TXT value poisons every other certificate that writes the same
	// _acme-challenge name (a wildcard and its apex always share one).
	cleanupErr := r.manager.CleanupOrphan(ctx, name)
	if cleanupErr != nil {
		r.log.Warn("failed to reclaim the orphaned order and its TXT records", "cert", name, "err", cleanupErr)
	}

	// Reclaim the per-certificate series. Nothing else ever revisits a name that
	// has left the desired state, so its gauges would sit at their last value
	// forever -- and a not_after frozen at its last value trips the documented
	// expiry rule permanently, for a certificate that no longer exists.
	metrics.DeleteCertSeries(name)

	// The probe side has the same leak, per host: the served-certificate series
	// stay at their last value and the prober's transition memory grows with
	// every host ever seen. The hosts are not in the desired state anymore, so
	// they are recovered from the last issued certificate's SANs.
	if stErr == nil && st != nil {
		for _, host := range r.orphanProbeHosts(st) {
			metrics.DeleteProbeSeries(host)
			if p := r.getProber(); p != nil {
				p.Forget(host)
			}
		}
	}

	// The expiry comes from the row just read, when that read worked. The rest of the line is the
	// same one every later pass prints from the sweep's own read (see reportOrphan).
	var notAfter time.Time
	if stErr == nil && st != nil {
		notAfter = st.NotAfter
	}
	r.reportOrphan(name, notAfter, counted)

	// Mark the teardown as finished, LAST -- after the order and the TXT records were reclaimed,
	// after the per-certificate series were dropped and after the probe hosts were forgotten -- so
	// "marked" can only ever mean "there is nothing left to do for this name". Every later pass
	// reports the orphan and skips all of it (see publishOrphans).
	//
	// A teardown that FAILED is never marked: the order and the TXT records are still out there, and
	// recording it as finished would drop them for good -- nothing else revisits a name that has
	// left the desired state. The next pass retries it.
	//
	// The store refuses the mark while an order or an authorization row is left behind even when
	// the manager reported success (a TXT record that could not be reclaimed, or one still inside
	// its propagation window), which leaves the name unmarked on purpose for the same reason. That
	// refusal is not logged here -- the manager already said why it kept the row, and repeating it
	// every pass is the flood orphanLogLimit exists to stop.
	if cleanupErr != nil {
		return
	}
	marked, err := r.store.MarkOrphanCleaned(name)
	switch {
	case err != nil:
		// Not fatal: an unmarked name is simply torn down again next pass, which is the behaviour
		// this whole path had before the column existed.
		r.log.Warn("cannot record that the orphan teardown finished, so it will be repeated on the "+
			"next pass", "cert", name, "err", err)
	case !marked:
		r.log.Debug("the orphan teardown left an order or an authorization row behind, so it will be "+
			"retried on the next pass", "cert", name)
	}
}

// reportOrphan is the per-pass line for a certificate that is not in the desired state.
//
// It is shared by the two paths that produce it -- the pass that tears the name down and every
// later pass that finds it already torn down -- because the operator's signal has to read the same
// either way. What the durable mark changed is the SQL, deliberately not what the journal says:
// nothing else will ever mention that this certificate stopped being renewed.
//
// A zero notAfter (a row that could not be read, or one that was never issued) drops the expiry
// attributes rather than printing 1970, the same rule publish follows for the expiry series.
func (r *Reconciler) reportOrphan(name string, notAfter time.Time, counted bool) {
	attrs := []any{"cert", name}
	if !notAfter.IsZero() {
		attrs = append(attrs, "notAfter", notAfter,
			"daysLeft", config.DaysUntil(notAfter, time.Now()))
	}
	msg := "this certificate is no longer in the desired state, so it will not be renewed " +
		"and will expire; if that was not intended, restore its declaration and re-run wecert-onboard"
	if counted {
		// Past the limit the line still exists -- at Debug, so `-log-level=debug` or a journal query
		// can still name every one of them -- but it does not drown the pass summary.
		r.log.Debug(msg, attrs...)
		return
	}
	r.log.Error(msg, attrs...)
}

// orphanProbeHosts recovers the dialable names of a dropped certificate from the
// SANs of the last certificate that was issued for it.
//
// The desired state no longer carries the domains, and the state store does not
// persist them separately -- but the issued certificate does. A certificate that
// was never issued was also never probed (probing requires a confirmed deploy),
// so there is nothing to reclaim then.
func (r *Reconciler) orphanProbeHosts(st *state.CertState) []string {
	hosts := probeHosts(r.issuedSANs(st), r.cfg.Probe.MaxHostsPerCertOr(config.DefaultMaxHostsPerCert))
	if len(hosts) == 0 && st != nil && len(st.CertPEM) > 0 {
		// An orphan has no configured names to fall back to, so an unreadable certificate means the
		// per-host probe series cannot be reclaimed here. Say that, because the consequence is a
		// series frozen at its last value -- and if probe_match was 0 for one of those hosts, the
		// documented alert on it fires forever for a host nobody manages.
		r.log.Warn("cannot read the names out of the stored certificate of a certificate that left "+
			"the desired state, so its per-host probe series cannot be reclaimed automatically; "+
			"delete them by hand if one of them is frozen at 0",
			"cert", st.Name)
	}
	return hosts
}

// issuedSANs returns the names of the certificate actually stored for this certificate, or
// nil when there is none to parse.
//
// This is the authority on "what was deployed", and the probe comparison has to be made
// against it rather than against the configured domain set. They differ whenever a
// degradation is in force: the fallback deliberately issues a subset, so the live
// certificate is *supposed* to be missing the dropped names. Comparing against the config
// made probe.Verify report "the served certificate is missing names that were deployed" for
// every host of a degraded certificate, which drove wecert_certificate_probe_match to 0 --
// a gauge documented as the actionable "the rebind did not take effect" alert. A permanent
// false alarm on the metric that exists to catch a real failure is worse than no metric.
//
// Reading the certificate also avoids dialling the dropped names, whose DNS is broken by
// definition, so the probe error counter stops climbing on certificates that are behaving
// exactly as designed.
func (r *Reconciler) issuedSANs(st *state.CertState) []string {
	if st == nil || len(st.CertPEM) == 0 {
		return nil
	}
	block, _ := pem.Decode(st.CertPEM)
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// No warning here. The message used to live in this function and claim it was "falling back
		// to the configured names" -- which is what probeCert does with a nil answer, but this
		// function has no configured names and its other caller (orphanProbeHosts) has none at all:
		// a certificate that left the desired state still has its SANs nowhere else, so the honest
		// statement is "the names are unknown", and each caller now says what that costs it.
		return nil
	}
	return leaf.DNSNames
}

// ── Convergence ────────────────────────────────────────────────────────────────────

// RunReport summarizes what one full pass actually did.
//
// It exists so a caller can tell "everything worked" from "nothing ran" and from "something
// failed". A pass deliberately does not abort on the first bad certificate -- one mistyped domain
// must not stall every other renewal, the most dangerous kind of coupling in automation -- so the
// failures have to be reported rather than thrown.
//
// Without this the information was not merely discarded, it was unavailable: a one-shot run exited
// 0 with every certificate failing, so a systemd timer reported success while the fleet went
// unmanaged. Certificates already being processed elsewhere are skipped and listed.
type RunReport struct {
	// Attempted counts certificates whose pass ran, whether it succeeded or failed.
	Attempted int
	// Succeeded counts passes that completed without error.
	Succeeded int
	// Backoff counts passes that deliberately did not run because the certificate is
	// inside its retry window. Not a failure, but not progress either.
	Backoff int
	// Failed counts passes that ran and errored.
	Failed int
	// Skipped lists certificates whose pass was not started because one was already in
	// flight, so this round did not converge them. Not an error: the in-flight pass will.
	Skipped []string
	// DesiredStateUnreadable reports that the desired state could not be resolved, so no
	// certificate was considered at all.
	DesiredStateUnreadable bool
}

// Trouble reports whether this pass should be treated as a failure by a one-shot run.
//
// A plain "Failed > 0" is not enough on its own. A certificate whose retries are all inside a backoff
// window produces Backoff > 0 and Failed == 0, so a run that attempted nothing would look clean --
// which is exactly the state a certificate stuck in a long backoff sits in, and exactly what a caller
// running once per interval needs to hear about.
//
// Backoff and Skipped are both "attempted nothing", and they are the whole guard: the version of this
// function that checked only Skipped could never fire for the case its own comment was about, because
// an ErrBackoff pass increments Backoff and never appends to Skipped (see RunDetailed). The gap is
// reachable in practice, not theoretical: the backoff is 1m<<n capped at 6h, so after about seven
// consecutive failures it exceeds an hourly timer's interval, and from then on the unit exits 0 with
// a green journal while the certificate is not being renewed. README.md and
// docs/lifecycle-acceptance.md both document the exit code as the timer's only alert channel.
