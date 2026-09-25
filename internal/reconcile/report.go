// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
	"strings"
	"time"
)

// Split from reconcile.go so one concern is one file. Same package.

func (rep RunReport) Trouble() bool {
	if rep.Failed > 0 || rep.DesiredStateUnreadable {
		return true
	}
	// Backed-off certificates count too: they never land in Skipped (no pass was in
	// flight -- the manager deliberately did not run one), so without this a pass in
	// which every certificate sits inside its retry window reported Attempted == 0 and
	// nothing else, and a one-shot run exited 0 over a fleet making no progress.
	return rep.Attempted == 0 && (rep.Backoff > 0 || len(rep.Skipped) > 0)
}

// RunDetailed runs one pass over every certificate and reports what happened.
//
// One certificate failing does not abort the pass: otherwise a certificate with a mistyped domain
// would stall every other certificate's renewal, the most dangerous kind of coupling in
// automation. The failures are therefore reported through RunReport rather than by aborting.
//
// This is the only entry point for a whole pass. There used to be three (RunOnce, RunAll and this
// one), and the extra two were not harmless: RunOnce discarded the report entirely, which is how a
// one-shot systemd run came to exit 0 while every certificate failed. A caller that does not care
// about the outcome is better off saying so explicitly (`_ = r.RunDetailed(ctx)`) than calling a
// wrapper that cannot tell it.
func (r *Reconciler) RunDetailed(ctx context.Context) RunReport {
	var rep RunReport

	// Stamped on the way out, so the value means "a pass finished", never "a pass started". A pass
	// that hangs has to be able to go stale, otherwise a wedged daemon looks busy forever -- and
	// "nothing is happening" is invisible to every error counter in this package.
	//
	// Exclusively this function. StartAll, the webhook path, reconciles named certificates without
	// running a pass, so stamping it there would let an API caller mask a dead timer loop.
	defer metrics.LastReconcile.SetToCurrentTime()

	res := r.resolve(ctx)
	if res == nil {
		// Reap retired certificates even when the desired state is unreadable: they
		// have already been replaced, reaping them is unrelated to the desired state,
		// and ignoring them slowly exhausts the cloud certificate quota.
		rep.DesiredStateUnreadable = true
		r.passStepPanicSafe("reap retired certificates", func() { r.manager.ReapRetired(ctx) })
		r.passStepPanicSafe("retry revocations", func() { r.retryRevocations(ctx) })
		return rep
	}
	// Before anything is written this pass: is the database still the file this process opened, and
	// does it still hold the cross-process lock? SQLite and flock bind to the inode, so a state
	// directory removed (or a database restored) under a running daemon is invisible to every
	// read and write that follows -- the pass keeps converging into a file nothing will read again.
	for _, problem := range r.store.VerifyOnDisk() {
		r.log.Error("the state database underneath this process has changed", "problem", problem,
			"hint", "stop the daemon, restore the directory or the newest snapshot, then start it again")
	}

	r.publishOrphans(ctx, res)

	// The probe floor and the certificates finally meet here.
	//
	// In enforce mode the config's certificate list is empty by construction, so config.normalize's
	// check never sees the profiles the document actually uses: a floor longer than a shortlived
	// profile's validity then fails every probe of that certificate, pins
	// wecert_certificate_probe_match at 0 and fires the critical "not serving the deployed
	// certificate" alert with a diagnosis that blames the rebind. Reported rather than fatal: the
	// document is allowed to change between passes, and refusing to renew over a probe setting
	// would turn a monitoring misconfiguration into an outage.
	if err := config.CheckProbeFloor(r.cfg.Probe.MinValidDur, res.Certificates); err != nil {
		r.log.Error("the probe's minimum remaining validity cannot be satisfied by this desired "+
			"state, so probes of the certificate it names will fail while it is still valid",
			"err", err)
	}

	for i := range res.Certificates {
		c := &res.Certificates[i]

		if err := ctx.Err(); err != nil {
			// Cancelled mid-pass: the certificates not reached are neither succeeded nor
			// failed, and calling them failures would make an ordinary shutdown look like
			// an incident.
			return rep
		}

		if !r.acquire(c.Name) {
			r.log.Info("skipping: this certificate already has a pass in flight", "cert", c.Name)
			rep.Skipped = append(rep.Skipped, c.Name)
			continue
		}
		// defer inside the loop body so a panic in reconcileOne cannot leak the slot
		// and wedge every later pass with ErrAlreadyRunning.
		err := func() error {
			defer r.release(c.Name)
			return r.reconcileOne(ctx, c)
		}()

		switch {
		case errors.Is(err, state.ErrBackoff):
			rep.Backoff++
		case err != nil:
			rep.Attempted++
			rep.Failed++
		default:
			rep.Attempted++
			rep.Succeeded++
		}
	}

	r.passStepPanicSafe("reap retired certificates", func() { r.manager.ReapRetired(ctx) })
	r.passStepPanicSafe("retry revocations", func() { r.retryRevocations(ctx) })
	r.passStepPanicSafe("reclaim stale probe series", func() { r.reclaimStaleProbeSeries(res) })
	r.passStepPanicSafe("publish the quota gauges", func() { r.publishQuota(res) })
	r.passStepPanicSafe("sweep stuck TXT records", func() { r.sweepStuckTXT(ctx) })
	r.passStepPanicSafe("run the binding patrol", func() { r.runBindingPatrol(ctx) })
	return rep
}

// passStepPanicSafe runs one pass-level epilogue step inside its own recover.
//
// These steps are outside reconcileOne's panic fence: they run on the pass's own goroutine
// (RunDetailed, whose caller -- the timer loop in runDaemon -- has no recover) or, for the
// quota publication, on a webhook-started background goroutine, where an unrecovered panic is
// process-fatal. They are bookkeeping, not the pass's answer, so a panic in one is logged with
// its stack and the remaining steps still run -- the same contract publishPanicSafe gives the
// per-certificate work. No metric is counted: ReconcilePanics is labelled by certificate and a
// pass-level step has none.
func (r *Reconciler) passStepPanicSafe(step string, fn func()) {
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("recovered from a panic in a pass epilogue step; the rest of the pass "+
				"is unaffected. This is a bug, please report it",
				"step", step, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	fn()
}

// runBindingPatrol runs the account-wide binding audit if the manager can. Throttled
// inside the manager (hours, not passes): this catches console changes and orphan
// uploads that the per-certificate probe path never sees.
func (r *Reconciler) runBindingPatrol(ctx context.Context) {
	p, ok := r.manager.(BindingPatroller)
	if !ok {
		return
	}
	if counts, err := p.PatrolBindings(ctx); err != nil {
		r.log.Warn("binding patrol failed", "err", err)
	} else if counts != nil {
		r.log.Info("binding patrol finished", "counts", counts)
	}
}

// sweepStuckTXT runs the DNS cleanup guardian once per pass, independent of which
// certificates were walked. cleanupOrphanTXT only runs for a certificate that reached
// its no-order branch; a certificate that keeps renewing would otherwise never retry a
// leftover TXT from an older crash. Also mirrors the queue onto metrics so a stale
// _acme-challenge is visible without opening the read-only view.
func (r *Reconciler) sweepStuckTXT(ctx context.Context) {
	g, ok := r.manager.(TXTGuardian)
	if !ok {
		return
	}
	if retried, cleared, err := g.SweepStuckTXT(ctx); err != nil {
		r.log.Warn("DNS cleanup guardian sweep failed", "err", err)
	} else if retried > 0 {
		r.log.Info("DNS cleanup guardian retried stuck TXT reclaims",
			"retried", retried, "cleared", cleared)
	}
	rows, err := g.ListStuckTXTReclaims()
	if err != nil {
		r.log.Warn("cannot list stuck TXT reclaims for metrics", "err", err)
		return
	}
	metrics.TXTReclaimStuck.Set(float64(len(rows)))
	metrics.TXTReclaimStuckOldestSeconds.Set(StuckTXTLagSeconds(rows, time.Now()))
}

// StuckTXTLagSeconds is the age of the oldest stuck reclaim (0 when empty).
func StuckTXTLagSeconds(rows []*state.TXTReclaimStuck, now time.Time) float64 {
	var oldest float64
	for _, e := range rows {
		if e.StuckSince.IsZero() {
			continue
		}
		if age := now.Sub(e.StuckSince).Seconds(); age > oldest {
			oldest = age
		}
	}
	return oldest
}

// publishQuota refreshes the rate-limit gauges from the desired state this pass resolved.
//
// The scopes are derived here rather than asked of the manager: the manager does not know
// which registered domains or identifier sets this deployment cares about, and inventing them
// would mean a DNS lookup per certificate per pass. Using the resolved document keeps it free.
func (r *Reconciler) publishQuota(res *spec.Result) {
	if res == nil {
		return
	}
	// Every scope this deployment actually spends against, not one representative per family.
	//
	// Publishing only the first certificate's first domain meant the per-domain and per-identifier
	// series existed for exactly one scope: for the normal one-certificate-per-domain layout,
	// WecertRateLimitNearlyExhausted could never fire for any other domain -- the series it
	// compares against was simply absent, and an absent series reads as "nothing to see". The sets
	// are deduplicated because two certificates routinely share a registered domain (a wildcard and
	// its apex, a multi-name certificate).
	registered := map[string]bool{}
	identifiers := map[string]bool{}
	sets := map[string]bool{}
	for i := range res.Certificates {
		c := &res.Certificates[i]
		for _, d := range c.Domains {
			if rd := group.RegisteredDomain(d); rd != "" {
				registered[rd] = true
			}
			identifiers[strings.ToLower(d)] = true
		}
		if key := c.DomainKey(); key != "" {
			sets[key] = true
		}
	}
	r.manager.PublishQuota(map[string][]string{
		"registered-domain":    sortedKeys(registered),
		"exact-identifier-set": sortedKeys(sets),
		"identifier":           sortedKeys(identifiers),
	})
}

// retryRevocations re-attempts outstanding revocations and publishes how many remain.
//
// Revocation is unbounded in time on purpose: a request recorded because a key leaked must keep
// being attempted until the CA accepts it, and it must not be forgotten because the process
// restarted or the CA was briefly unavailable.
//
// Both halves live here, off one query, because they answer the same question. The retry used to be
// gated on a separate HasPendingRevocations() call to keep the common case cheap; once the gauge
// also had to be maintained, that gate saved nothing and only created a second place for the two
// answers to disagree.
func (r *Reconciler) retryRevocations(ctx context.Context) {
	pending, err := r.manager.PendingRevocations()
	if err != nil {
		// Leave the gauge where it is. Reporting 0 here would be a confident all-clear on the one
		// signal that means "a certificate that should no longer be trusted still is", and a stale
		// number is recoverable where a false zero pages nobody. The counter is what makes the
		// staleness visible.
		metrics.RevocationQueryErrors.Inc()
		r.log.Warn("cannot read outstanding revocations; wecert_revocation_pending is now stale",
			"err", err)
		return
	}
	// Published from the same read that gates the retry, so the number the gauge shows is exactly
	// the number of requests the retry was asked to work through. A request this pass succeeds in
	// clearing therefore stays visible until the next pass; erring towards "still pending" is the
	// safe direction for a security signal.
	defer metrics.RevocationPending.Set(float64(pending))
	if pending == 0 {
		return
	}
	r.manager.RetryPendingRevocations(ctx)
}

// reclaimStaleProbeSeries drops the per-host probe metric series of hosts that are no
// longer probed.
//
// The probe vectors are labelled by host while DeleteCertSeries is labelled by
// certificate, so a certificate leaving the desired state -- or simply losing a name from
// its SAN set -- strands that host's series at its last value forever. Since
// wecert_certificate_probe_match{host} == 0 is documented as "a rebind did not take
// effect", a frozen 0 is a permanent false alert, and host churn makes it unbounded series
// growth as well.
//
// The set of hosts that ever ran a probe comes from the runner, which records a state for
// every host it checks; this round's set is recorded by probeCert. Only the difference is
// reclaimed, so a host that simply was not probed this round (an unconfirmed deployment,
// a failed pass) keeps its series rather than flickering.
//
// res is the desired state the caller already resolved. It is a parameter rather than
// something this function fetches because it runs once per pass but judges one host at
// a time: resolving inside the per-host check meant a full document read, YAML decode,
// validation and hash -- plus resolve's metric and log side effects -- for EVERY
// candidate host of every pass.
