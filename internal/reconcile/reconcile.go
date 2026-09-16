// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// ErrAlreadyRunning means this certificate already has a pass in flight.
//
// This is not exceptional; it is a gate that must exist: the timer and an
// event-triggered convergence very likely land on the same certificate at the
// same time. Two orders from the two sides run straight into "5 certificates
// per exact set of identifiers / 7 days" — and that limit has no override.
var ErrAlreadyRunning = errors.New("this certificate already has a pass in flight")

// Notifier is notified after each certificate finishes processing. May be nil.
//
// It lives on this layer rather than in the webhook layer so the "renewal
// result" event goes out the same way whether the timer or an external trigger
// started the pass.
type Notifier interface {
	Renewal(ctx context.Context, certName string, err error)
}

// CertManager is the capability Reconciler needs.
//
// It is an interface rather than a direct *acme.Manager dependency so the
// convergence loop is testable — depending on the concrete type would mean
// orchestration logic like "one certificate failing must not stall the others"
// could only be verified by really running ACME.
type CertManager interface {
	Reconcile(ctx context.Context, c *config.Certificate) error
	ReapRetired(ctx context.Context)
}

// Reconciler converges the certificates in the current desired state one by one.
//
// Concurrency-safe: the timer loop and webhook-triggered convergence call it at
// the same time, and the running map keeps one certificate from being processed
// concurrently.
type Reconciler struct {
	cfg      *config.Config
	provider spec.Provider
	store    *state.Store
	manager  CertManager
	notifier Notifier
	log      *slog.Logger

	mu      sync.Mutex
	running map[string]struct{}

	// prober is the optional network-side prober. Nil means no probing.
	//
	// It is attached with SetProber instead of being a New parameter: it is purely
	// additional observation and should not force every test double to construct
	// one.
	prober *probe.Runner

	// last is the most recently resolved desired state, for read-only diagnostics.
	// A pointer is required: the diagnostic endpoint reads it from another
	// goroutine.
	last atomic.Pointer[spec.Result]
}

// SetProber attaches the network-side prober. Must be called before the first
// convergence. Passing nil makes the whole probe path a no-op, so convergence
// behaves exactly as if none were attached.
func (r *Reconciler) SetProber(p *probe.Runner) { r.prober = p }

// New builds a reconciler.
//
// provider is the source of the desired state: spec.Static (the certificates in
// the config), spec.File (the document onboarding writes) or spec.Observer (the
// former plus shadow comparison). The convergence logic does not care which —
// that is exactly why switching sources requires no changes here.
func New(cfg *config.Config, provider spec.Provider, store *state.Store, manager CertManager, notifier Notifier, log *slog.Logger) *Reconciler {
	return &Reconciler{
		cfg:      cfg,
		provider: provider,
		store:    store,
		manager:  manager,
		notifier: notifier,
		log:      log,
		running:  make(map[string]struct{}),
	}
}

// acquire tries to claim a certificate. False means someone is already running it.
func (r *Reconciler) acquire(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.running[name]; busy {
		return false
	}
	r.running[name] = struct{}{}
	return true
}

func (r *Reconciler) release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, name)
}

// ── Desired state ────────────────────────────────────────────────────────────────

// Prime resolves the desired state once and caches it, triggering no
// convergence.
//
// Call it once at startup so read-only endpoints (webhook name resolution,
// diagnostics) give correct answers before the first convergence finishes.
func (r *Reconciler) Prime(ctx context.Context) {
	r.resolve(ctx)
}

// resolve resolves the desired state. A nil result means **nothing should be
// done this pass**.
//
// This is the most important failure semantic in the design: an unreadable
// desired state never means an empty one. The latter makes wecert strip domains
// from every certificate and the live endpoints fail handshakes immediately.
// Skipping a pass only costs "not renewed this time"; the next pass retries.
func (r *Reconciler) resolve(ctx context.Context) *spec.Result {
	res, err := spec.Desired(ctx, r.provider)
	if err != nil {
		metrics.DesiredStateErrors.Inc()
		r.log.Error("cannot read the desired state; skipping this pass entirely "+
			"(an unreadable source is never treated as an empty desired state)",
			"provider", spec.KindOf(r.provider), "err", err)
		return nil
	}

	r.last.Store(res)
	r.publishDesired(res)
	return res
}

// LastResult returns the most recently resolved desired state; may be nil.
func (r *Reconciler) LastResult() *spec.Result { return r.last.Load() }

// CertNames returns the certificate names in the current desired state, in its
// order.
//
// It reads the cache instead of re-resolving: re-reading the source on every
// call would tie an HTTP request's latency to the cloud API's response time.
func (r *Reconciler) CertNames() []string {
	res := r.last.Load()
	if res == nil {
		return nil
	}
	return res.CertNames()
}

// publishDesired mirrors desired-state health into metrics and logs.
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
		age := time.Since(res.GeneratedAt)
		metrics.DesiredStateAge.Set(age.Seconds())
		if max := r.cfg.DesiredState.MaxStalenessDur; max > 0 && age > max {
			r.log.Error("the desired-state document is stale: the onboarding component has stopped refreshing it; "+
				"renewals keep working, but newly declared names will never be picked up",
				"generatedAt", res.GeneratedAt, "age", age.Round(time.Minute), "threshold", max)
		}
	}

	if res.Shadow != nil && res.Shadow.Error == "" {
		metrics.DesiredStateShadowDiff.Set(float64(len(res.Shadow.AddCertificates) +
			len(res.Shadow.RemoveCertificates) + len(res.Shadow.ChangeCertificates)))
	}
}

// publishOrphans reports certificates present in the state store but no longer
// in the desired state.
//
// They will not be renewed and will quietly expire. The desired-state deletion
// path already has a grace period and reference checks; this is the last safety
// net — if something still slips through, at least it is visible before expiry
// rather than only when a site fails a handshake.
func (r *Reconciler) publishOrphans(res *spec.Result) {
	names, err := r.store.ListCertNames()
	if err != nil {
		r.log.Warn("cannot list certificate names for the orphan check", "err", err)
		return
	}

	want := make(map[string]bool, len(res.Certificates))
	for i := range res.Certificates {
		want[res.Certificates[i].Name] = true
	}

	orphans := 0
	for _, name := range names {
		if want[name] {
			continue
		}
		orphans++

		attrs := []any{"cert", name}
		if st, err := r.store.GetCert(name); err == nil && st != nil && !st.NotAfter.IsZero() {
			attrs = append(attrs, "notAfter", st.NotAfter,
				"daysLeft", int(time.Until(st.NotAfter).Hours()/24))
		}
		r.log.Error("this certificate is no longer in the desired state, so it will not be renewed "+
			"and will expire; if that was not intended, restore its declaration and re-run wecert-onboard",
			attrs...)
	}
	metrics.OrphanedCertificates.Set(float64(orphans))
}

// ── Convergence ────────────────────────────────────────────────────────────────────

// RunAll runs one pass over every certificate.
//
// One certificate failing does not abort the pass: otherwise a certificate with
// a mistyped domain stalls every other certificate's renewal — the most
// dangerous kind of coupling in automation.
//
// Certificates already being processed elsewhere are skipped and listed.
func (r *Reconciler) RunAll(ctx context.Context) (skipped []string) {
	res := r.resolve(ctx)
	if res == nil {
		// Reap retired certificates even when the desired state is unreadable: they
		// have already been replaced, reaping them is unrelated to the desired state,
		// and ignoring them slowly exhausts the cloud certificate quota.
		r.manager.ReapRetired(ctx)
		return nil
	}
	r.publishOrphans(res)

	for i := range res.Certificates {
		c := &res.Certificates[i]

		if err := ctx.Err(); err != nil {
			return skipped
		}

		if !r.acquire(c.Name) {
			r.log.Info("skipping: this certificate already has a pass in flight", "cert", c.Name)
			skipped = append(skipped, c.Name)
			continue
		}
		r.reconcileOne(ctx, c)
		r.release(c.Name)
	}

	r.manager.ReapRetired(ctx)
	return skipped
}

// RunOnce is a compatibility alias for RunAll.
func (r *Reconciler) RunOnce(ctx context.Context) {
	r.RunAll(ctx)
}

// RunCert processes exactly one named certificate. An unknown name returns an
// error; one already being processed returns ErrAlreadyRunning.
func (r *Reconciler) RunCert(ctx context.Context, name string) error {
	res := r.resolve(ctx)
	if res == nil {
		return fmt.Errorf("cannot read the desired state, so %q was not processed", name)
	}
	found := res.Find(name)
	if found == nil {
		return fmt.Errorf("no certificate named %q in the desired state", name)
	}

	if !r.acquire(name) {
		return ErrAlreadyRunning
	}
	defer r.release(name)

	r.reconcileOne(ctx, found)
	return nil
}

// StartCert processes one certificate asynchronously.
//
// Resolution and claiming are **synchronous** — so "is this certificate already
// being processed" and "does this name exist" are answered to the caller
// immediately; the actual convergence goes to the background because it can
// take minutes (DNS propagation) and making the HTTP request wait would blow
// the caller's timeout.
//
// ctx must be a **process-level** context, never a request context: it is
// cancelled the moment the response returns, killing the background pass.
func (r *Reconciler) StartCert(ctx context.Context, name string) error {
	res := r.resolve(ctx)
	if res == nil {
		return fmt.Errorf("cannot read the desired state, so %q was not processed", name)
	}
	found := res.Find(name)
	if found == nil {
		return fmt.Errorf("no certificate named %q in the desired state", name)
	}

	if !r.acquire(name) {
		return ErrAlreadyRunning
	}

	// res is heap-allocated and not reused during this pass, so referring to its
	// elements is safe.
	go func() {
		defer r.release(name)
		r.reconcileOne(ctx, found)
	}()
	return nil
}

// StartAll processes every certificate asynchronously and synchronously returns
// the skipped (already running) names.
func (r *Reconciler) StartAll(ctx context.Context) []string {
	res := r.resolve(ctx)
	if res == nil {
		return nil
	}

	var skipped []string
	for _, name := range res.CertNames() {
		if err := r.StartCert(ctx, name); err != nil {
			skipped = append(skipped, name)
		}
	}
	return skipped
}

// reconcileOne processes one certificate and mirrors the result into metrics
// and notifications.
func (r *Reconciler) reconcileOne(ctx context.Context, c *config.Certificate) {
	err := r.safeReconcile(ctx, c)
	if err != nil {
		metrics.ReconcileTotal.WithLabelValues(c.Name, "error").Inc()
		// manager already logged and scheduled backoff; this is just a summary.
		r.log.Warn("this pass did not succeed", "cert", c.Name, "err", err)
	} else {
		metrics.ReconcileTotal.WithLabelValues(c.Name, "ok").Inc()
	}

	r.publish(c.Name)
	r.probeCert(ctx, c)

	if r.notifier != nil {
		r.notifier.Renewal(ctx, c.Name, err)
	}
}

// safeReconcile calls the manager and recovers from a panic inside it.
//
// This is the single choke point every reconcile path goes through (RunAll's
// loop, RunCert, and StartCert's goroutine), so it is the one place a recover
// here protects all of them. Without it, one certificate hitting an
// unanticipated nil pointer or index-out-of-range would not just fail that
// certificate -- Go terminates the whole process on an unrecovered panic in any
// goroutine, taking down every other certificate's renewal with it. That is
// exactly the coupling RunAll's own comment says must never happen, and a
// panic is the one failure mode a plain error return cannot guard against.
//
// The certificate's on-disk state at the moment of the panic is unknown (the
// manager may have crashed between two writes), so this cannot call
// recordFailure itself -- it only reports the outcome; the caller's normal
// error handling (metrics, logging, notification) takes it from there, and the
// certificate's own next scheduled pass decides fresh from whatever ended up on
// disk.
func (r *Reconciler) safeReconcile(ctx context.Context, c *config.Certificate) (err error) {
	defer func() {
		if p := recover(); p != nil {
			metrics.ReconcilePanics.WithLabelValues(c.Name).Inc()
			r.log.Error("recovered from a panic while reconciling this certificate; "+
				"the process keeps running, every other certificate is unaffected, "+
				"and the next scheduled pass will retry this one",
				"cert", c.Name, "panic", p, "stack", string(debug.Stack()))
			err = fmt.Errorf("panic while reconciling %s: %v", c.Name, p)
		}
	}()
	return r.manager.Reconcile(ctx, c)
}

// probeCert dials a real TLS connection to confirm the live endpoint really
// serves the certificate that was just deployed.
//
// It is the only evidence in the system that does not trust the cloud control
// plane. The control plane saying "bound successfully" and a browser actually
// getting the certificate are two things, and the gap between them — async
// rebinds, another certificate winning SNI — is where CLB fails most often.
//
// Failing to reach a conclusion **does not** affect this pass: a probe that
// cannot dial out must not make a successful renewal look failed. It only
// affects metrics and alerts.
func (r *Reconciler) probeCert(ctx context.Context, c *config.Certificate) {
	if r.prober == nil {
		return
	}

	// Probing something whose deployment is unconfirmed only produces errors — the
	// first upload needs a manual bind, and until then the live endpoint is still
	// serving the old certificate anyway.
	st, err := r.store.GetCert(c.Name)
	if err != nil || st == nil || !st.DeployConfirmed {
		return
	}

	hosts := probeHosts(c.Domains, r.cfg.Probe.MaxHostsPerCert)
	if len(hosts) == 0 {
		// Every name in this certificate is a wildcard: nothing concrete to dial.
		r.log.Debug("nothing to probe: every name in this certificate is a wildcard",
			"cert", c.Name, "domains", c.Domains)
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}

	e := probe.Expectation{
		Domains:     c.Domains,
		NotAfter:    st.NotAfter,
		MinValidFor: r.cfg.Probe.MinValidDur,
	}

	// Dial the names of one certificate concurrently. Serially, a 3-name
	// certificate takes 30 seconds when every probe times out, and this runs every
	// single pass.
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			// A panic here is a background probe, not an issuance step, but an
			// unrecovered panic in any goroutine still kills the whole process --
			// so a single bad handshake response must not be allowed to take
			// every certificate's renewal down with it either.
			defer func() {
				if p := recover(); p != nil {
					r.log.Error("recovered from a panic while probing a live endpoint",
						"cert", c.Name, "host", h, "panic", p, "stack", string(debug.Stack()))
				}
			}()
			r.prober.Check(ctx, h, e)
		}(host)
	}
	wg.Wait()
}

// probeHosts picks the dialable names out of one certificate's domains.
//
// Wildcards have no address of their own, so they are skipped; the rest are
// taken in declaration order up to max — declaration order puts the registered
// domain first, and that is usually the one most worth verifying.
func probeHosts(domains []string, max int) []string {
	if max <= 0 {
		return nil
	}
	out := make([]string, 0, max)
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			continue
		}
		out = append(out, d)
		if len(out) >= max {
			break
		}
	}
	return out
}

// publish mirrors the current state store into Prometheus.
func (r *Reconciler) publish(name string) {
	st, err := r.store.GetCert(name)
	if err != nil || st == nil {
		return
	}

	if st.NotAfter.IsZero() {
		metrics.CertNotAfter.WithLabelValues(name).Set(0)
	} else {
		metrics.CertNotAfter.WithLabelValues(name).Set(float64(st.NotAfter.Unix()))
	}

	// Only a confirmed swap to the new certificate counts as "deployed": the first
	// upload still needs a manual bind, and the light must not turn green before
	// then or the expiry alert will think everything is fine.
	if st.DeployConfirmed && st.DeployedCertID != "" {
		metrics.CertDeployed.WithLabelValues(name).Set(1)
	} else {
		metrics.CertDeployed.WithLabelValues(name).Set(0)
	}

	metrics.CertConsecutiveFailures.WithLabelValues(name).Set(float64(st.ConsecutiveFailures))

	if st.ARIWindowStart.IsZero() {
		metrics.CertARIWindowStart.WithLabelValues(name).Set(0)
	} else {
		metrics.CertARIWindowStart.WithLabelValues(name).Set(float64(st.ARIWindowStart.Unix()))
	}

	if !st.NotAfter.IsZero() {
		days := time.Until(st.NotAfter).Hours() / 24
		if days < 21 {
			r.log.Warn("certificate approaching expiry",
				"cert", name, "notAfter", st.NotAfter, "daysLeft", int(days),
				"consecutiveFailures", st.ConsecutiveFailures, "lastError", st.LastError)
		}
	}
}
