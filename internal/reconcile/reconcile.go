// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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

// ErrDesiredStateUnavailable means the desired state could not be read, so the
// requested pass did not start.
//
// It is a sentinel because callers must tell it apart from "the name is not
// managed": an unreadable source is transient and worth retrying, while an
// unknown name will still be unknown next time. The webhook maps the former to
// 503 and the latter to a plain "unknown" report -- collapsing them misreports
// an outage as "we do not manage that certificate".
var ErrDesiredStateUnavailable = errors.New("cannot read the desired state")

// ErrUnknownCert means the requested name is not in the current desired state.
var ErrUnknownCert = errors.New("no such certificate in the desired state")

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
	// CleanupOrphan reclaims the in-flight order and the challenge TXT records
	// of a certificate that has left the desired state. It must exist on this
	// interface rather than being optional: skipping it leaks _acme-challenge
	// rows on DNSPod forever, and a stale value poisons every other certificate
	// that shares the TXT name (a wildcard and its apex always do).
	CleanupOrphan(ctx context.Context, certName string) error
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

	// startSlots bounds how many certificates a full trigger converges at once.
	//
	// Without it, POST /hook/reconcile started one goroutine per certificate, so a
	// 100-certificate state fired 100 concurrent ACME orders, DNSPod writes and
	// Tencent Cloud calls from a single HTTP request -- while the timer path walks the
	// same certificates strictly one at a time. The bound matches the fan-out caps the
	// acme and probe packages already use.
	startSlots chan struct{}

	// prober is the optional network-side prober. Nil means no probing.
	//
	// It is attached with SetProber instead of being a New parameter: it is purely
	// additional observation and should not force every test double to construct
	// one. The field is an interface so the panic containment around a probe can be
	// exercised without a live TLS endpoint.
	prober prober

	// last is the most recently resolved desired state, for read-only diagnostics.
	// A pointer is required: the diagnostic endpoint reads it from another
	// goroutine.
	last atomic.Pointer[spec.Result]

	// probedHosts records every host this round actually probed, so the per-host metric
	// series of hosts that are no longer probed can be reclaimed.
	//
	// Without it those series live forever: they are labelled by host, so
	// metrics.DeleteCertSeries (which is labelled by certificate) cannot reach them, and
	// nothing else revisits a host after its certificate leaves the desired state. The
	// visible symptom is a wecert_certificate_probe_match{host} frozen at its last value
	// -- and the documentation tells operators to alert on that being 0, so a stale 0 is a
	// permanent false alarm.
	probeMu     sync.Mutex
	probedHosts map[string]struct{}
}

// prober is the network-side probe capability the reconciler needs.
type prober interface {
	Check(ctx context.Context, host string, e probe.Expectation) probe.Verdict
	// Forget drops the prober's remembered state for a host that has left the
	// desired state (see publishOrphans).
	Forget(host string)
}

// SetProber attaches the network-side prober. Must be called before the first
// convergence. Passing nil makes the whole probe path a no-op, so convergence
// behaves exactly as if none were attached.
//
// The nil check is not redundant with the interface field: storing a nil
// *probe.Runner in it would make r.prober != nil, and the probe path would then call
// Check on a nil runner instead of being skipped.
func (r *Reconciler) SetProber(p *probe.Runner) {
	if p == nil {
		r.prober = nil
		return
	}
	r.prober = p
}

// New builds a reconciler.
//
// provider is the source of the desired state: spec.Static (the certificates in
// the config), spec.File (the document onboarding writes) or spec.Observer (the
// former plus shadow comparison). The convergence logic does not care which —
// that is exactly why switching sources requires no changes here.
func New(cfg *config.Config, provider spec.Provider, store *state.Store, manager CertManager, notifier Notifier, log *slog.Logger) *Reconciler {
	return &Reconciler{
		cfg:         cfg,
		provider:    provider,
		store:       store,
		manager:     manager,
		notifier:    notifier,
		log:         log,
		running:     make(map[string]struct{}),
		startSlots:  make(chan struct{}, maxConcurrentStarts),
		probedHosts: map[string]struct{}{},
	}
}

// maxConcurrentStarts bounds the fan-out of a full webhook trigger. See
// Reconciler.startSlots.
const maxConcurrentStarts = 8

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

		st, stErr := r.store.GetCert(name)

		// Reclaim whatever an in-flight issuance left behind. Until now nothing
		// ever tore down an order whose certificate left the desired state
		// mid-flight: its challenge leases stayed on DNSPod forever, and a stale
		// TXT value poisons every other certificate that writes the same
		// _acme-challenge name (a wildcard and its apex always share one).
		if err := r.manager.CleanupOrphan(ctx, name); err != nil {
			r.log.Warn("failed to reclaim the orphaned order and its TXT records", "cert", name, "err", err)
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
				if r.prober != nil {
					r.prober.Forget(host)
				}
			}
		}

		attrs := []any{"cert", name}
		if stErr == nil && st != nil && !st.NotAfter.IsZero() {
			attrs = append(attrs, "notAfter", st.NotAfter,
				"daysLeft", int(time.Until(st.NotAfter).Hours()/24))
		}
		r.log.Error("this certificate is no longer in the desired state, so it will not be renewed "+
			"and will expire; if that was not intended, restore its declaration and re-run wecert-onboard",
			attrs...)
	}
	metrics.OrphanedCertificates.Set(float64(orphans))
}

// orphanProbeHosts recovers the dialable names of a dropped certificate from the
// SANs of the last certificate that was issued for it.
//
// The desired state no longer carries the domains, and the state store does not
// persist them separately -- but the issued certificate does. A certificate that
// was never issued was also never probed (probing requires a confirmed deploy),
// so there is nothing to reclaim then.
func (r *Reconciler) orphanProbeHosts(st *state.CertState) []string {
	if len(st.CertPEM) == 0 {
		return nil
	}
	block, _ := pem.Decode(st.CertPEM)
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		r.log.Warn("cannot parse the stored certificate to reclaim its probe series", "cert", st.Name, "err", err)
		return nil
	}
	return probeHosts(leaf.DNSNames, r.cfg.Probe.MaxHostsPerCert)
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
	r.publishOrphans(ctx, res)

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
		// defer inside the loop body so a panic in reconcileOne cannot leak the slot
		// and wedge every later pass with ErrAlreadyRunning.
		func() {
			defer r.release(c.Name)
			r.reconcileOne(ctx, c)
		}()
	}

	r.manager.ReapRetired(ctx)
	r.reclaimStaleProbeSeries()
	return skipped
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
func (r *Reconciler) reclaimStaleProbeSeries() {
	if r.prober == nil {
		return
	}
	all, ok := r.prober.(interface{ ProbedHosts() []string })
	if !ok {
		return
	}

	r.probeMu.Lock()
	current := r.probedHosts
	r.probedHosts = map[string]struct{}{}
	r.probeMu.Unlock()

	for _, h := range all.ProbedHosts() {
		if _, live := current[h]; live {
			continue
		}
		metrics.DeleteProbeSeries(h)
	}
}

// RunOnce is a compatibility alias for RunAll.
func (r *Reconciler) RunOnce(ctx context.Context) {
	r.RunAll(ctx)
}

// RunCert processes exactly one named certificate. An unknown name returns an
// error; one already being processed returns ErrAlreadyRunning. Unlike RunAll,
// the pass's own error is propagated: a caller that asked for one specific
// certificate needs to hear that it failed, not a bare "accepted".
func (r *Reconciler) RunCert(ctx context.Context, name string) error {
	res := r.resolve(ctx)
	if res == nil {
		return fmt.Errorf("%w, so %q was not processed", ErrDesiredStateUnavailable, name)
	}
	found := res.Find(name)
	if found == nil {
		return fmt.Errorf("%w: %q", ErrUnknownCert, name)
	}

	if !r.acquire(name) {
		return ErrAlreadyRunning
	}
	defer r.release(name)

	return r.reconcileOne(ctx, found)
}

// StartNamed processes a list of named certificates asynchronously, resolving the desired
// state ONCE.
//
// StartCert resolves the desired state itself, which is right for the single-name case
// (the caller has nothing resolved yet) and wrong for a caller looping over names:
// resolve() re-reads the file, decodes the YAML, validates it and hashes the document, so
// an N-name trigger paid that N times, all synchronously inside one HTTP request. This is
// the same N+1 the full-trigger path already fixed; the per-name path was left behind.
//
// The returned maps mirror what the caller needs to answer with: started, alreadyRunning,
// unknown. A non-nil error means the desired state could not be read, so nothing started
// and the buckets are meaningless.
func (r *Reconciler) StartNamed(ctx context.Context, names []string) (
	started, alreadyRunning, unknown []string, err error,
) {
	res := r.resolve(ctx)
	if res == nil {
		// No desired state: every name is unanswerable rather than unknown. Reporting
		// them as unknown would tell the caller to give up on certificates that may well
		// exist, so this is the transient-failure case, exactly as in StartAll -- the
		// caller must not answer 202 "accepted" for a convergence that cannot happen.
		return nil, nil, nil, fmt.Errorf(
			"%w, so none of %d requested certificate(s) was processed",
			ErrDesiredStateUnavailable, len(names))
	}

	// Dedupe while preserving order: a caller that lists the same name twice should not
	// get the second one back as "already running" purely because of its own duplicate.
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true

		found := res.Find(name)
		if found == nil {
			unknown = append(unknown, name)
			continue
		}
		if err := r.startCert(ctx, res, found); err != nil {
			alreadyRunning = append(alreadyRunning, name)
			continue
		}
		started = append(started, name)
	}
	return started, alreadyRunning, unknown, nil
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
// startCert launches one certificate's pass against an already-resolved desired
// state.
//
// The resolved result is a parameter rather than something the callee fetches,
// because resolve() costs a file read, a YAML decode, a full validation and a
// sha256 of the document -- and a full trigger would otherwise pay that once per
// certificate.
func (r *Reconciler) startCert(ctx context.Context, res *spec.Result, c *config.Certificate) error {
	if !r.acquire(c.Name) {
		return ErrAlreadyRunning
	}

	// res is heap-allocated and not reused during this pass, so referring to its
	// elements is safe.
	go func() {
		defer r.release(c.Name)

		// Queue for a start slot instead of running immediately. Nothing is dropped:
		// the caller has already been told "accepted", and the pass starts as soon as
		// a slot frees up.
		select {
		case r.startSlots <- struct{}{}:
			defer func() { <-r.startSlots }()
		case <-ctx.Done():
			// The process is shutting down while this pass is still parked on a
			// start slot. The caller was told "accepted", so say plainly that the
			// pass will never run -- otherwise the 202 is indistinguishable from a
			// pass that started and failed silently.
			r.log.Debug("shutdown while waiting for a start slot; the queued pass will not run", "cert", c.Name)
			return
		}

		r.reconcileOne(ctx, c)
	}()
	return nil
}

func (r *Reconciler) StartCert(ctx context.Context, name string) error {
	res := r.resolve(ctx)
	if res == nil {
		return fmt.Errorf("%w, so %q was not processed", ErrDesiredStateUnavailable, name)
	}
	found := res.Find(name)
	if found == nil {
		return fmt.Errorf("%w: %q", ErrUnknownCert, name)
	}
	return r.startCert(ctx, res, found)
}

// StartAll processes every certificate asynchronously and synchronously returns
// which ones were accepted and which were skipped (already running).
//
// The accepted list comes from the same resolution the starts were made from --
// not from a second, cached read -- so the two can never disagree about what was
// just triggered. A resolve failure is an error, not an empty result: reporting
// "accepted: all certificates" (from the last good cache) while nothing started
// is exactly the lie this return value exists to prevent.
func (r *Reconciler) StartAll(ctx context.Context) (accepted, skipped []string, err error) {
	res := r.resolve(ctx)
	if res == nil {
		return nil, nil, ErrDesiredStateUnavailable
	}

	// Walk the resolved slice directly: looking each name up with Find over the same
	// slice would make this O(n^2).
	for i := range res.Certificates {
		if err := r.startCert(ctx, res, &res.Certificates[i]); err != nil {
			skipped = append(skipped, res.Certificates[i].Name)
		} else {
			accepted = append(accepted, res.Certificates[i].Name)
		}
	}
	return accepted, skipped, nil
}

// reconcileOne processes one certificate and mirrors the result into metrics
// and notifications. The pass's error is returned for callers that need it
// (RunCert); RunAll and startCert deliberately discard it -- one failing
// certificate must not stall the others.
func (r *Reconciler) reconcileOne(ctx context.Context, c *config.Certificate) (err error) {
	// Contain a panic at the certificate boundary.
	//
	// Every caller of this function runs it for one certificate on behalf of all the
	// others -- twice from a goroutine, where an unrecovered panic takes the whole
	// process down. A single nil map write would then stop every other certificate
	// from renewing, which is the same "one failure blocks everything" coupling this
	// package exists to avoid. Recovering here turns it into an ordinary failed pass:
	// counted, logged with a stack, and retried on the usual backoff.
	defer func() {
		if p := recover(); p != nil {
			metrics.ReconcilePanics.WithLabelValues(c.Name).Inc()
			// The panic skipped the accounting below, so record the failed pass here --
			// otherwise reconcile_total under-reports exactly the passes that went worst.
			metrics.ReconcileTotal.WithLabelValues(c.Name, "error").Inc()
			r.log.Error("recovered from a panic: this certificate's pass was aborted, "+
				"the other certificates are unaffected; this is a bug, please report it",
				"cert", c.Name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = fmt.Errorf("panic while reconciling %s: %v", c.Name, p)
		}
	}()

	err = r.manager.Reconcile(ctx, c)
	if err != nil {
		metrics.ReconcileTotal.WithLabelValues(c.Name, "error").Inc()
		// manager already logged and scheduled backoff; this is just a summary.
		r.log.Warn("this pass did not succeed", "cert", c.Name, "err", err)
	} else {
		metrics.ReconcileTotal.WithLabelValues(c.Name, "ok").Inc()
	}

	r.publish(c)
	r.probeCert(ctx, c)

	if r.notifier != nil {
		r.notifier.Renewal(ctx, c.Name, err)
	}
	return err
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
	if err != nil || st == nil || !c.Deploy.Enabled || !st.DeployConfirmed {
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
			// A panic on a background goroutine is not recoverable by its parent, so
			// without this guard a parsing bug in one host's certificate takes the
			// whole daemon down -- and the probe is best-effort evidence, the least
			// important thing here to die for.
			defer func() {
				if p := recover(); p != nil {
					metrics.CertificateProbeErrors.WithLabelValues(h).Inc()
					r.log.Error("recovered from a panic while probing; the probe was abandoned",
						"host", h, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				}
			}()
			// Record the host before probing it: the series is about to be written, so it is
			// live from this moment on even if the probe itself fails.
			r.probeMu.Lock()
			r.probedHosts[h] = struct{}{}
			r.probeMu.Unlock()
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
func (r *Reconciler) publish(c *config.Certificate) {
	st, err := r.store.GetCert(c.Name)
	if err != nil || st == nil {
		return
	}

	if st.NotAfter.IsZero() {
		metrics.CertNotAfter.WithLabelValues(c.Name).Set(0)
	} else {
		metrics.CertNotAfter.WithLabelValues(c.Name).Set(float64(st.NotAfter.Unix()))
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

	if st.ARIWindowStart.IsZero() {
		metrics.CertARIWindowStart.WithLabelValues(c.Name).Set(0)
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
