// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"context"
	"errors"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
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

// ErrShuttingDown means the process is draining, so no new pass may start.
//
// It is a sentinel for the same reason as ErrDesiredStateUnavailable: "we are going away, try
// again after the restart" is a different answer from "that certificate is already running" and
// must not be reported as the latter. A pass started now would write its promotion, resume anchor
// or failure counter into a state store that the shutdown path closes as soon as Drain returns.
var ErrShuttingDown = errors.New("the reconciler is shutting down")

// Notifier is notified after each certificate finishes processing. May be nil.
//
// It lives on this layer rather than in the webhook layer so the "renewal
// result" event goes out the same way whether the timer or an external trigger
// started the pass.
type Notifier interface {
	Renewal(ctx context.Context, certName string, err error)
}

// Drainer is the optional capability a notifier has when it can wait for the notifications
// it has already accepted.
//
// Delivery is fire-and-forget: Notifier.Renewal hands the POST to a goroutine and returns.
// That is right while the process keeps running, but a one-shot run or a shutdown would
// otherwise exit with the POST in flight and lose it -- and the notification most worth
// keeping is the "result":"error" one. Optional because a test double should not have to
// implement a lifecycle it does not have; callers type-assert.
type Drainer interface {
	Drain(ctx context.Context)
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
	// PublishQuota refreshes the rate-limit gauges. Optional in spirit -- a manager that has
	// no quota accounting simply reports nothing -- but part of the interface because every
	// production manager has one.
	PublishQuota(scopes map[string][]string)
	QuotaStatus(scopes map[string][]string) []ratelimit.QuotaReport

	// RetryPendingRevocations re-attempts every revocation the CA has not accepted yet.
	RetryPendingRevocations(ctx context.Context)
	// PendingRevocations reports how many are still outstanding. Used both as the gate for the
	// retry and as the value of wecert_revocation_pending, so the two cannot disagree.
	PendingRevocations() (int, error)

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

	// bg counts the passes started by the webhook surface, so shutdown can wait for them.
	//
	// A pass can take minutes (DNS propagation), and the store, the ACME account and the process
	// are all shared with it. Nothing used to wait: on SIGTERM the daemon cancelled its context,
	// returned, and the deferred store.Close() closed SQLite under any pass still running -- so its
	// epilogue (promotion, resume-anchor PutOrder, authorization update, recordFailure) failed. The
	// worst case is the one this code already names elsewhere: an exit between an upload returning
	// an id and PutOrder recording it leaves a cloud certificate in neither certificates nor
	// retired_certificates, so it is billed and never reclaimed. Add happens before the goroutine
	// starts, so a pass still queued for a start slot is counted too.
	bg sync.WaitGroup

	// quotaPasses counts the webhook-triggered passes that are still running, so the quota gauges are
	// republished once when the last of them finishes rather than once per certificate. See startCert:
	// publishing is proportional to the scopes in the desired state, so per-certificate publication
	// made a full trigger quadratic in the fleet (11 million SQL statements at 500 certificates).
	quotaPasses atomic.Int64

	// bgMu serializes a pass's registration against Drain's transition to draining.
	//
	// sync.WaitGroup requires that a positive Add which starts from zero does not run concurrently
	// with Wait ("Note that calls with a positive delta that start when the counter is zero must
	// happen before a Wait"). The webhook's StartAll could Add while Drain was inside Wait -- the
	// HTTP server's Shutdown is asynchronous -- which Go reports as
	// "sync: WaitGroup is reused before previous Wait has returned", a process-fatal panic, and
	// which also let a pass start after Drain had returned and write into a closed store.
	bgMu sync.Mutex

	// draining is set under bgMu by Drain. After that, startCert refuses new passes.
	draining bool

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
	//
	// Guarded because SetProber is documented as "before the first convergence" but
	// nothing enforces that: a late call raced the webhook goroutines that read
	// r.prober during a pass. The contract stays; the data race goes.
	proberMu sync.RWMutex
	prober   prober

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
//
// Safe to call concurrently with a running pass (it replaces the pointer under the
// mutex), but "before the first convergence" is still the intended use: a pass
// already in flight keeps the prober it started with.
func (r *Reconciler) SetProber(p *probe.Runner) {
	r.proberMu.Lock()
	defer r.proberMu.Unlock()
	if p == nil {
		r.prober = nil
		return
	}
	r.prober = p
}

// getProber returns the attached prober, or nil. Every probe-path read goes
// through here rather than touching r.prober directly.
func (r *Reconciler) getProber() prober {
	r.proberMu.RLock()
	defer r.proberMu.RUnlock()
	return r.prober
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

// QuotaStatus returns the locally observed CA quota buckets for the most
// recently resolved desired state. It never resolves desired state on an HTTP
// request path; an unavailable cache simply yields no quota rows.
func (r *Reconciler) QuotaStatus() []ratelimit.QuotaReport {
	res := r.last.Load()
	if res == nil {
		return nil
	}
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
	return r.manager.QuotaStatus(map[string][]string{
		"registered-domain":    sortedKeys(registered),
		"exact-identifier-set": sortedKeys(sets),
		"identifier":           sortedKeys(identifiers),
	})
}

// publishDesired mirrors desired-state health into metrics and logs.
