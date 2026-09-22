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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
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
		r.manager.ReapRetired(ctx)
		r.retryRevocations(ctx)
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

	r.manager.ReapRetired(ctx)
	r.retryRevocations(ctx)
	r.reclaimStaleProbeSeries(res)
	r.publishQuota(res)
	return rep
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
func (r *Reconciler) reclaimStaleProbeSeries(res *spec.Result) {
	p := r.getProber()
	if p == nil {
		return
	}
	all, ok := p.(interface{ ProbedHosts() []string })
	if !ok {
		return
	}

	// Judge each candidate host against the desired state the pass already resolved.
	//
	// This used to resolve per host (inside hostIsUnconfirmed): every stale host paid a full
	// resolve -- a file read, a YAML decode, a validation pass and a sha256 of the document.
	// The scale work in round 11 measured the result at the default probe cap: 500 certificates, a
	// pass that reclaims stale hosts took 27.8 s against 0.18 s for the same pass with nothing to
	// reclaim (155x), and it is exactly O(staleHosts x fleetSize): 0.41/1.48/5.66/22.9 s at
	// 25/50/100/200 certificates. The hosts are also what a shrinking probe set produces -- removed
	// certificates or names -- so this is the shape of an ordinary fleet edit, not a corner case.
	//
	// hostOwner is nil when there is no store to judge deployment state from (a partially built
	// reconciler in tests): every stale host is then reclaimed, which is what the old helper did
	// for that case.
	var (
		hostOwner    map[string]string
		desiredNames map[string]bool
	)
	if r.store != nil {
		if res == nil {
			// No desired state: keep the series rather than deleting evidence.
			//
			// And keep the record of what was probed too. The per-round set used to be cleared
			// above, before this return, so "keep the evidence" threw away the very thing that
			// says which hosts are live: the next pass that DID resolve a document judged
			// every host last round probed -- and this round did not -- as stale, and deleted
			// the series this branch exists to preserve. One unreadable document was enough to
			// turn a whole round's probe evidence into deletions.
			return
		}
		hostOwner = make(map[string]string, len(res.Certificates))
		desiredNames = make(map[string]bool, len(res.Certificates))
		for i := range res.Certificates {
			c := &res.Certificates[i]
			desiredNames[c.Name] = true
			for _, d := range probeHosts(c.Domains, len(c.Domains)) {
				// First certificate wins, matching the old helper's "return on the first match"
				// order: a host covered by two certificates must be judged by the one the document
				// lists first, not by whichever happened to be written last into the map.
				if _, seen := hostOwner[d]; !seen {
					hostOwner[d] = c.Name
				}
			}
		}
	}
	// A pass for a certificate the desired state no longer lists: the only in-flight pass that
	// can still be about a host that has no owner here.
	orphanPassInFlight := r.anyPassInFlightExcept(desiredNames)

	// The record is per-round, so take it and reset it only now that the round is really being
	// judged -- see the res == nil branch above.
	r.probeMu.Lock()
	current := r.probedHosts
	r.probedHosts = map[string]struct{}{}
	r.probeMu.Unlock()

	for _, h := range all.ProbedHosts() {
		if _, live := current[h]; live {
			continue
		}
		// A host the runner has seen but this round did not probe is only stale if
		// nothing is still working on the certificate it belongs to.
		//
		// This round's probe set is not the whole picture. Two things keep a host out of
		// it while it is still being probed: a certificate whose pass is in flight right
		// now is skipped by the loop above, and a pass that has not reached probeCert yet
		// has not recorded anything. Deleting on that basis makes the series of a live
		// host disappear and reappear, which is exactly the flicker this function's own
		// contract says it avoids -- and a probe_match series that blinks is a false
		// alert for whoever is paging on it.
		//
		// Judged PER CERTIFICATE, not globally. The guard used to be "is any pass anywhere in
		// flight", which meant a single webhook-triggered pass -- and those run for minutes
		// while the timer's own pass walks past them -- suspended reclamation for the whole
		// fleet. A host whose certificate had already left the desired state then kept its
		// series anyway, which is the permanent false alert this function exists to remove.
		// Only the host's own certificate being mid-pass justifies waiting.
		name, inDesiredState := hostOwner[h]
		if inDesiredState {
			if r.passInFlight(name) {
				continue
			}
			// And a certificate that is merely UNCONFIRMED is still being worked on.
			//
			// probeCert returns early for a certificate whose deployment is not confirmed (the
			// honest thing: there is no "deployed certificate" to compare against), so a host
			// disappears from this round's probe set during exactly the window a renewal is
			// mid-rebind -- which can last until the next binding check, up to six hours.
			// Deleting there made probe_match, probe_not_after and probe_trusted flicker once
			// per renewal, and for a rebind that then FAILED it was worse than flicker: the
			// series a `probe_match == 0` alert would fire on were gone, so the documented
			// alert stayed silent for the failure it exists to catch.
			st, err := r.store.GetCert(name)
			if err != nil || st == nil || !st.DeployConfirmed {
				continue
			}
		} else if orphanPassInFlight {
			// No owner in the desired state -- but a pass can still be running for the
			// certificate this host belonged to before it was removed, and that pass may
			// not have reached probeCert yet. Wait for THAT one rather than deleting a
			// series a live pass is about to write. A pass for a certificate the desired
			// state still lists is not a reason to wait: it cannot be about this host.
			continue
		}
		metrics.DeleteProbeSeries(h)
		// The runner's transition memory has to go with the series. Its own comment says
		// both are needed -- otherwise a host that leaves a SAN set leaks an entry there and
		// strands a gauge here -- and only the gauge was being reclaimed, so `last` grew
		// with every host ever dropped from a certificate, and certificate names churn by
		// design.
		//
		// p, not r.getProber(): the snapshot taken at the top of this function is the one
		// ProbedHosts() was read from. Re-reading could see nil after a concurrent
		// SetProber(nil) and panic on the method call.
		p.Forget(h)
	}
}

// anyPassInFlight reports whether any certificate currently holds a convergence claim.
func (r *Reconciler) anyPassInFlight() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.running) > 0
}

// anyPassInFlightExcept reports whether any certificate outside names currently holds a
// convergence claim.
//
// That is "is a pass running for a certificate that is no longer part of the desired state":
// such a pass can still be about a host the desired state does not own, so its probeCert has
// not necessarily run yet. A pass for a certificate the desired state DOES list cannot be about
// that host, and must not hold reclamation up -- that is what the plain anyPassInFlight test
// used to do to the whole fleet.
func (r *Reconciler) anyPassInFlightExcept(names map[string]bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for n := range r.running {
		if !names[n] {
			return true
		}
	}
	return false
}

// passInFlight reports whether this one certificate currently holds a convergence claim.
//
// The per-certificate form of anyPassInFlight, and the one reclaimStaleProbeSeries needs: a
// global "anybody busy" test let one unrelated in-flight pass suspend reclamation for every
// host in the fleet.
func (r *Reconciler) passInFlight(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, busy := r.running[name]
	return busy
}

// RunCert processes exactly one named certificate. An unknown name returns an
// error; one already being processed returns ErrAlreadyRunning. Unlike a whole pass,
// the certificate's own error is propagated: a caller that asked for one specific
// certificate needs to hear that it failed, not a bare "accepted".
//
// This is the SYNCHRONOUS, test- and tooling-oriented entry point: it runs the pass on
// the caller's goroutine and deliberately bypasses Drain's bookkeeping -- it neither
// consults draining nor registers with the background group, so a shutdown will not
// wait for it and it can even start mid-drain. The webhook therefore uses StartCert /
// StartNamed, which are drain-safe; a production caller that cannot accept that must
// not switch to RunCert.
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
// unknown. A non-nil error means either the desired state could not be read (nothing
// started, the buckets are meaningless) or a shutdown began mid-walk -- in the latter
// case the buckets are the partial answer: every name already in `started` was accepted
// and is waited for by Drain, so the caller can say exactly which passes exist.
func (r *Reconciler) StartNamed(ctx context.Context, names []string) (
	started, alreadyRunning, unknown []string, err error,
) {
	if r.drainingNow() {
		// As in StartAll: "shutting down" is not "already running".
		return nil, nil, nil, ErrShuttingDown
	}
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
			if errors.Is(err, ErrShuttingDown) {
				// Drain began between the check above and this start. The names already in
				// `started` WERE accepted and Drain will wait for them, so they go back to
				// the caller along with the error: discarding them would report a pass that
				// is running as one that was refused.
				return started, alreadyRunning, unknown, ErrShuttingDown
			}
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
	// Refuse while draining, and register the pass before the shutdown path can reach Wait: see
	// beginPass. A pass admitted here is counted, so Drain waits for it.
	if !r.beginPass() {
		return ErrShuttingDown
	}
	if !r.acquire(c.Name) {
		// This pass never starts, so undo the registration.
		r.bg.Done()
		return ErrAlreadyRunning
	}
	// Count this pass towards one quota publication for the whole trigger (see quotaPasses).
	r.quotaPasses.Add(1)

	// res is heap-allocated and not reused during this pass, so referring to its
	// elements is safe.
	go func() {
		defer r.bg.Done()
		defer r.release(c.Name)
		// Publish the rate-limit gauges when a webhook-triggered pass finishes, ONCE PER TRIGGER.
		//
		// These gauges exist on this path at all because RunDetailed publishes them at the end of a
		// scheduled round and the webhook had no equivalent: a pass started by a POST spends quota
		// and records the CA's Retry-After just the same, so a deadline shorter than the polling
		// interval (an hour by default) was never shown as blocked -- exactly the window it
		// describes, and WecertRateLimitBlocked could not fire for it. Publishing on this path is
		// also what puts the spend in the number.
		//
		// publishQuota's cost is proportional to the scopes the desired state produces, so calling it
		// per certificate made a full trigger quadratic in the fleet: the round-11 scale work measured
		// 11,001,500 SQL statements and 84.4 s for 500 certificates of 20 names, against 23,003
		// statements and 0.234 s for the same fleet's scheduled pass -- minutes of the single SQLite
		// connection and one core, with every other database user queued behind it.
		//
		// The last pass of a batch publishes for the whole batch, so the gauges still carry every
		// spend the batch made, and a single StartCert still publishes for itself.
		//
		// Deferred rather than inlined at the end: the slot-wait below can also return early on
		// shutdown, and a counter incremented on one path and not decremented on another would stick
		// above zero and stop the gauges being republished for the rest of the process's life.
		// Deferred functions run last-in-first-out, so this runs before the claim is released.
		defer func() {
			if r.quotaPasses.Add(-1) == 0 {
				r.publishQuota(res)
			}
		}()

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
			// pass that started and failed silently. Warn, not Debug: the caller
			// holds an acceptance that will never be fulfilled, which is exactly
			// what an operator auditing a shutdown needs to see.
			r.log.Warn("shutdown while waiting for a start slot; the queued pass will not run", "cert", c.Name)
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

// beginPass registers a background pass, or refuses it once Drain has begun.
//
// One mutex decides both questions, and that is the whole point: the pass is either counted before
// Wait can be called, or it is rejected. Without it the webhook's StartAll could Add while Drain
// was already inside Wait -- sync.WaitGroup forbids that ("calls with a positive delta that start
// when the counter is zero must happen before a Wait") and Go turns it into a process-fatal
// "sync: WaitGroup is reused before previous Wait has returned" panic; it also let a pass start
// after Drain had returned, whose store writes then failed against the closed database.
//
// It returns false rather than an error so the caller can name the refusal in its own terms.
func (r *Reconciler) beginPass() bool {
	r.bgMu.Lock()
	defer r.bgMu.Unlock()
	if r.draining {
		return false
	}
	r.bg.Add(1)
	return true
}

// drainingNow reports whether Drain has been called.
func (r *Reconciler) drainingNow() bool {
	r.bgMu.Lock()
	defer r.bgMu.Unlock()
	return r.draining
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
	if r.drainingNow() {
		// Answer for the whole trigger at once. Reporting every certificate as "skipped" would
		// mean "already running" to the caller, which is the opposite of what is happening.
		return nil, nil, ErrShuttingDown
	}
	res := r.resolve(ctx)
	if res == nil {
		return nil, nil, ErrDesiredStateUnavailable
	}

	// Walk the resolved slice directly: looking each name up with Find over the same
	// slice would make this O(n^2).
	for i := range res.Certificates {
		if err := r.startCert(ctx, res, &res.Certificates[i]); err != nil {
			if errors.Is(err, ErrShuttingDown) {
				// Drain began between the check above and this start: stop the walk and say so.
				return nil, nil, ErrShuttingDown
			}
			skipped = append(skipped, res.Certificates[i].Name)
		} else {
			accepted = append(accepted, res.Certificates[i].Name)
		}
	}
	return accepted, skipped, nil
}

// Drain waits for the passes this reconciler started in the background, up to ctx's deadline.
//
// The caller is the shutdown path, and what it protects is the state store: an accepted pass writes
// promotions, resume anchors and failure counters, and closing SQLite underneath one loses whichever
// of those was in flight (see the bg field). A pass still parked waiting for a start slot is counted
// as well, and returns as soon as the cancelled context reaches it.
//
// A pass already inside a CA call cannot be interrupted (lego's low-level API is context-free), so
// this is bounded rather than absolute: the caller decides how long a shutdown may take, and a
// timeout is reported so the operator knows the store is about to be closed under a live pass.
func (r *Reconciler) Drain(ctx context.Context) error {
	// Refuse new passes from here on, and publish that to beginPass before Wait is called: an Add
	// racing this transition is exactly what made the WaitGroup panic (see beginPass). The lock is
	// released before waiting, so a pass already being registered can finish and be counted.
	r.bgMu.Lock()
	r.draining = true
	r.bgMu.Unlock()

	done := make(chan struct{})
	go func() {
		r.bg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("still waiting for background passes to finish: %w", ctx.Err())
	}
}

// notifyPanicSafe delivers one renewal notification without letting a panic out.
//
// It exists for the one call site that runs while a panic is already being handled: anything raised
// there is unrecoverable, and on the webhook path it reaches a bare goroutine and kills the
// process. A notification is worth having; it is not worth the daemon.
func (r *Reconciler) notifyPanicSafe(ctx context.Context, certName string, err error) {
	if r.notifier == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("the renewal notification itself panicked; the pass result is unaffected",
				"cert", certName, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	r.notifier.Renewal(ctx, certName, err)
}

// reconcileOne processes one certificate and mirrors the result into metrics
// and notifications. The pass's error is returned for callers that need it
// (RunCert); a whole pass and startCert deliberately discard it -- one failing
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
	// accounted is set once the switch below has run, so a later panic does not double-count the
	// pass: the counter the switch picked is the pass's answer.
	var accounted bool
	defer func() {
		if p := recover(); p != nil {
			metrics.ReconcilePanics.WithLabelValues(c.Name).Inc()
			// The panic skipped the accounting below, so record the failed pass here -- but only if
			// the switch really did not run. A panic raised AFTER it (in publish, probeCert or the
			// notification) used to increment "error" on top of the "ok" the pass had already
			// earned, so one pass counted as both.
			if !accounted {
				metrics.ReconcileTotal.WithLabelValues(c.Name, "error").Inc()
			}
			r.log.Error("recovered from a panic: this certificate's pass was aborted, "+
				"the other certificates are unaffected; this is a bug, please report it",
				"cert", c.Name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = fmt.Errorf("panic while reconciling %s: %v", c.Name, p)

			// The notification is sent from here because the normal call below is unreachable
			// while the stack unwinds -- and a panic is the failure an operator most needs to
			// hear about, not the one that goes quiet. Same contract as any other failure: the
			// pass attempted something and it did not succeed.
			//
			// In its OWN recover, because this runs while a panic is being handled: a second panic
			// raised here (the notifier is a user-supplied path -- an HTTP POST, a template, a
			// channel send) has no handler left, and on the webhook path that goroutine is
			// `go func(){ r.reconcileOne(...) }()`, so it takes the process down. Measured before
			// this: a panic in the notification path escaped and killed the pass loop.
			r.notifyPanicSafe(ctx, c.Name, err)
		}
	}()

	err = r.manager.Reconcile(ctx, c)
	accounted = true
	switch {
	case errors.Is(err, state.ErrBackoff):
		// The manager deliberately did not run this pass: the certificate is inside the
		// retry window an earlier failure scheduled. That is neither a success nor a
		// failure, and reporting it as either is a lie the operator acts on --
		// result="ok" hid a certificate stuck in backoff behind a healthy-looking counter,
		// and an error every interval would train people to ignore the channel.
		metrics.ReconcileTotal.WithLabelValues(c.Name, "skipped").Inc()
		// Info, not Debug: this is the only line that explains a pass which attempted nothing, and a
		// one-shot run now exits non-zero for exactly this state (see Trouble). At Debug the timer's
		// journal said "the pass did not converge: attempted=0 ..." with no certificate, no reason
		// and no next attempt in it.
		r.log.Info("pass skipped: still inside the retry backoff window an earlier failure scheduled",
			"cert", c.Name)
	case err != nil:
		metrics.ReconcileTotal.WithLabelValues(c.Name, "error").Inc()
		// manager already logged and scheduled backoff; this is just a summary.
		r.log.Warn("this pass did not succeed", "cert", c.Name, "err", err)
	default:
		metrics.ReconcileTotal.WithLabelValues(c.Name, "ok").Inc()
	}

	// Both of these run AFTER the switch above has decided what this pass's answer is, and
	// both are best-effort: publish only mirrors state into Prometheus, and probeCert is
	// documented as "failing to reach a conclusion does not affect this pass". A panic in
	// either therefore must not become the pass's answer -- it used to unwind into the recover
	// above, which reported a certificate that had just been renewed as a FAILED pass: the
	// metric said ok, the report said Failed, and `-once` exited non-zero for a certificate
	// that was fine. Contained here, it is a counted, logged bug instead of a false alarm.
	r.publishPanicSafe(c)
	r.probeCertPanicSafe(ctx, c)

	// Notified only when the pass actually attempted something: "every renewal attempt
	// emits" is the documented meaning of this event, and a backoff skip is the absence of
	// an attempt.
	//
	// Through notifyPanicSafe on the normal path too, not only in the recover above: the
	// notifier is a user-supplied path, and a panic raised HERE would be caught by this
	// function's own recover -- turning a pass that had already succeeded into a reported
	// failure and firing a second, contradictory notification from the recover block.
	if !errors.Is(err, state.ErrBackoff) {
		r.notifyPanicSafe(ctx, c.Name, err)
	}
	return err
}

// publishPanicSafe runs publish inside its own recover.
//
// publish mirrors the state store into Prometheus and nothing else: it is not part of the
// pass's answer. Letting a panic in it escape into reconcileOne's recover turned a successful
// renewal into a reported failure (see the call site), which is the shape of a false alarm --
// and a false alarm on the renewal channel is what trains people to ignore it.
func (r *Reconciler) publishPanicSafe(c *config.Certificate) {
	defer func() {
		if p := recover(); p != nil {
			metrics.ReconcilePanics.WithLabelValues(c.Name).Inc()
			r.log.Error("recovered from a panic while publishing this certificate's metrics; "+
				"the pass itself is unaffected, but the expiry series may be stale. This is a bug, "+
				"please report it",
				"cert", c.Name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	r.publish(c)
}

// probeCertPanicSafe runs probeCert inside its own recover.
//
// probeCert is documented as best-effort evidence -- "failing to reach a conclusion does not
// affect this pass" -- and a panic is only the most abrupt way of failing to reach one. Its
// per-host goroutines each recover already (a panic there is unrecoverable by the parent), but
// the part that runs on this goroutine -- reading the stored certificate, building the
// expectation -- had no handler, so a panic there reached reconcileOne's recover and reported a
// renewed certificate as a failed pass.
func (r *Reconciler) probeCertPanicSafe(ctx context.Context, c *config.Certificate) {
	defer func() {
		if p := recover(); p != nil {
			metrics.ReconcilePanics.WithLabelValues(c.Name).Inc()
			r.log.Error("recovered from a panic while probing the live endpoint; the pass itself is "+
				"unaffected, but there is no network-side evidence for this certificate. This is a "+
				"bug, please report it",
				"cert", c.Name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	r.probeCert(ctx, c)
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
	p := r.getProber()
	if p == nil {
		return
	}

	// Probing something whose deployment is unconfirmed only produces errors — the
	// first upload needs a manual bind, and until then the live endpoint is still
	// serving the old certificate anyway.
	st, err := r.store.GetCert(c.Name)
	if err != nil || st == nil || !c.Deploy.Enabled || !st.DeployConfirmed {
		return
	}

	// Compare against the certificate actually stored, not the configured domain set:
	// during a fallback the deployed set is deliberately smaller, and using the config
	// reported every host as a mismatch. See issuedSANs.
	domains := r.issuedSANs(st)
	if len(domains) == 0 {
		r.log.Warn("cannot read the names out of the stored certificate, so probing falls back to the "+
			"configured names (a certificate that was issued for a fallback subset would be probed "+
			"under the full set, which can report a mismatch that is not real)",
			"cert", c.Name)
		domains = c.Domains
	}
	hosts := probeHosts(domains, r.cfg.Probe.MaxHostsPerCertOr(config.DefaultMaxHostsPerCert))
	if len(hosts) == 0 {
		if r.cfg.Probe.MaxHostsPerCertOr(config.DefaultMaxHostsPerCert) <= 0 {
			// A cap of 0 is "off" (probeHosts' contract, e.g. probing paused during an
			// investigation) -- blaming wildcards would point the diagnosis at the
			// certificate when the cause is the setting.
			r.log.Debug("nothing to probe: the per-certificate host cap is 0, so probing is off",
				"cert", c.Name, "maxHostsPerCert", r.cfg.Probe.MaxHostsPerCertOr(config.DefaultMaxHostsPerCert))
		} else {
			// Every name in this certificate is a wildcard: nothing concrete to dial.
			r.log.Debug("nothing to probe: every name in this certificate is a wildcard",
				"cert", c.Name, "domains", domains)
		}
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}

	e := r.probeExpectation(domains, st.NotAfter)

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
			p.Check(ctx, h, e)
		}(host)
	}
	wg.Wait()
}

// probeExpectation is what the probe must find for this certificate to count as deployed.
//
// Split out of probeCert so the trust switch has a test: it is the one field that is not
// simply copied out of the state or the configuration, and getting it wrong either blinds the
// probe to a chain no client accepts or reports a permanent mismatch for an internal CA.
func (r *Reconciler) probeExpectation(domains []string, notAfter time.Time) probe.Expectation {
	return probe.Expectation{
		Domains:     domains,
		NotAfter:    notAfter,
		MinValidFor: r.cfg.Probe.MinValidDur,
		// A chain that no client accepts is a failed deployment even when the certificate is
		// the one that was deployed, so this is strict unless the configuration says the CA
		// is internal (probe.requireTrusted: false).
		RequireTrusted: r.cfg.Probe.RequireTrustedOr(true),
	}
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
