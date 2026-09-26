// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
)

// Split from reconcile.go so one concern is one file. Same package.

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

	// One publication for the whole trigger, decided after the registration loop ends -- not by
	// whichever pass happens to finish last (see beginQuotaTrigger).
	r.beginQuotaTrigger()
	defer r.endQuotaTrigger(res)

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
	// Count this pass towards one quota publication for the whole trigger (see quotaPasses), and mark
	// the quiet period as unpublished: a pass that starts after a publication has something to add.
	r.startQuotaPass()

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
				r.publishQuotaIfQuiet(res)
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
	r.beginQuotaTrigger()
	defer r.endQuotaTrigger(res)
	return r.startCert(ctx, res, found)
}

// beginQuotaTrigger marks the start of a trigger that is about to register passes, and endQuotaTrigger
// marks the end of that registration.
//
// Between the two the gauges are not published, however many passes come and go: the batch is not
// complete until the loop that starts it has finished, and publishing for a partial batch means
// publishing again for the rest (see quotaStarting).
func (r *Reconciler) beginQuotaTrigger() {
	r.quotaStarting.Add(1)
	r.quotaMu.Lock()
	r.quotaPublished = false
	r.quotaMu.Unlock()
}

func (r *Reconciler) endQuotaTrigger(res *spec.Result) {
	if r.quotaStarting.Add(-1) == 0 {
		r.publishQuotaIfQuiet(res)
	}
}

// startQuotaPass counts one pass towards its trigger's single publication.
func (r *Reconciler) startQuotaPass() {
	r.quotaPasses.Add(1)
	r.quotaMu.Lock()
	r.quotaPublished = false
	r.quotaMu.Unlock()
}

// publishQuotaIfQuiet publishes the gauges when nothing is running and no trigger is still
// registering, at most once per quiet period.
//
// The check and the claim happen under one lock. Checking the counters and then publishing without
// it lets the pass side and the trigger side both observe the quiet state -- the last pass finishing
// while the registration loop ends -- and publish twice for one trigger.
func (r *Reconciler) publishQuotaIfQuiet(res *spec.Result) {
	r.quotaMu.Lock()
	if r.quotaPublished || r.quotaPasses.Load() != 0 || r.quotaStarting.Load() != 0 {
		r.quotaMu.Unlock()
		return
	}
	r.quotaPublished = true
	r.quotaMu.Unlock()

	// Panic-safe: this can run on a pass's background goroutine, past reconcileOne's recover, where
	// an unrecovered panic is process-fatal.
	r.passStepPanicSafe("publish the quota gauges", func() { r.publishQuota(res) })
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
//
// A non-nil error therefore means one of two things, and the buckets say which: the desired
// state could not be read (nothing started, both lists are empty), or a shutdown began
// mid-walk -- in the latter case the lists are the PARTIAL answer: every name already in
// `accepted` was registered and is waited for by Drain, exactly as StartNamed documents, so
// discarding them would report a running pass as one that was refused.
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

	// One publication for the whole trigger, decided after the registration loop ends (see
	// beginQuotaTrigger): with the counter alone, a fast first pass could publish for a partial batch.
	r.beginQuotaTrigger()
	defer r.endQuotaTrigger(res)

	// Walk the resolved slice directly: looking each name up with Find over the same
	// slice would make this O(n^2).
	for i := range res.Certificates {
		if err := r.startCert(ctx, res, &res.Certificates[i]); err != nil {
			if errors.Is(err, ErrShuttingDown) {
				// Drain began between the check above and this start. The names already in
				// `accepted` WERE started and Drain will wait for them, so they go back to the
				// caller along with the error -- the same contract as StartNamed. Discarding
				// them would tell the webhook "nothing started" while passes are in flight.
				return accepted, skipped, ErrShuttingDown
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
	// On the timeout path this goroutine outlives the return: it stays parked in Wait until
	// the in-flight passes finish. That is bounded -- Drain is the shutdown path and runs
	// once per process, so at most one such goroutine exists, and it cannot block forever
	// because a pass's own work is bounded by the CA and store timeouts above it. A
	// "cancellable Wait" would need a second WaitGroup per call, which is more machinery than
	// a single parked goroutine at exit is worth.
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
