// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/state"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Split from reconcile.go so one concern is one file. Same package.

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
