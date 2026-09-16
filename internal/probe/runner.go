package probe

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/metrics"
)

// State values. Constants rather than ad-hoc strings because these are the keys used to
// deduplicate alerts: one misspelled letter makes one state look like two, so it alerts
// every single round.
const (
	stateOK          = "ok"
	stateMismatch    = "mismatch"
	stateUnreachable = "unreachable"
)

// Runner handles "probe + judge + record metrics + alert only on state transitions".
//
// Why alert only on transitions: this probe runs every round and network jitter is normal.
// Logging an ERROR every round would quickly teach people to ignore it, and that alert would
// effectively cease to exist. Conversely it must never be skipped either -- dropping from ok
// to mismatch is the entire reason this probe exists.
type Runner struct {
	opts Options

	// minValidFor is "how much validity must at least remain"; 0 means do not check.
	minValidFor time.Duration

	log *slog.Logger

	mu   sync.Mutex
	last map[string]string
}

// NewRunner constructs the prober. A minValidFor of 0 means remaining validity is not
// checked.
func NewRunner(opts Options, minValidFor time.Duration, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	return &Runner{
		opts:        opts,
		minValidFor: minValidFor,
		log:         log,
		last:        make(map[string]string),
	}
}

// Check probes one name, judges it against the expectation, and records the result in
// metrics and logs.
//
// It returns the verdict for callers to use, but **whether to alert is decided here** --
// this is the only place that holds "what the last state was".
func (r *Runner) Check(ctx context.Context, host string, e Expectation) Verdict {
	res, err := Probe(ctx, host, r.opts)
	if err != nil {
		metrics.CertificateProbeErrors.WithLabelValues(host).Inc()

		// Unreachable and wrong-certificate must be reported separately: being unable to dial
		// out from the machine running wecert is an environment problem, not a certificate
		// problem. Merging them into one conclusion sends people down the wrong path -- and
		// "believing the certificate is broken" is far more serious than "the probe did not run".
		r.transition(host, stateUnreachable,
			"cannot reach this name to check which certificate it serves", "err", err)
		return Verdict{Problems: []string{err.Error()}}
	}

	metrics.CertificateProbeNotAfter.WithLabelValues(host).Set(float64(res.NotAfter.Unix()))
	if res.Trusted {
		metrics.CertificateProbeTrusted.WithLabelValues(host).Set(1)
	} else {
		metrics.CertificateProbeTrusted.WithLabelValues(host).Set(0)
	}

	if e.Now.IsZero() {
		e.Now = time.Now()
	}
	if e.MinValidFor == 0 {
		e.MinValidFor = r.minValidFor
	}

	v := res.Verify(e)
	if v.OK {
		metrics.CertificateProbeMatch.WithLabelValues(host).Set(1)
		r.transition(host, stateOK, "the certificate being served is the one that was deployed",
			"notAfter", res.NotAfter, "daysLeft", res.DaysLeft(e.Now), "issuer", res.Issuer,
			"trusted", res.Trusted, "handshakeMs", res.HandshakeMS)
		return v
	}

	metrics.CertificateProbeMatch.WithLabelValues(host).Set(0)
	// List every problem at once. Making someone dial a second time to discover the other
	// problems multiplies the troubleshooting cost by the number of problems.
	r.transition(host, stateMismatch, "the certificate being served is not the one that was deployed",
		"problems", v.Problems, "servedNotAfter", res.NotAfter,
		"sans", res.SANs, "issuer", res.Issuer, "remoteAddr", res.RemoteAddr)
	return v
}

// LastState returns the previous state for a name, mainly for diagnostics.
// An empty string means it has never been probed.
func (r *Runner) LastState(host string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last[host]
}

func (r *Runner) transition(host, state, msg string, attrs ...any) {
	r.mu.Lock()
	prev, seen := r.last[host]
	r.last[host] = state
	r.mu.Unlock()

	if seen && prev == state {
		return
	}

	args := append([]any{"host", host, "state", state, "previous", prev}, attrs...)
	if state == stateOK {
		r.log.Info(msg, args...)
		return
	}
	r.log.Error(msg, args...)
}
