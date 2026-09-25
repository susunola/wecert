package probe

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
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

// Answer is the last recorded conclusion about one host: what the probe found,
// and which problem kind it found if it did not match.
//
// It exists because the verdict returned by Check is discarded by the reconciler, and a
// Prometheus gauge is not evidence: the metrics are labelled by host, they drop their
// answer the moment a probe fails to read a certificate, and an inventory page that reads
// the last value back cannot tell "matched five minutes ago" from "matched before the DNS
// record was deleted". The runner already knows the conclusion at the instant it makes it,
// so it keeps it here for a read-only page to show.
type Answer struct {
	Host        string
	Match       bool
	Trusted     bool
	NotAfter    time.Time
	ProblemKind string // one of the ProblemKind constants, or "" when the probe matched
}

// Runner handles "probe + judge + record metrics + alert only on state transitions".
//
// Why alert only on transitions: this probe runs every round and network jitter is normal.
// Logging an ERROR every round would quickly teach people to ignore it, and that alert would
// effectively cease to exist. Conversely it must never be skipped either -- dropping from ok
// to mismatch is the entire reason this probe exists.
type Runner struct {
	opts Options

	// Keep probeAll injectable so multi-address aggregation can be tested without
	// relying on real DNS; production instances always use ProbeAll.
	probeAll func(context.Context, string, Options) ([]Attempt, error)

	// minValidFor is "how much validity must at least remain"; 0 means do not check.
	minValidFor time.Duration

	log *slog.Logger

	mu   sync.Mutex
	last map[string]string

	// answers is the last conclusion per host, kept beside last under the same mutex:
	// Check runs one goroutine per host and an inventory read happens at any time, so an
	// unguarded map here would be a genuine data race.
	answers map[string]Answer

	// hostLocks serializes Check calls for the same host. Two certificates can cover the
	// same name, and the reconciler probes a certificate's names concurrently; without a
	// per-host mutex two Checks for one host interleave their metric writes and state
	// transitions, and the transition dedup in transition() never sees a repeat -- every
	// round re-alerts. Different hosts still run in parallel.
	//
	// Entries are dropped by Forget, which is only for hosts that will never be probed
	// again; without that the map would grow with every host ever seen, the same leak
	// `last` had.
	hostLocks map[string]*sync.Mutex
}

// NewRunner constructs the prober. A minValidFor of 0 means remaining validity is not
// checked.
func NewRunner(opts Options, minValidFor time.Duration, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	return &Runner{
		opts:        opts,
		probeAll:    ProbeAll,
		minValidFor: minValidFor,
		log:         log,
		last:        make(map[string]string),
		answers:     make(map[string]Answer),
		hostLocks:   make(map[string]*sync.Mutex),
	}
}

// Check probes one name, judges it against the expectation, and records the result in
// metrics and logs.
//
// It returns the verdict for callers to use, but **whether to alert is decided here** --
// this is the only place that holds "what the last state was".
func (r *Runner) Check(ctx context.Context, host string, e Expectation) Verdict {
	unlock := r.lockHost(host)
	defer unlock()

	attempts, err := r.probeAll(ctx, host, r.opts)
	if err != nil {
		// A dead context means the daemon is shutting down (or the pass ran out of time),
		// not that the host is unreachable. Recording it would write probe_match=0, delete
		// the answer gauges and log a spurious ERROR transition for an environment problem
		// that does not exist -- so say nothing and leave the last known state in place.
		if ctx.Err() != nil {
			return Verdict{Problems: []Problem{{Kind: ProblemUnreachable, Text: err.Error()}}}
		}
		metrics.CertificateProbeErrors.WithLabelValues(host).Inc()

		// The verdict is not OK, so "the served certificate is the deployed one" must stop claiming
		// it is. This branch used to leave probe_match at its previous value: a host that resolved
		// and matched last round, then lost its DNS, kept a stale 1 for as long as the resolution
		// failed -- and the documented alert on probe_match == 0 could not fire for the one host
		// whose name no longer resolves. Every non-OK branch below says this for the same reason.
		metrics.CertificateProbeMatch.WithLabelValues(host).Set(0)

		// The two gauges that describe a certificate the probe READ go too, and for the same reason:
		// this host's DNS just stopped resolving, and leaving the last handshake's notAfter and
		// trusted=1 exported would answer "is the chain trusted?" and "which certificate is live?"
		// for an endpoint nobody can dial. probe_match and the error counter stay: they are the
		// evidence that the probe, not the certificate, is the problem.
		metrics.ClearProbeAnswer(host)

		// Unreachable and wrong-certificate must be reported separately: being unable to dial
		// out from the machine running wecert is an environment problem, not a certificate
		// problem. Merging them into one conclusion sends people down the wrong path -- and
		// "believing the certificate is broken" is far more serious than "the probe did not run".
		r.transition(host, stateUnreachable,
			"cannot reach this name to check which certificate it serves", "err", err)
		r.recordUnreachable(host)
		return Verdict{Problems: []Problem{{Kind: ProblemUnreachable, Text: err.Error()}}}
	}

	// The resolution succeeded but the context died while the addresses were being
	// dialled: same rule as above, and it has to be checked BEFORE the per-attempt loop,
	// which increments probe_errors for every cancelled dial.
	if ctx.Err() != nil {
		return Verdict{Problems: []Problem{{Kind: ProblemUnreachable, Text: ctx.Err().Error()}}}
	}

	if e.Now.IsZero() {
		e.Now = time.Now()
	}
	if e.MinValidFor == 0 {
		e.MinValidFor = r.minValidFor
	}

	var (
		first       *Result
		problems    []Problem
		attemptErrs []string
	)
	for _, attempt := range attempts {
		if attempt.Err != nil {
			metrics.CertificateProbeErrors.WithLabelValues(host).Inc()
			attemptErrs = append(attemptErrs, fmt.Sprintf("%s: %v", attempt.Address, attempt.Err))
			continue
		}
		if attempt.Result == nil {
			continue
		}
		if first == nil {
			first = attempt.Result
		}
		if v := attempt.Result.Verify(e); !v.OK {
			for _, p := range v.Problems {
				problems = append(problems, Problem{
					Kind: p.Kind,
					Text: fmt.Sprintf("%s: %s", attempt.Address, p.Text),
				})
			}
		}
	}

	if first == nil {
		msg := "no resolved address completed a TLS handshake"
		if len(attemptErrs) > 0 {
			msg += ": " + strings.Join(attemptErrs, " | ")
		}
		// Same reasoning as the two branches around it, and the same omission would have the same
		// consequence: the name still resolves, so the resolve-failure branch above never runs, and
		// probe_match kept whatever the last healthy round wrote. A listener deleted at the CLB, a
		// security group closed on every backend, or a timeout on every address all land here --
		// and "the endpoint serves nothing at all" is the strongest possible reason to stop saying
		// it serves the deployed certificate.
		//
		// It is also the branch where the stale value is least visible: ClearProbeAnswer takes the
		// two gauges that could contradict a match (notAfter, trusted) away with it, so a leftover
		// 1 stands alone in the exported picture.
		metrics.CertificateProbeMatch.WithLabelValues(host).Set(0)
		metrics.ClearProbeAnswer(host)
		r.transition(host, stateUnreachable,
			"cannot reach this name to check which certificate it serves", "err", msg)
		r.recordUnreachable(host)
		return Verdict{Problems: []Problem{{Kind: ProblemUnreachable, Text: msg}}}
	}

	// Metrics are labelled by host rather than address, so retain the first
	// successful result here. A differing later address sets probe_match to 0
	// and is named in the log below.
	metrics.CertificateProbeNotAfter.WithLabelValues(host).Set(float64(first.NotAfter.Unix()))
	if first.Trusted {
		metrics.CertificateProbeTrusted.WithLabelValues(host).Set(1)
	} else {
		metrics.CertificateProbeTrusted.WithLabelValues(host).Set(0)
	}

	if len(problems) > 0 {
		metrics.CertificateProbeMatch.WithLabelValues(host).Set(0)
		r.transition(host, stateMismatch, mismatchMessage(problems),
			"problems", problemTexts(problems), "servedNotAfter", first.NotAfter,
			"sans", first.SANs, "issuer", first.Issuer, "remoteAddr", first.RemoteAddr)
		// The certificate WAS read, so Trusted and NotAfter are real evidence and are kept;
		// the kind of the first problem is what the page names as the reason it did not match.
		r.recordAnswer(Answer{
			Host:        host,
			Match:       false,
			Trusted:     first.Trusted,
			NotAfter:    first.NotAfter,
			ProblemKind: string(problems[0].Kind),
		})
		return Verdict{Problems: problems}
	}

	if len(attemptErrs) > 0 {
		// Not every resolved address was verified, so "the served certificate is
		// the deployed one" is unproven. Leaving probe_match at its previous value
		// would keep reporting a stale 1 while the verdict is non-OK -- exactly the
		// false green this metric exists to rule out.
		//
		// The consequence to know when reading a dashboard: on a dual-stack host whose AAAA is
		// unreachable, the addresses that DID answer served exactly the deployed certificate, and
		// this still exports 0 with a probe error. That is deliberate (an unverified address is not
		// a verified one) but it means "probe_match == 0" alone does not say WHICH failure it is:
		// read wecert_certificate_probe_errors_total next to it, and the per-address log lines.
		metrics.CertificateProbeMatch.WithLabelValues(host).Set(0)
		// Same reasoning as the two branches above: the answers that were read came from SOME of
		// this host's addresses, so publishing them as the host's answer is the partial-address
		// false green -- and probe_match=0 with probe_errors rising is the documented way to spot it.
		metrics.ClearProbeAnswer(host)
		msg := "some resolved addresses could not be probed: " + strings.Join(attemptErrs, " | ")
		r.transition(host, stateUnreachable,
			"some addresses could not be reached to check which certificate they serve", "err", msg)
		r.recordUnreachable(host)
		return Verdict{Problems: []Problem{{Kind: ProblemUnreachable, Text: msg}}}
	}

	metrics.CertificateProbeMatch.WithLabelValues(host).Set(1)
	r.transition(host, stateOK, "the certificate being served is the one that was deployed",
		"notAfter", first.NotAfter, "daysLeft", first.DaysLeft(e.Now), "issuer", first.Issuer,
		"trusted", first.Trusted, "handshakeMs", first.HandshakeMS)
	r.recordAnswer(Answer{
		Host:     host,
		Match:    true,
		Trusted:  first.Trusted,
		NotAfter: first.NotAfter,
	})
	return Verdict{OK: true}
}

// mismatchMessage words the transition line after what Verify actually found.
//
// The line used to be one hard-coded sentence -- "the certificate being served is not the one that
// was deployed" -- for every class of problem, and it is false for all of the servedButBroken set:
// there the served certificate IS the deployed one, and the finding is that renewal has not run
// yet, the certificate is out of its validity window, or the chain does not verify. The sentence
// is also what the CRITICAL alert's annotation repeats, so getting it wrong sends the operator to
// CLB bindings, SNI and the deploy path for a renewal or chain problem.
func mismatchMessage(problems []Problem) string {
	only := func(kind ProblemKind) bool {
		for _, p := range problems {
			if p.Kind != kind {
				return false
			}
		}
		return len(problems) > 0
	}
	// servedButBroken is the class where the deployed certificate IS the one being served
	// and the problem is with the certificate itself. A mix of these (an expiring
	// certificate that also does not chain) still points at the certificate, not at the
	// deployment path.
	servedButBroken := func() bool {
		for _, p := range problems {
			switch p.Kind {
			case ProblemMinValidFor, ProblemValidityWindow, ProblemUntrusted:
			default:
				return false
			}
		}
		return len(problems) > 0
	}
	switch {
	case only(ProblemMinValidFor):
		return "the certificate being served has less validity left than required"
	case only(ProblemValidityWindow):
		return "the certificate being served is expired or not yet valid"
	case only(ProblemUntrusted):
		return "the certificate being served does not verify against the system roots"
	case only(ProblemNotCovered):
		return "the certificate being served does not cover this name"
	case servedButBroken():
		return "the certificate being served is the deployed one, but it is currently not usable"
	default:
		return "the certificate being served is not the one that was deployed"
	}
}

// problemTexts is the []string a log attribute wants.
func problemTexts(problems []Problem) []string {
	out := make([]string, 0, len(problems))
	for _, p := range problems {
		out = append(out, p.Text)
	}
	return out
}

// ProbedHosts returns every host this runner has recorded a state for.
//
// The reconciler uses it to reclaim per-host metric series: the probe vectors are
// labelled by host, so a certificate leaving the desired state strands its hosts' series
// at their last values forever, and the documented alert on
// wecert_certificate_probe_match == 0 then fires permanently for a host that is no longer
// part of the desired state at all.
func (r *Runner) ProbedHosts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.last))
	for h := range r.last {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Answer returns the most recent answer recorded for host.
//
// The bool is false when this runner has never concluded anything about the name (or has
// forgotten it); a zero Answer with true is possible in principle only for a host whose
// last Check returned before recording, which cannot happen -- every path records.
func (r *Runner) Answer(host string) (Answer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.answers[host]
	return a, ok
}

// recordAnswer stores the last conclusion for a host.
//
// Guarded by the same mutex as last: Check runs concurrently (one goroutine per host) and
// an inventory page reads the answers while probes are still landing.
func (r *Runner) recordAnswer(a Answer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[a.Host] = a
}

// recordUnreachable records "the probe could not answer for this host".
//
// Every unreachable path goes through here so that a stale answer cannot survive it: the
// failure this memory exists to remove is a host that matched last round, stopped resolving
// or answering, and kept showing the old Match=true (with its old NotAfter) on the inventory
// page because nothing overwrote it. Trusted stays false and NotAfter stays zero on purpose:
// no handshake happened, so there is no certificate to report -- the same reason the metrics
// for it are cleared a few lines above.
func (r *Runner) recordUnreachable(host string) {
	r.recordAnswer(Answer{Host: host, ProblemKind: string(ProblemUnreachable)})
}

// LastState returns the previous state for a name, mainly for diagnostics.
// An empty string means it has never been probed.
func (r *Runner) LastState(host string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last[host]
}

// Forget drops the remembered state and answer for a host that will never be probed again
// (its certificate left the desired state).
//
// Without it, last, answers and hostLocks grow with every host ever seen -- and certificate
// names are derived from domains, which churn by design. The exported metric series have the
// same problem and are reclaimed separately (metrics.DeleteProbeSeries); both have to happen,
// or a dropped host leaks memory here and a frozen gauge there.
//
// The contract "will never be probed again" is what makes dropping the lock safe:
// a Check still holding it while the entry is deleted would no longer be mutually
// exclusive with the next one.
func (r *Runner) Forget(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.last, host)
	delete(r.answers, host)
	delete(r.hostLocks, host)
}

// lockHost takes the per-host serialization lock and returns the unlock function.
// See the hostLocks field for why one host must not be checked twice at once.
func (r *Runner) lockHost(host string) func() {
	r.mu.Lock()
	l, ok := r.hostLocks[host]
	if !ok {
		l = &sync.Mutex{}
		r.hostLocks[host] = l
	}
	r.mu.Unlock()
	l.Lock()
	return l.Unlock
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
