package acme

import (
	"fmt"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/state"
)

// Defaults for fields left unset. Config carries its own copy of each one; these are
// the backstop, because the policy arrives through SetFallbackPolicy and is not
// guaranteed to have gone through config.normalize.
const (
	defaultFallbackAfterFailures = 5
	defaultFallbackBeforeExpiry  = 7 * 24 * time.Hour
	defaultFallbackMinIdentFail  = 3
	defaultFallbackFailureWindow = 24 * time.Hour
	defaultFallbackMinNames      = 1
)

// SetFallbackPolicy attaches the "split off a subset and issue it before expiry" policy.
//
// Not calling it means fully off, which is the default state. This changes what the
// certificate covers, and that is a security decision the program should not make on
// someone's behalf.
func (m *Manager) SetFallbackPolicy(p config.FailureFallback) { m.fallback = &p }

// applyFallback decides which domain set to order for this round.
//
// Almost always it returns the input unchanged. Only when a certificate is "nearly
// expired and still refuses to issue" does it drop the names that keep failing -- those
// 24 names that were fine should not expire alongside the 1 name with broken DNS.
func (m *Manager) applyFallback(c *config.Certificate, st *state.CertState, rd round) (*config.Certificate, round) {
	// Stop waiting for names that can never come back, before anything else looks at the
	// record. This runs first, and separately from the metrics block below, so the two
	// concerns stay independent: what the record should contain, and what the gauges say.
	m.pruneFallback(c)

	kept, dropped, reason := m.fallbackDomains(c, st, rd.fallbackActive)

	if len(dropped) == 0 {
		// Three outcomes, not two. Failing to read the record is not evidence that the
		// certificate is healthy: reporting "not degraded" from a failed read would flip the
		// gauge to green exactly when the store is unavailable and degradations are most
		// likely to be missed. Leave both gauges at their last known value instead.
		fb, ferr := m.store.GetFallback(c.Name)
		switch {
		case ferr != nil:
			m.log.Warn("cannot read the fallback state; leaving the metrics as they were",
				"cert", c.Name, "err", ferr)
		case fb != nil:
			// Trying the full set is not recovery: it becomes recovery only after a
			// full certificate is successfully issued and deployed.
			metrics.CertificateFallbackActive.WithLabelValues(c.Name).Set(1)
			metrics.CertificateFallbackDropped.WithLabelValues(c.Name).Set(float64(len(fb.Dropped)))
		default:
			metrics.CertificateFallbackActive.WithLabelValues(c.Name).Set(0)
			metrics.CertificateFallbackDropped.WithLabelValues(c.Name).Set(0)
		}
		// Throw away the stale ledger while we are here: those identifiers are no longer
		// in the certificate, so their authorizations will never be attempted again and
		// can never earn the "success" that would clear them.
		if perr := m.store.PruneIdentifierFailures(c.Name, m.now(),
			m.fallbackWindow()); perr != nil {
			m.log.Warn("cannot prune the identifier failure ledger", "cert", c.Name, "err", perr)
		}
		return c, rd
	}

	cp := *c
	cp.Domains = kept

	// Tell the rest of THIS pass that the certificate is being issued short of names.
	// download uses it to keep the failure evidence that justifies the reduction, and
	// the SAN-drift branch uses it to stop re-ordering the full set on every pass.
	//
	// It is returned rather than stored: two different certificates converge at the same
	// time, so a Manager field would let a neighbour's pass decide this one's behaviour.
	rd.degraded = true
	rd.fallbackActive = true

	// ERROR, not WARN: this is the decision "we deliberately removed names from the
	// certificate", and it has to be loud enough that nobody can miss it.
	m.log.Error("FALLING BACK to a subset of names so the rest stay available",
		"cert", c.Name,
		"keeping", kept, "dropping", dropped,
		"consecutiveFailures", st.ConsecutiveFailures,
		"notAfter", st.NotAfter,
		"reason", reason)

	metrics.CertificateFallbackActive.WithLabelValues(c.Name).Set(1)
	metrics.CertificateFallbackDropped.WithLabelValues(c.Name).Set(float64(len(dropped)))

	if err := m.store.PutFallback(&state.Fallback{
		CertName: c.Name, Dropped: dropped, Since: m.now(), Reason: reason,
	}); err != nil {
		m.log.Warn("cannot record the fallback state", "cert", c.Name, "err", err)
	}
	return &cp, rd
}

// pruneFallback removes from the record the names that are no longer part of the desired set,
// clearing the record entirely when nothing is left to wait for.
//
// A dropped name that has since been removed from the configuration can never come back, so
// the record must stop waiting for it -- and "this name will not validate, drop it from the
// configuration" is the expected response to what a fallback reports. Without this, the record
// never satisfies the condition that clears it, which is "a round ordered the full desired set
// and the issuance succeeded": download tests `containsAll(c.Domains, fb.Dropped)`, and a
// dropped name that is absent from c.Domains makes that permanently false.
//
// The consequence is not merely a stale row. wecert_certificate_fallback_active means "a
// certificate missing names is serving right now", and it would stay set for the life of the
// certificate -- a degradation alert that can never clear is worse than no alert, because it
// teaches whoever reads it to ignore the signal.
//
// c is the certificate as configured, before applyFallback reduces it: this is the only point
// in a pass that holds both the record and the full desired set.
func (m *Manager) pruneFallback(c *config.Certificate) {
	if c == nil {
		return
	}
	fb, err := m.store.GetFallback(c.Name)
	if err != nil {
		// Not fatal: the caller's metrics block treats an unreadable record as "leave the
		// gauges alone", and a prune that cannot read has nothing to prune.
		m.log.Warn("cannot read the fallback record to prune it", "cert", c.Name, "err", err)
		return
	}
	if fb == nil || len(fb.Dropped) == 0 {
		return
	}

	kept := stillConfigured(fb.Dropped, c.Domains)
	if len(kept) == len(fb.Dropped) {
		return
	}
	gone := entriesOfNotIn(fb.Dropped, kept)

	if len(kept) == 0 {
		if err := m.store.ClearFallback(c.Name); err != nil {
			m.log.Warn("cannot clear the fallback record; it would keep reporting a degradation that ended",
				"cert", c.Name, "err", err)
			return
		}
		m.log.Info("every name dropped by an earlier fallback has left the desired set; clearing the record",
			"cert", c.Name, "wasDropping", gone)
		return
	}

	pruned := &state.Fallback{CertName: c.Name, Dropped: kept, Since: fb.Since, Reason: fb.Reason}
	if err := m.store.PutFallback(pruned); err != nil {
		m.log.Warn("cannot update the fallback record", "cert", c.Name, "err", err)
		return
	}
	m.log.Info("a name dropped by an earlier fallback has left the desired set and can never come back; "+
		"it is no longer waited for",
		"cert", c.Name, "removed", gone, "stillDropping", kept)
}

// stillConfigured keeps only the entries of want that are also in have, preserving order.
func stillConfigured(want, have []string) []string {
	if len(want) == 0 {
		return nil
	}
	present := make(map[string]bool, len(have))
	for _, h := range have {
		present[h] = true
	}
	out := make([]string, 0, len(want))
	for _, w := range want {
		if present[w] {
			out = append(out, w)
		}
	}
	return out
}

// entriesOfNotIn returns the entries of want that are not in have, preserving order.
func entriesOfNotIn(want, have []string) []string {
	present := make(map[string]bool, len(have))
	for _, h := range have {
		present[h] = true
	}
	var out []string
	for _, w := range want {
		if !present[w] {
			out = append(out, w)
		}
	}
	return out
}

// fallbackDomains decides whether to degrade, and which names to drop.
//
// A non-empty dropped is the only thing that means "degrade". The evidence conditions all
// have to hold at the same time:
//
//   - the policy is explicitly enabled
//   - a certificate is already in effect (without one there is no "keep what we have"
//     to argue for)
//   - this certificate has failed enough times in a row
//   - **one specific** identifier keeps failing
//   - the names left after dropping are no fewer than the floor
//
// The last two are the crux. When we do not know which name is broken we must never
// drop anything -- dropping at random also sacrifices names that were fine, and that is
// worse than not degrading at all.
//
// The pre-expiry window is special, and getting it wrong is what made the fallback
// oscillate. It gates *entering* a fallback, not *staying* in one:
//
//   - to enter, the certificate must be close enough to expiry that losing it is the
//     imminent risk the trade-off is for;
//   - to stay, it must not -- because issuing the reduced set replaces the nearly-expired
//     certificate with a fresh one, which pushes notAfter months out and would otherwise
//     read as "the danger is over". That reading cleared the fallback one pass after it
//     was established, and the next pass immediately ordered the full set -- the one
//     containing the identifier that cannot issue. Once per backoff window, forever.
//
// So while a degradation record exists and the failing evidence is still fresh, the
// reduced set stands. The full set gets its next attempt when the failure evidence ages
// out (an operator fixed the name, or the ledger expired) -- that is the documented
// self-healing entry point, and it now costs one attempt per failure window instead of
// one per reconcile pass.
func (m *Manager) fallbackDomains(c *config.Certificate, st *state.CertState, held bool) (kept, dropped []string, reason string) {
	p := m.fallback
	if p == nil || !p.EnabledOr(false) {
		return c.Domains, nil, ""
	}

	// With no certificate in effect there is no "partially available" to speak of:
	// that is not preserving anything, it is just issuing a subset.
	if st.NotAfter.IsZero() {
		return c.Domains, nil, ""
	}

	afterFailures := p.AfterFailuresOr(defaultFallbackAfterFailures)
	if st.ConsecutiveFailures < afterFailures {
		return c.Domains, nil, ""
	}

	beforeExpiry := p.BeforeExpiryDur
	if beforeExpiry <= 0 {
		beforeExpiry = defaultFallbackBeforeExpiry
	}
	left := st.NotAfter.Sub(m.now())

	failures, err := m.store.ListIdentifierFailures(c.Name)
	if err != nil {
		m.log.Warn("cannot read the identifier failure ledger; not falling back",
			"cert", c.Name, "err", err)
		return c.Domains, nil, ""
	}

	// Only names that are still failing recently count. Stale entries do not -- that is
	// exactly the self-healing entry point: once the problem is fixed the entries age out
	// and the next round naturally tries the full set again.
	minFailures := p.MinIdentifierFailuresOr(defaultFallbackMinIdentFail)
	cutoff := m.now().Add(-m.fallbackWindow())

	bad := make(map[string]*state.IdentifierFailure)
	for _, f := range failures {
		if f.Failures >= minFailures && f.LastFailedAt.After(cutoff) {
			bad[f.Identifier] = f
		}
	}
	if len(bad) == 0 {
		return c.Domains, nil, ""
	}

	// Decide what this round is: entering a fallback, or continuing one that already
	// exists. Continuing does not re-check the expiry window, for the reason above.
	if !held && left > beforeExpiry {
		// Not entering: the certificate is not close enough to expiry for the
		// "keep most names alive" trade-off to be the right one yet.
		return c.Domains, nil, ""
	}

	kept = make([]string, 0, len(c.Domains))
	for _, d := range c.Domains {
		if _, isBad := bad[d]; isBad {
			dropped = append(dropped, d)
			continue
		}
		kept = append(kept, d)
	}

	minNames := p.MinNamesOr(defaultFallbackMinNames)
	if len(kept) < minNames {
		// This is a total outage wearing a disguise, yet it would read as "still
		// partially available".
		m.log.Error("the failure fallback would leave too few names; refusing to fall back",
			"cert", c.Name, "wouldKeep", len(kept), "minNames", minNames, "wouldDrop", dropped)
		return c.Domains, nil, ""
	}

	return kept, dropped, fmt.Sprintf(
		"issuance has failed %d times in a row and the certificate expires in %s; "+
			"dropping the names whose authorizations keep failing so the rest stay available "+
			"(and so this stops consuming the exact-set quota every hour)",
		st.ConsecutiveFailures, left.Round(time.Hour))
}

func (m *Manager) fallbackWindow() time.Duration {
	if m.fallback != nil && m.fallback.FailureWindowDur > 0 {
		return m.fallback.FailureWindowDur
	}
	return defaultFallbackFailureWindow
}
