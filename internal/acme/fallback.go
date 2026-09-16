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
func (m *Manager) applyFallback(c *config.Certificate, st *state.CertState) *config.Certificate {
	kept, dropped, reason := m.fallbackDomains(c, st)

	if len(dropped) == 0 {
		metrics.CertificateFallbackActive.WithLabelValues(c.Name).Set(0)
		metrics.CertificateFallbackDropped.WithLabelValues(c.Name).Set(0)

		// This round uses the full set. If we were degraded before, we have recovered --
		// that record exists for exactly one reason: to say "a certificate missing names
		// is serving right now".
		if fb, err := m.store.GetFallback(c.Name); err == nil && fb != nil {
			m.log.Info("back on the full name set; clearing the fallback record",
				"cert", c.Name, "wasDropping", fb.Dropped, "since", fb.Since)
			if cerr := m.store.ClearFallback(c.Name); cerr != nil {
				m.log.Warn("cannot clear the fallback record", "cert", c.Name, "err", cerr)
			}
		}
		// Throw away the stale ledger while we are here: those identifiers are no longer
		// in the certificate, so their authorizations will never be attempted again and
		// can never earn the "success" that would clear them.
		if perr := m.store.PruneIdentifierFailures(c.Name, m.now(),
			m.fallbackWindow()); perr != nil {
			m.log.Warn("cannot prune the identifier failure ledger", "cert", c.Name, "err", perr)
		}
		return c
	}

	cp := *c
	cp.Domains = kept

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
	return &cp
}

// fallbackDomains decides whether to degrade, and which names to drop.
//
// A non-empty dropped is the only thing that means "degrade". Every condition has to
// hold at the same time:
//
//   - the policy is explicitly enabled
//   - a certificate is already in effect (without one there is no "keep what we have"
//     to argue for)
//   - this certificate has failed enough times in a row
//   - we are already inside the danger window before expiry
//   - **one specific** identifier keeps failing
//   - the names left after dropping are no fewer than the floor
//
// The last two are the crux. When we do not know which name is broken we must never
// drop anything -- dropping at random also sacrifices names that were fine, and that is
// worse than not degrading at all.
func (m *Manager) fallbackDomains(c *config.Certificate, st *state.CertState) (kept, dropped []string, reason string) {
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
	if left > beforeExpiry {
		return c.Domains, nil, ""
	}

	failures, err := m.store.ListIdentifierFailures(c.Name)
	if err != nil {
		m.log.Warn("cannot read the identifier failure ledger; not falling back",
			"cert", c.Name, "err", err)
		return c.Domains, nil, ""
	}

	// Only drop names that are still failing recently. Stale entries do not count --
	// that is exactly the self-healing entry point: once the problem is fixed the
	// entries age out and the next round naturally tries the full set again.
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
