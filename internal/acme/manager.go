package acme

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// Upper bounds on authorization polling and order waiting. Blow past them and we back
// off; the next round carries on with the same order -- because the order is already on
// disk, "the next round" is cheap while placing a new order is expensive.
const (
	authzWaitTimeout = 3 * time.Minute

	// bindingCheckInterval is how often an uploaded-but-unconfirmed certificate is
	// re-checked for bindings. Six hours rather than every pass: only a human can
	// change the answer, and the lookup is a two-call, up-to-30-second enumeration
	// running inside the serial convergence loop.
	bindingCheckInterval = 6 * time.Hour
	orderWaitTimeout     = 2 * time.Minute
	pollInterval         = 3 * time.Second
	// ACME's expires is an optional field. When it fails to parse or is not returned we
	// use this conservative bound; it must never fall back to the zero value, because a
	// zero value reads as "already expired" and discards an unfinished order.
	defaultOrderTTL = 7 * 24 * time.Hour
)

// challengeSolver is the DNS-01 capability Manager needs.
// It is an interface so that "reclaim leftover TXT" -- a path that has leaked before --
// can be covered by tests.
type challengeSolver interface {
	Present(ctx context.Context, domain, token, keyAuth string) (DNSRecord, error)
	WaitAll(ctx context.Context, records []DNSRecord) error
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
	// LookupTXT probes DNS for this challenge's record, asking the zone's authoritative
	// nameservers rather than a recursive resolver. Crash recovery depends on it: a pass
	// that died between the DNS write and the state persist left the record up while the
	// authorization row denies it, and only a probe can tell adopt from rewrite.
	//
	// The three outcomes are distinct on purpose: found means "confirmed present", a nil
	// error with found=false means "authoritatively absent", and a non-nil error means
	// "cannot tell" -- which is the answer for an empty resolver cache too, because a
	// cached negative must never be mistaken for proof that nothing was written.
	LookupTXT(ctx context.Context, domain, keyAuth string) (DNSRecord, bool, error)
}

// keyAuthProvider only needs "convert a challenge token into a key authorization".
// *api.Core satisfies it out of the box.
type keyAuthProvider interface {
	GetKeyAuthorization(token string) (string, error)
}

// Manager converges the desired state (config.Certificate) onto the actual state
// (state.CertState).
//
// The correctness of this whole system rests on four invariants, all of them visible in
// the code below:
//
//  1. At any moment a certificate has at most one order in progress, and the order URL
//     must be on disk. Reconcile first looks for a pending order that has not expired
//     and advances it, never creating a new one -- unless the configured domains
//     changed, because then that order can no longer issue what you asked for.
//  2. ARI comes first, and placing the order must carry replaces -- without it we get no
//     "exempt from every rate limit" treatment.
//  3. A wildcard and its apex write to the same _acme-challenge name, so it has to be
//     "write everything -> validate everything -> only then clean up together".
//  4. The desired state is domains, not time. When the live certificate's SANs disagree
//     with the config, reissue at once instead of waiting for the ARI window; and before
//     discarding an order, the TXT records in DNS must be reclaimed first -- once the
//     authorization row is gone, those records can never be reclaimed again.
type Manager struct {
	store    *state.Store
	core     API
	dns      challengeSolver
	keyAuth  keyAuthProvider
	deployer deploy.Deployer
	log      *slog.Logger

	ariInterval time.Duration
	retention   time.Duration

	// authzWait and pollInterval bound the two wait loops (authorization validation
	// and order status). Fields rather than constants only so tests can drive several
	// rounds without real minutes passing -- the lack of that knob is part of why the
	// amplification in awaitAuthorizations went unnoticed.
	authzWait    time.Duration
	pollInterval time.Duration

	// bindingCheckEvery throttles the "is this certificate bound yet?" lookup, and
	// bindingChecked remembers when each certificate was last asked.
	//
	// Only a human can change the answer -- the certificate was uploaded but not yet
	// bound in the console -- so asking on every pass is pure API cost for a fact that
	// cannot have changed. It is also blocking: the enumeration is asynchronous and the
	// wait polls it for up to 30s, inside the serial convergence loop.
	//
	// In memory rather than in the state database on purpose: a restart re-asking once is
	// harmless, and this is bookkeeping about a transient state, not something that has
	// to survive.
	bindingCheckEvery time.Duration
	bindingMu         sync.Mutex
	bindingChecked    map[string]time.Time

	now func() time.Time

	// fallback is the "split off a subset and issue it before expiry" policy. nil means
	// off, which is the default. See SetFallbackPolicy and applyFallback.
	fallback *config.FailureFallback
}

// round is the per-pass intent of ONE certificate: which domain set this pass decided to
// order for, and whether a degradation was in force when it decided.
//
// These used to be Manager fields, and that was a bug. The reconciler is serial per
// *certificate*, not per process: startCert fans out one goroutine per certificate (capped
// at maxConcurrentStarts) and the timer's RunAll overlaps them, and all of them share the
// one Manager built in main. Two different certificates' passes therefore wrote and read
// the same three booleans, which showed up as genuine data races and as three wrong
// outcomes -- a full-set issuance keeping its failure counter, a fallback re-ordering the
// identifier set it exists to avoid, and a certificate with months of validity left having
// names dropped because a neighbour's round looked like a fallback.
//
// It is a value threaded down the call chain now, so there is nothing to share and no lock
// to take.
//
// Why the flags matter at all: a successful issuance for the degraded subset used to reset
// consecutive_failures and clear the identifier ledger along with every other success. That
// erased the only evidence that anything was wrong, so the very next pass judged the
// certificate "recoverable", tried the full set again, and fell back once more -- once per
// backoff window, forever, spending an order on an identifier set already known to be
// broken. See download for what each flag suppresses.
type round struct {
	// degraded is set when this pass ordered a SUBSET of the configured names.
	degraded bool

	// fullSet is set when this pass ordered the FULL configured identifier set.
	fullSet bool

	// fallbackActive records that a degradation decision is in force for this certificate
	// (a cert_fallback row exists), whether or not this pass dropped anything.
	//
	// The SAN-drift branch in Reconcile reads it: while a fallback is active the live
	// certificate is *supposed* to be missing the dropped names, so "the SANs do not
	// match the config" is not evidence that anything needs reissuing. Without this the
	// drift check re-ordered the full set on every pass, which is what made the fallback
	// oscillate instead of hold.
	fallbackActive bool
}

// NewManager builds the converger.
func NewManager(
	store *state.Store,
	core API,
	dns *DNSSolver,
	deployer deploy.Deployer,
	log *slog.Logger,
) *Manager {
	return newManager(store, core, dns, core, deployer, log)
}

// newManager allows the DNS solver and key authorization source to be injected for tests.
func newManager(
	store *state.Store,
	core API,
	dns challengeSolver,
	keyAuth keyAuthProvider,
	deployer deploy.Deployer,
	log *slog.Logger,
) *Manager {
	return &Manager{
		store:             store,
		core:              core,
		dns:               dns,
		keyAuth:           keyAuth,
		deployer:          deployer,
		log:               log,
		ariInterval:       6 * time.Hour,
		retention:         7 * 24 * time.Hour,
		authzWait:         authzWaitTimeout,
		pollInterval:      pollInterval,
		bindingCheckEvery: bindingCheckInterval,
		bindingChecked:    make(map[string]time.Time),
		now:               time.Now,
	}
}

// Reconcile handles a single certificate. A returned error only means "this round did
// not succeed": the failure is already persisted and the next attempt is already
// scheduled.
func (m *Manager) Reconcile(ctx context.Context, c *config.Certificate) error {
	st, err := m.store.GetCert(c.Name)
	if err != nil {
		return err
	}
	if st == nil {
		st = &state.CertState{Name: c.Name}
	}

	// Whether a degradation record exists is a durable fact about this certificate, not
	// per-pass state, so it is read once here and carried in the round value. A read
	// failure leaves it false, which is the pre-existing behaviour.
	//
	// Reading it once, up front, is also what makes the rest of the pass consistent: the
	// drift branch, the fallback decision and download all see the same answer even though
	// other certificates are converging at the same time.
	rd := round{}
	if fb, ferr := m.store.GetFallback(c.Name); ferr == nil {
		rd.fallbackActive = fb != nil
	}
	// Skip straight through the backoff window. Once a retry is scheduled, stop knocking
	// on the CA's door.
	if !st.NextAttemptAt.IsZero() && m.now().Before(st.NextAttemptAt) {
		m.log.Debug("inside the backoff window; skipping", "cert", c.Name, "nextAttemptAt", st.NextAttemptAt)
		return state.ErrBackoff
	}

	// The configured (full) set, captured before applyFallback may reduce it. Only the
	// count is needed: applyFallback removes names and never adds any, so an unchanged
	// count means the ordered set is the full one.
	cfgDomains := c.Domains

	// Pre-expiry degradation: which domain set this round should actually order for.
	//
	// It lives here instead of being buried inside issue() because every later use of
	// c.Domains must see one and the same set -- order matching, SAN drift comparison, the
	// CSR, the identifier fingerprint. If even one of them used the full configured set,
	// then during a fallback it would fight with "the order's identifier set disagrees
	// with the config -> discard and rebuild", turning into a pointless order every round.
	//
	// Note what this does NOT mean: using the reduced set here is not a licence to forget
	// that names were dropped. download keys off the round value below so that a successful
	// issuance for the subset keeps the failure evidence intact; without it the next pass
	// sees a "healthy" certificate and immediately re-orders the full set.
	c, rd = m.applyFallback(c, st, rd)
	if len(c.Domains) == len(cfgDomains) {
		// applyFallback only ever removes names, so the counts matching means the full
		// configured set is what this round would order for.
		rd.fullSet = true
	}

	// Invariant 1: with an unexpired order in progress, keep advancing it, never create a
	// new one.
	if o, err := m.store.GetOrder(c.Name); err != nil {
		return err
	} else if o != nil {
		switch {
		// A zero ExpiresAt means the server gave no expiry: keep advancing and let the CA
		// declare the order invalid itself.
		case !o.ExpiresAt.IsZero() && !m.now().Before(o.ExpiresAt):
			m.log.Warn("order expired; discarding it and deciding again",
				"cert", c.Name, "order", o.OrderURL, "expiredAt", o.ExpiresAt)
			if err := m.discardOrder(ctx, c.Name); err != nil {
				return err
			}

		case !orderMatchesConfig(o, c):
			// The configured domains changed. This order's identifier set was fixed the
			// moment it was placed, so advancing it only gets it rejected by the CA at
			// finalize over and over until the order expires -- and the "never create a new
			// order" invariant is exactly what makes that stall so persistent. So discard it
			// decisively and let the next round rebuild for the new domains.
			m.log.Warn("the configured domains changed; discarding the old order and rebuilding for the new set",
				"cert", c.Name,
				"orderIdentifiers", o.Identifiers,
				"configIdentifiers", c.DomainKey())
			if err := m.discardOrder(ctx, c.Name); err != nil {
				return err
			}

		default:
			m.log.Info("resuming the existing order", "cert", c.Name, "order", o.OrderURL, "status", o.Status)
			return m.advance(ctx, c, st, o, rd)
		}
	}

	// Reaching here means no order is in progress. If the state store still holds
	// authorizations that were "written into DNS", they are orphaned now (the order delete
	// succeeded but the authorization delete failed, or the process was killed). Reclaim
	// them on the spot rather than leaving them parked on DNSPod forever.
	if err := m.cleanupOrphanTXT(ctx, c.Name); err != nil {
		m.log.Warn("failed to reclaim a leftover TXT record", "cert", c.Name, "err", err)
	}

	// No certificate yet -> first issuance.
	if st.NotAfter.IsZero() {
		m.log.Info("first issuance",
			"cert", c.Name, "names", len(c.Domains), "profile", c.Profile)
		return m.issue(ctx, c, st, "", rd)
	}

	// Certificate exists, but the binding to a cloud resource is unconfirmed -> do one
	// read-only confirmation.
	//
	// A first issuance only uploads and does not bind (on the Tencent Cloud side there is
	// no "old certificate -> resource" relation to look up yet), so DeployConfirmed is
	// false and a human has to bind it once in the console. But until that happens nothing
	// ever comes back to set the flag -- the deployed metric reports "not deployed" for
	// the whole certificate lifetime (up to 90 days under the classic profile) while the
	// certificate is in fact serving normally the entire time.
	//
	// It sits before the domain comparison: this is bookkeeping only and does not affect
	// whether to renew.
	if c.Deploy.Enabled && st.DeployedCertID != "" && !st.DeployConfirmed && m.bindingCheckDue(c.Name) {
		if err := m.confirmBinding(ctx, c, st); err != nil {
			// A lookup failure is not a binding failure. Renewal is the main line here and
			// must not be dragged down by a confirmation step.
			m.log.Warn("could not confirm the certificate binding (renewal is unaffected)",
				"cert", c.Name, "certId", st.DeployedCertID, "err", err)
		}
	}

	// Certificate exists -> check whether the domain set is right first, and time second.
	//
	// The order must not be reversed: if we relied on the ARI window alone, a domain newly
	// added to the config would only take effect at the next renewal window, which under
	// the classic profile is up to a whole validity period. "Domains change at any time" is
	// exactly this project's use case, and that delay is not acceptable.
	if leaf, lerr := ParseLeaf(st.CertPEM); lerr != nil {
		m.log.Warn("could not parse the live certificate; skipping the SAN comparison", "cert", c.Name, "err", lerr)
	} else if drifted, detail := CoverageDrift(leaf, c.Domains); drifted {
		if rd.fallbackActive {
			// A degradation is in force, so the live certificate is *supposed* to be
			// missing names: this drift is the fallback working, not a config change that
			// needs converging on.
			//
			// Reissuing here is what turned the fallback into an oscillation. Every pass
			// saw "the SANs do not match the config" and placed a fresh order for the full
			// set -- the very set whose one broken identifier caused the fallback -- so the
			// account spent an order per pass on a known-bad identifier set. The reduced
			// set is already deployed and serving; the full set gets its next attempt at
			// the renewal window below, and the failure evidence expiring (or an operator
			// fixing the name) is what ends the fallback, not another immediate order.
			m.log.Warn("the live certificate is the degraded name set and a fallback is in force; "+
				"holding it until the renewal window instead of re-ordering the broken full set",
				"cert", c.Name, "detail", detail,
				"note", "the full set is retried once the identifier failure evidence ages out, "+
					"or when an operator fixes the failing name")
		} else {
			m.log.Warn("the live certificate's SANs no longer match the config; reissuing now",
				"cert", c.Name, "detail", detail,
				"note", "an order after a domain-set change does not count as a same-name renewal and will consume "+
					"the Certificates per Registered Domain quota (50 per 7 days, shared across accounts)")
			// `replaces` IS sent here, which reverses an earlier decision.
			//
			// It used to be dropped on the premise that "the ARI exemption needs an
			// identical identifier set, so a changed set is a different bucket anyway".
			// Let's Encrypt's published rule says otherwise: an ARI order is exempt from
			// ALL rate limits when it "includes at least one identifier matching the
			// certificate it intends to replace and the certificate has not been
			// previously replaced using ARI". The error this comment used to quote --
			// `identifiers in this order do not match any identifiers in the certificate
			// being replaced` -- is the NO-overlap case.
			//
			// A config change normally keeps most of the set: adding c.example.com to
			// [a,b] gives [a,b,c], which shares a and b with the certificate being
			// replaced and therefore qualifies. Omitting `replaces` there spends one of
			// the 50-certificates-per-registered-domain-per-7-days allowance for nothing.
			//
			// The pathological case is a wholly disjoint set (moving a name between
			// certificates), where the CA may refuse the order. That is no longer a dead
			// end: issue() retries once without `replaces` on ANY newOrder error, so the
			// worst outcome is losing the exemption rather than never issuing again.
			//
			// The `replaces` value is the certificate actually live now, which is what the
			// stored ARI certID identifies -- including when the live certificate is the
			// degraded subset, since the check is for any shared identifier.
			return m.issue(ctx, c, st, st.ARICertID, rd)
		}
	}

	// Certificate exists -> decide whether renewal is due.
	renewAt, replaces, ariErr := m.renewalDecision(ctx, c, st)
	if ariErr != nil && renewAt.IsZero() {
		// renewalDecision only leaves renewAt zero when the decision itself failed: a
		// cancelled context, or a PutCert that would not write. There is no fallback
		// instant to renew against in that case, and the zero value reads as "long
		// overdue" -- so without this guard a shutdown (or a state-store hiccup) would
		// place a real new order, burning the exact-set rate-limit quota. Stop the round
		// instead; the next pass decides again.
		return ariErr
	}
	if ariErr != nil {
		m.log.Warn("ARI lookup failed; falling back to a time-based threshold", "cert", c.Name, "err", ariErr)
	}
	if m.now().Before(renewAt) {
		m.log.Debug("not yet due for renewal", "cert", c.Name, "renewAt", renewAt, "notAfter", st.NotAfter)
		return nil
	}

	m.log.Info("starting renewal",
		"cert", c.Name, "notAfter", st.NotAfter, "renewAt", renewAt, "ariReplaces", replaces != "")
	return m.issue(ctx, c, st, replaces, rd)
}

// orderMatchesConfig reports whether the order's identifier set still matches the config.
//
// Orders persisted by older versions do not carry this field (empty string), and then no
// comparison is made -- better to advance one extra round than to throw away an order
// just because the information is unavailable (reordering costs
// "5 certs per exact set of identifiers / 7 days").
func orderMatchesConfig(o *state.Order, c *config.Certificate) bool {
	if o.Identifiers == "" {
		return true
	}
	return o.Identifiers == c.DomainKey()
}

// bindingCheckDue reports whether the binding lookup is worth making again, and records
// that it is about to be made.
//
// Recording before the attempt, not after: a lookup that errors would otherwise be
// retried on every pass, which is the cost this exists to avoid.
func (m *Manager) bindingCheckDue(certName string) bool {
	now := m.now()

	m.bindingMu.Lock()
	defer m.bindingMu.Unlock()

	if last, ok := m.bindingChecked[certName]; ok && now.Sub(last) < m.bindingCheckEvery {
		return false
	}
	m.bindingChecked[certName] = now
	return true
}

// confirmBinding looks up once which cloud resources this certificate is bound to, and
// sets DeployConfirmed when it is bound.
//
// Idempotent: a certificate already confirmed never reaches here (the caller checks).
// When no binding is found it stays false and logs a line with a hint -- that state means
// "waiting for a human to bind it once in the CLB console", it is not an error, so it
// records no failure and enters no backoff.
func (m *Manager) confirmBinding(ctx context.Context, c *config.Certificate, st *state.CertState) error {
	n, err := m.deployer.Bindings(ctx, st.DeployedCertID)
	if err != nil {
		return err
	}

	if n == 0 {
		m.log.Info("certificate uploaded but not bound to any cloud resource yet",
			"cert", c.Name, "certId", st.DeployedCertID,
			"hint", "bind it once in the CLB console; renewals switch it automatically afterwards")
		return nil
	}

	st.DeployConfirmed = true
	if err := m.store.PutCert(st); err != nil {
		return err
	}

	m.log.Info("confirmed the certificate is bound to cloud resources",
		"cert", c.Name, "certId", st.DeployedCertID, "resources", n)
	return nil
}
