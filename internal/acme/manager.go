package acme

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/ratelimit"
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

	// PropagationTimeout is the budget the solver waits for a record to appear. Crash recovery uses
	// it as the floor under "an authoritative denial means the write never happened": inside that
	// window a denial proves nothing, because the write may still be propagating.
	PropagationTimeout() time.Duration
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

	// transientBackoff holds a backoff deadline that could NOT be persisted, keyed by
	// certificate name.
	//
	// Why it is needed: the documented disaster for this system is spending rate-limit
	// quota, and the mechanism that prevents it is NextAttemptAt. That lives in CertState,
	// so when the state store itself is failing -- a full disk is the obvious case, and it
	// is exactly the situation where PutOrder just failed -- the deadline cannot be written
	// and the next pass runs immediately. The order rate then follows the pass rate: at a
	// 1-minute interval, 1440 orders a day against "300 new orders per account per 3 hours".
	//
	// Keeping the deadline in memory as well means a failure still costs one backoff window
	// even when it cannot be recorded. It is deliberately not a substitute for persisting:
	// it is lost on restart, which is acceptable because a restart is not a fast loop.
	//
	// Guarded because different certificates converge concurrently, and the map is keyed by
	// name so one certificate's backoff cannot delay another's.
	transientMu      sync.Mutex
	transientBackoff map[string]time.Time

	// orderFetchFails counts consecutive GetOrder failures per order URL.
	//
	// Why it exists: an order URL that is permanently gone (the CA purged it, or wecert was
	// pointed at a different ACME directory -- accounts are keyed by directory while orders
	// are not) fails GetOrder the same way every pass. That failure was classified as
	// transient, and the only exits from the order branch are `expires_at` and an identifier
	// set change, so RENEWAL -- which is decided after the order branch -- was blocked for the
	// order's whole TTL. Observed: a certificate 5 days from expiry sat through 24 passes and
	// 24 GetOrder failures, fell to 21 hours left, and only issued once the order expired.
	//
	// lego does not expose the HTTP status, so "permanently gone" cannot be distinguished from
	// "the network hiccuped" by the error itself. Counting consecutive failures on the same
	// URL can: a transient failure does not survive several rounds, and the cost of being
	// wrong is one extra order, while the cost of not acting is an expiring certificate.
	//
	// Keyed by order URL rather than certificate name so a replaced order starts at zero, and
	// cleared on any success.
	orderFetchMu    sync.Mutex
	orderFetchFails map[string]int

	// identifierCooldown remembers identifiers whose authorizations just failed, so a
	// certificate is not ordered again while one of its names is known to be failing.
	//
	// Why per-identifier and not just per-certificate: the certificate backoff starts at a
	// minute and doubles, so the first hour of a persistently failing name costs six attempts
	// (1+2+4+8+16+32 minutes) against "5 authorization failures per identifier per hour".
	// Worse, the budget belongs to the IDENTIFIER, so N certificates that share the name
	// attack the same budget -- at ten certificates the first hour costs sixty failures
	// against five. Past that hour the limit blocks every new order for the name, so the
	// extra attempts bought nothing at all; and the consecutive-failure counter (1152, +1/day)
	// counts toward an account pause that needs manual portal action.
	//
	// The cooldown is deliberately in memory: it guards a rate-limit budget that is itself
	// time-based and cheap to relearn, and persisting it would mean another column for state
	// that a restart may reasonably forget.
	identifierMu       sync.Mutex
	identifierCooldown map[string]time.Time

	// quota answers "how much of each published rate limit is left".
	//
	// Let's Encrypt publishes its limits but has no endpoint to query the remainder, so the
	// answer comes from accounting for what this program spent (see internal/ratelimit). nil
	// disables the accounting entirely, which is what the focused unit tests want.
	quota *ratelimit.Tracker

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

// transientBackoffFor reports an unpersisted backoff deadline for this certificate, if any.
//
// Expired entries are dropped on read so the map cannot grow with every certificate that ever
// failed once.
func (m *Manager) transientBackoffFor(certName string) (time.Time, bool) {
	m.transientMu.Lock()
	defer m.transientMu.Unlock()
	until, ok := m.transientBackoff[certName]
	if !ok {
		return time.Time{}, false
	}
	if !m.now().Before(until) {
		delete(m.transientBackoff, certName)
		return time.Time{}, false
	}
	return until, true
}

// setTransientBackoff remembers a deadline that could not be written to the state store.
func (m *Manager) setTransientBackoff(certName string, until time.Time) {
	m.transientMu.Lock()
	defer m.transientMu.Unlock()
	m.transientBackoff[certName] = until
}

// maxOrderFetchFailures is how many consecutive GetOrder failures discard an order.
//
// Four is chosen against the failure it prevents: the order branch blocks renewal while an
// order exists, so the stake is "how long is renewal delayed". Four rounds is minutes at the
// daemon's interval, while a genuinely transient failure (a CA blip, a brief network outage)
// resolves well inside that. The cost of discarding wrongly is one order against the 300-per-
// 3-hours account limit; the cost of not discarding is an expired certificate.
const maxOrderFetchFailures = 4

// noteOrderFetchFailure records a GetOrder failure and reports whether the order should now be
// treated as dead.
func (m *Manager) noteOrderFetchFailure(orderURL string) (dead bool) {
	m.orderFetchMu.Lock()
	defer m.orderFetchMu.Unlock()
	m.orderFetchFails[orderURL]++
	if m.orderFetchFails[orderURL] >= maxOrderFetchFailures {
		delete(m.orderFetchFails, orderURL)
		return true
	}
	return false
}

// clearOrderFetchFailures forgets the failures for an order that answered again.
func (m *Manager) clearOrderFetchFailures(orderURL string) {
	m.orderFetchMu.Lock()
	defer m.orderFetchMu.Unlock()
	delete(m.orderFetchFails, orderURL)
}

// identifierCooldownFor is how long a name is left alone after one of its authorizations fails.
//
// An hour matches the window of "5 authorization failures per identifier per hour": retrying
// inside it cannot help, because the limit that would reject the attempt is measured over the
// same period. After the window the identifier's own budget has partially refilled, which is
// the earliest point at which another attempt is informative.
const identifierCooldownFor = time.Hour

// coolingDown returns the identifier among these names that is inside its cooldown, if any.
func (m *Manager) coolingDown(domains []string) (string, time.Time, bool) {
	now := m.now()
	m.identifierMu.Lock()
	defer m.identifierMu.Unlock()
	for _, d := range domains {
		until, ok := m.identifierCooldown[d]
		if !ok {
			continue
		}
		if !now.Before(until) {
			delete(m.identifierCooldown, d)
			continue
		}
		return d, until, true
	}
	return "", time.Time{}, false
}

// noteIdentifierFailure starts (or extends) the cooldown for a name whose authorization failed.
func (m *Manager) noteIdentifierFailure(identifier string) {
	if identifier == "" {
		return
	}
	m.identifierMu.Lock()
	defer m.identifierMu.Unlock()
	m.identifierCooldown[identifier] = m.now().Add(identifierCooldownFor)
}

// clearIdentifierCooldown forgets a name that validated successfully, so the next failure
// starts a fresh window rather than inheriting one.
func (m *Manager) clearIdentifierCooldown(identifier string) {
	if identifier == "" {
		return
	}
	m.identifierMu.Lock()
	defer m.identifierMu.Unlock()
	delete(m.identifierCooldown, identifier)
}

// quotaNow reports the clock the quota accounting uses.
//
// Tests replace m.now wholesale (m.now = func() time.Time { ... }), which cannot reach the
// tracker's own clock, so the two would otherwise disagree and a test's simulated hours would
// not advance the buckets. Callers that need consistency use SetNow instead.
func (m *Manager) SetNow(now func() time.Time) {
	m.now = now
	if m.quota != nil {
		m.quota.SetNow(now)
	}
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
		store:              store,
		core:               core,
		dns:                dns,
		keyAuth:            keyAuth,
		deployer:           deployer,
		log:                log,
		ariInterval:        6 * time.Hour,
		retention:          7 * 24 * time.Hour,
		authzWait:          authzWaitTimeout,
		pollInterval:       pollInterval,
		bindingCheckEvery:  bindingCheckInterval,
		bindingChecked:     make(map[string]time.Time),
		transientBackoff:   make(map[string]time.Time),
		orderFetchFails:    make(map[string]int),
		identifierCooldown: make(map[string]time.Time),
		quota:              ratelimit.NewTracker(rateBucketAdapter{store: store}, log, nil),
		// quotaNow is kept in step with m.now by SetNow, so a test that drives the clock
		// does not leave the quota accounting reading the wall clock.
		now: time.Now,
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
	} else {
		// A read that failed is not "no fallback is in force".
		//
		// The drift branch below reads fallbackActive to decide whether a missing SAN is the
		// degradation working or a config change to converge on. Treating an unreadable store as
		// "no fallback" ordered the full -- known-bad -- identifier set immediately, while the
		// sibling decision in fallback.go holds on the very same failure. Holding costs one pass;
		// the other direction spends an order on the set whose broken identifier caused the
		// degradation, which is the oscillation the fallback exists to stop.
		rd.fallbackActive = true
		m.log.Warn("cannot read whether a degradation is in force; holding the current certificate "+
			"this pass rather than reissuing the full identifier set",
			"cert", c.Name, "err", ferr)
	}
	// Skip straight through the backoff window. Once a retry is scheduled, stop knocking
	// on the CA's door.
	if until, ok := m.transientBackoffFor(c.Name); ok && m.now().Before(until) {
		// A backoff that could not be persisted (see transientBackoff). Checking it first
		// means a failing state store still costs one window instead of one order per pass.
		m.log.Warn("inside a backoff window that could not be recorded (the state store was failing); skipping",
			"cert", c.Name, "nextAttemptAt", until)
		return state.ErrBackoff
	}
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
		// recordFailure, not a bare return: the doc comment above promises that a failed decision
		// schedules the retry, and a bare return skipped the counter, the backoff and the in-memory
		// transient backoff -- so a state store that fails this read was invisible in
		// wecert_certificate_consecutive_failures and retried at the pass rate.
		return m.recordFailure(st, fmt.Errorf("read the order in progress: %w", err))
	} else if o != nil {
		switch {
		// A zero ExpiresAt means the server gave no expiry: keep advancing and let the CA
		// declare the order invalid itself.
		case !o.ExpiresAt.IsZero() && !m.now().Before(o.ExpiresAt):
			m.log.Warn("order expired; discarding it and deciding again",
				"cert", c.Name, "order", o.OrderURL, "expiredAt", o.ExpiresAt)
			if err := m.discardOrder(ctx, c.Name); err != nil {
				// A store failure here has to schedule the retry, exactly as the sibling call site in
				// manager_flow.go does: returning the bare error skips the backoff entirely, so the
				// next pass retries at the pass rate (re-running cleanupOrphanTXT's authoritative DNS
				// probes and provider deletes each time) and nothing escalates or records why.
				return m.recordFailure(st, fmt.Errorf("discard the expired order: %w", err))
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
				return m.recordFailure(st, fmt.Errorf("discard the order for the changed domain set: %w", err))
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
		if rd.fallbackActive && driftIsTheDegradation(leaf, c, m.store, c.Name, m.log) {
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
		//
		// Recorded as a pass failure rather than returned bare. The write that failed is the one
		// carrying ARICheckedAt, which is the only thing throttling the ARI call, so a bare return
		// means the next pass queries renewalInfo again -- at the pass rate, for every certificate,
		// for as long as the store is broken. That is the loop renewalDecision's own default branch
		// exists to avoid, and recordFailure's unpersisted backoff is what breaks it. A cancelled
		// pass is filtered inside recordFailure, so a shutdown still does not lock the certificate
		// out of the next window.
		return m.recordFailure(st, ariErr)
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
	n, complete, err := m.deployer.Bindings(ctx, st.DeployedCertID)
	if err != nil {
		return err
	}

	if n == 0 && !complete {
		// Not the same answer as "not bound": at least one region's enumeration failed, so a
		// human may well have bound it. Saying "bind it once in the CLB console" here would send
		// the operator to do something they have already done, so the two cases are kept apart
		// and this one is only logged.
		m.log.Warn("could not enumerate every region this certificate could be bound in; "+
			"leaving the binding unconfirmed and re-checking later",
			"cert", c.Name, "certId", st.DeployedCertID)
		return nil
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
