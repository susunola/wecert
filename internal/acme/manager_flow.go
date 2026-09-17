package acme

import (
	"strings"

	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/state"
)

// authzFetchConcurrency caps how many authorization lookups are in flight at once.
//
// On certificates with many SANs this step must be concurrent: pulling 100 authorizations
// serially is 100 round trips, and a 3-minute wait budget does not survive many rounds. The
// cap of 8 is there to avoid hitting the CA with a burst.
//
// The concurrency is safe because of how lego is built: once constructed, api.Core carries
// only mutable state like the nonce manager, and that one has a mutex; the JWS and Doer are
// read-only.
const authzFetchConcurrency = 8

// advance pushes the order state machine forward.
func (m *Manager) advance(ctx context.Context, c *config.Certificate, st *state.CertState, o *state.Order, rd round) error {
	order, err := m.core.GetOrder(o.OrderURL)
	if err != nil {
		// A dead order URL must not block renewal for the order's whole TTL.
		//
		// The order branch keeps advancing a persisted order rather than creating a new one,
		// and renewal is only decided AFTER that branch -- so an order whose URL can never be
		// fetched again stalls every later renewal until it expires (7 days by default), long
		// past the renewal window. Observed: a certificate 5 days out sat through 24 passes
		// and 24 failures, fell to 21 hours left, and issued only once the order expired.
		//
		// Reachable without anything exotic: accounts are keyed by ACME directory while orders
		// are not, so pointing wecert at staging and back leaves orders naming a directory that
		// no longer serves them.
		if m.noteOrderFetchFailure(o.OrderURL) {
			m.log.Warn("the persisted order could not be fetched for several consecutive attempts; "+
				"treating it as dead and rebuilding, rather than blocking renewal until it expires",
				"cert", c.Name, "order", o.OrderURL, "attempts", maxOrderFetchFailures, "err", err)
			if derr := m.discardOrder(ctx, c.Name); derr != nil {
				// Discarding failed too, so the order row survives; still report the failure so
				// the backoff applies, and the next round tries again.
				return m.recordFailure(st, errors.Join(fmt.Errorf("get order: %w", err), derr))
			}
			return m.recordFailure(st, fmt.Errorf(
				"get order: %w (the order was discarded; the next attempt places a new one)", err))
		}
		return m.recordFailure(st, fmt.Errorf("get order: %w", err))
	}
	// It answered, so the URL is alive: forget any earlier failures.
	m.clearOrderFetchFailures(o.OrderURL)
	// Same contract as the other two call sites: persistOrder returns its write
	// error, and a failed write means crash recovery would resume from stale state.
	// Discarding it would defeat the point of making it return one, and Go does not
	// warn about a dropped return value.
	if err := m.persistOrder(o, order); err != nil {
		return m.recordFailure(st, err)
	}

	switch order.Status {
	case "valid":
		return m.download(ctx, c, st, o, order, rd)

	case "invalid":
		// The order is dead. Clean it up so the next round decides from scratch (which will
		// go through backoff).
		//
		// recordFailure must still run even when discardOrder itself fails: returning early
		// here would skip backoff entirely, so the very next round would retry immediately
		// with no backoff at all.
		err := fmt.Errorf("order became invalid: %v", order.Err())
		if derr := m.discardOrder(ctx, c.Name); derr != nil {
			err = errors.Join(err, derr)
		}
		return m.recordFailure(st, err)

	case "ready":
		return m.finalize(ctx, c, st, o, order, rd)

	case "processing":
		// The CSR is already with the CA (a previous pass submitted it and died before
		// seeing the result): the order goes straight from processing to valid/invalid
		// and never passes through "ready" again. Falling into the pending branch here
		// re-solves challenges that no longer exist and then waits for "ready" until
		// orderWaitTimeout -- recording a spurious failure on an order that is actually
		// on track. Just wait for the outcome and download.
		final, err := m.awaitOrderStatus(ctx, o.OrderURL, "valid", orderWaitTimeout)
		if err != nil {
			return m.recordFailure(st, err)
		}
		if err := m.persistOrder(o, final); err != nil {
			return m.recordFailure(st, err)
		}
		return m.download(ctx, c, st, o, final, rd)
	}

	// pending: drive the DNS-01 challenges through to the end.
	allValid, err := m.solveChallenges(ctx, c, st, order)
	if err != nil {
		return err
	}
	if !allValid {
		// Still waiting on CA validation; keep the order and carry on next round.
		return nil
	}

	// Every authorization is valid; wait for the order to turn ready, then finalize.
	ready, err := m.awaitOrderStatus(ctx, o.OrderURL, "ready", orderWaitTimeout)
	if err != nil {
		return m.recordFailure(st, err)
	}
	if err := m.persistOrder(o, ready); err != nil {
		return m.recordFailure(st, err)
	}
	if ready.Status == "valid" {
		return m.download(ctx, c, st, o, ready, rd)
	}
	return m.finalize(ctx, c, st, o, ready, rd)
}

// fetchAuthzs fetches the current state of several authorizations concurrently, returning
// results in the same order as the input.
//
// Serial fetching really does time out on certificates with many SANs: 100 authorizations at
// one round trip each makes a single round take tens of seconds, a 3-minute wait budget does
// not survive many rounds, and each round just sits there waiting for nothing. Concurrency is
// the only workable approach here.
//
// Each goroutine writes only its own slot and never touches the store, so no extra locking is
// needed; concurrent calls into api.Core are safe (the nonce manager has a mutex).
func (m *Manager) fetchAuthzs(ctx context.Context, authzs []*state.Authorization) ([]legoacme.Authorization, error) {
	out := make([]legoacme.Authorization, len(authzs))
	errs := make([]error, len(authzs))
	if len(authzs) == 0 {
		return out, nil
	}

	limit := authzFetchConcurrency
	if len(authzs) < limit {
		limit = len(authzs)
	}

	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, a := range authzs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, authzURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := ctx.Err(); err != nil {
				errs[i] = err
				return
			}
			cur, err := m.core.GetAuthorization(authzURL)
			if err != nil {
				errs[i] = err
				return
			}
			out[i] = cur
		}(i, a.AuthzURL)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("get authorization %s: %w", authzs[i].AuthzURL, err)
		}
	}
	return out, nil
}

// solveChallenges returns allValid=true when every authorization of the order has passed
// validation.
func (m *Manager) solveChallenges(
	ctx context.Context, c *config.Certificate, st *state.CertState, order legoacme.ExtendedOrder,
) (bool, error) {
	authzs, err := m.loadAuthorizations(c.Name, order.Authorizations)
	if err != nil {
		return false, m.recordFailure(st, err)
	}

	current, err := m.fetchAuthzs(ctx, authzs)
	if err != nil {
		return false, m.recordFailure(st, err)
	}

	// Phase 1: write every TXT that is still awaiting validation, all in one go.
	// Here we must never do "write one -> validate one -> delete one": for
	// example.com + *.example.com both authorizations' challenge values land on
	// _acme-challenge.example.com and have to exist at the same time.
	var pending []*state.Authorization
	// resumed collects the rows this pass did not write itself (Presented was already
	// true on entry): their records are not re-verified anywhere except by WaitAll
	// below, and the WaitAll error path needs to know who they are.
	var resumed []*state.Authorization
	var records []DNSRecord

	for i, a := range authzs {
		cur := current[i]
		a.Status = cur.Status
		a.Identifier = cur.Identifier.Value

		// The ledger is keyed by the name as the operator wrote it, which for a
		// wildcard means "*." + value: RFC 8555 §7.1.3 forbids the "*." prefix in
		// the authorization's own identifier, so `cur.Identifier.Value` alone is the
		// bare apex. Keying on the bare name would book a `*.example.com` failure
		// against `example.com`, and the fallback would then drop the healthy apex
		// while keeping the wildcard that is actually failing -- the exact opposite
		// of its job. `a.Identifier` must stay unprefixed for DNS-01, because the
		// apex and its wildcard deliberately share one TXT name.
		targeted := challenge.GetTargetedDomain(cur)

		switch cur.Status {
		case "valid":
			if err := m.store.PutAuthorization(a); err != nil {
				return false, m.recordFailure(st, fmt.Errorf("persist a validated authorization (%s): %w", a.Identifier, err))
			}
			continue
		case "invalid":
			// Persist the invalid state before reporting the error.
			// A failed write must not hide the main cause (the invalid authorization is what
			// we report), but it does have to leave a trace -- silently swallowing a DB error
			// robs later debugging of its clues.
			if perr := m.store.PutAuthorization(a); perr != nil {
				m.log.Warn("failed to record the invalidated authorization",
					"cert", c.Name, "identifier", targeted, "err", perr)
			}

			// Keep the books per identifier. The certificate-level consecutive_failures only
			// says "this certificate will not issue", while pre-expiry degradation has to
			// answer "which name will not issue" -- without that we could only drop names at
			// random, and that sacrifices the good names too.
			// Start the name's cooldown as well as recording the ledger row: the ledger
			// answers "who has been broken lately" for the fallback, while the cooldown
			// stops this process from spending the identifier's hourly failure budget on
			// retries inside the same window (see identifierCooldown).
			m.noteIdentifierFailure(targeted)
			m.spendAuthzFailure(targeted)
			if rerr := m.store.RecordIdentifierFailure(
				c.Name, targeted, authzError(cur), m.now()); rerr != nil {
				m.log.Warn("failed to record the identifier failure",
					"cert", c.Name, "identifier", targeted, "err", rerr)
			}

			return false, m.recordFailure(st, fmt.Errorf(
				"the authorization for identifier %s is invalid: %s", targeted, authzError(cur)))

		case "deactivated", "expired", "revoked":
			// RFC 8555 section 7.1.6: these statuses are closed. The authorization can never
			// become valid again, so the order carrying it can never be finalized -- but with no
			// case for them the pass treated them as pending and re-presented a challenge (a real
			// TXT write plus a propagation wait), POSTed AcceptChallenge for a closed
			// authorization, and then polled it for the whole authzWait, every pass, until the
			// order's own 7-day TTL expired.
			//
			// Discarding the order is what ends that: the next pass places a fresh one, whose
			// authorizations are new. No identifier failure is booked -- nothing about the name
			// failed validation, and booking one would arm the pre-expiry fallback against a
			// healthy identifier.
			if perr := m.store.PutAuthorization(a); perr != nil {
				m.log.Warn("failed to record the closed authorization",
					"cert", c.Name, "identifier", targeted, "status", cur.Status, "err", perr)
			}
			m.log.Warn("the authorization is closed and can never be satisfied; discarding the order "+
				"so the next pass places a fresh one",
				"cert", c.Name, "identifier", targeted, "status", cur.Status, "authz", a.AuthzURL)
			if derr := m.discardOrder(ctx, c.Name); derr != nil {
				return false, m.recordFailure(st, fmt.Errorf(
					"the authorization for %s is %s and discarding the order failed: %w",
					targeted, cur.Status, derr))
			}
			return false, m.recordFailure(st, fmt.Errorf(
				"the authorization for identifier %s is %s, which cannot be satisfied; a fresh order "+
					"will be placed on the next pass", targeted, cur.Status))
		}

		if !a.Presented {
			chlg, err := pickDNS01(cur)
			if err != nil {
				return false, m.recordFailure(st, err)
			}
			keyAuth, err := m.keyAuth.GetKeyAuthorization(chlg.Token)
			if err != nil {
				return false, m.recordFailure(st, fmt.Errorf("compute the key authorization: %w", err))
			}

			// The row must describe the challenge this pass is actually solving. The token
			// kept from an earlier visit can be a different challenge than the one `chlg`
			// names now, and then the row's token no longer hashes to its own TxtValue.
			// That breaks cleanup: removeAuthzTXT derives the key authorization from the
			// token, so CleanUp would look for a value that was never registered, conclude
			// "another challenge is still live at this name", and never fire the provider's
			// delete-all again -- stranding every later TXT record at that name for the
			// lifetime of the process.
			//
			// Refreshing it loses the older token, not the older record: the provider's
			// cleanup deletes every TXT at the name in one call.
			firstVisit := a.ChallengeToken == ""
			// A different challenge has never been POSTed, whatever the old row said. ChallengeSent
			// belongs to the challenge it was set for, and this row has just been pointed at
			// another one: keeping the flag true makes phase 3 skip it (`if a.ChallengeSent {
			// continue }`), so the new challenge is written to DNS, never accepted, and the order
			// sits pending until it expires -- up to the 7-day order TTL -- with no counter saying
			// so. markResumedUnpresented clears Presented for the same reason and forgot this one.
			if a.ChallengeToken != chlg.Token {
				a.ChallengeSent = false
				// The old token hashed to a record this row no longer uses, so its lease is dead.
				// Releasing it is what keeps the name cleanable: while a lease is held, every
				// later cleanup here takes the "another challenge is still live" branch, and the
				// provider's delete-EVERY-TXT call never fires again for the rest of the process.
				// The record itself (if it is still up) goes with the next delete-all, which the
				// new value's cleanup fires once it is the last leaver.
				m.releaseStaleLease(a.TxtName, a.TxtValue)
			}
			a.ChallengeURL = chlg.URL
			a.ChallengeToken = chlg.Token
			// Remember when this challenge was chosen. Crash recovery probes for the record of a row
			// that was never marked presented, and a denial is only evidence once the write would
			// have had time to reach the authoritative servers (see reclaimUnpresentedTXT).
			a.ChallengePreparedAt = m.now()

			adopted := false
			if firstVisit {
				// First visit: persist the challenge **before** writing DNS. A pass that
				// dies between the write and the persist below leaves the record up while
				// the row still says Presented=false -- and the token is then the only
				// way to locate that record again (the probe right below relies on it,
				// and so does cleanupOrphanTXT).
				if err := m.store.PutAuthorization(a); err != nil {
					return false, m.recordFailure(st, fmt.Errorf("persist a new challenge (%s): %w", a.Identifier, err))
				}
			} else {
				// Been here before: an earlier pass was interrupted between the DNS write
				// and marking Presented. Re-Present blindly and the record is duplicated;
				// probe first and, if the old record is already up, adopt it instead.
				rec, found, lerr := m.dns.LookupTXT(ctx, a.Identifier, keyAuth)
				switch {
				case lerr != nil:
					// A failed probe proves nothing either way, so write. The worst case
					// is a duplicate record, and cleanup removes every record at the name
					// in one call -- twin included.
					m.log.Warn("could not probe for an existing TXT; writing it anyway",
						"cert", c.Name, "identifier", a.Identifier, "err", lerr)
				case found:
					a.TxtName = rec.FQDN
					a.TxtValue = rec.Value
					a.Presented = true
					adopted = true
					m.log.Info("the TXT from the interrupted pass is already up; adopting it instead of writing a duplicate",
						"cert", c.Name, "identifier", a.Identifier, "name", a.TxtName)
				}
			}

			if !adopted {
				// Write only, do not wait for propagation -- wait once after all TXT are written.
				// Waiting per record makes a wildcard and its apex wait twice for nothing on the
				// same TXT name (one propagation round takes over 2 minutes on DNSPod's free tier,
				// so that is minutes right there).
				rec, err := m.dns.Present(ctx, a.Identifier, chlg.Token, keyAuth)
				if err != nil {
					return false, m.recordFailure(st, fmt.Errorf("present TXT (%s): %w", a.Identifier, err))
				}

				a.TxtName = rec.FQDN
				a.TxtValue = rec.Value
				a.Presented = true
				m.log.Info("TXT presented",
					"cert", c.Name, "identifier", a.Identifier, "name", a.TxtName)
			}
		} else {
			// This pass writes nothing for the row: it resumed a record an earlier pass
			// wrote. WaitAll below is the only remaining check that the record is
			// actually still there.
			resumed = append(resumed, a)
		}

		if err := m.store.PutAuthorization(a); err != nil {
			return false, m.recordFailure(st, fmt.Errorf("persist a presented challenge (%s): %w", a.Identifier, err))
		}
		records = append(records, DNSRecord{FQDN: a.TxtName, Value: a.TxtValue})
		pending = append(pending, a)
	}

	if len(pending) == 0 {
		// Every authorization is already valid (for example we crashed after it went valid but
		// before cleanup). Still try to clear any leftover TXT, so DNSPod's record quota does
		// not fill up slowly.
		m.cleanup(ctx, c.Name, authzs)
		return true, nil
	}

	// Phase 2: once every TXT is written, wait once for propagation to the authoritative NS.
	// WaitAll deduplicates by zone internally and resolves each zone's NS list only once.
	if err := m.dns.WaitAll(ctx, records); err != nil {
		// A resumed row was never re-verified: if its record was deleted out of band,
		// leaving Presented=true makes every round burn the whole propagation budget
		// waiting for a record that will never appear, until the order expires. Flip it
		// back so the next round probes and re-presents -- a record that is in fact
		// still up is simply adopted by that probe, so a healthy DNS costs nothing.
		// Skipped when the round was merely cancelled: a shutdown says nothing about DNS.
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			m.markResumedUnpresented(c.Name, resumed)
		}
		return false, m.recordFailure(st, fmt.Errorf("wait for TXT propagation: %w", err))
	}

	// Phase 3: only once propagation is confirmed do we tell the CA, one by one, to validate.
	for _, a := range pending {
		if a.ChallengeSent {
			continue
		}
		if err := m.core.AcceptChallenge(a.ChallengeURL); err != nil {
			return false, m.recordFailure(st, fmt.Errorf("trigger validation (%s): %w", a.Identifier, err))
		}
		a.ChallengeSent = true
		if err := m.store.PutAuthorization(a); err != nil {
			// The challenge WAS accepted; only the record of it failed. Counting the pass as a
			// failure is still right: without the row, the next pass cannot tell that this
			// challenge is already in flight, and the pass has not finished its job.
			return false, m.recordFailure(st, fmt.Errorf("persist that a challenge was accepted (%s): %w", a.Identifier, err))
		}
	}

	// Phase 4: poll until everything is valid.
	if err := m.awaitAuthorizations(ctx, pending); err != nil {
		return false, m.recordFailure(st, err)
	}

	// Phase 5: only after every validation passes do we clean up the TXT records together.
	m.cleanup(ctx, c.Name, pending)
	return true, nil
}

// markResumedUnpresented flips resumed rows back to Presented=false after the
// propagation wait failed, so the next round probes them again instead of trusting a
// record that may no longer exist. A failed persist only loses one round: the row is
// retried on the next pass.
func (m *Manager) markResumedUnpresented(certName string, resumed []*state.Authorization) {
	for _, a := range resumed {
		a.Presented = false
		// ChallengeSent is deliberately NOT cleared here: this pass re-presents the SAME challenge,
		// so if it was already accepted that is still true. It is cleared where the row is pointed
		// at a different challenge, which is the only event that invalidates it.
		if err := m.store.PutAuthorization(a); err != nil {
			m.log.Warn("failed to mark a resumed authorization unpresented",
				"cert", certName, "identifier", a.Identifier, "err", err)
			continue
		}
		m.log.Info("the resumed TXT never confirmed propagated; it will be probed and re-presented next round",
			"cert", certName, "identifier", a.Identifier, "name", a.TxtName)
	}
}

func (m *Manager) loadAuthorizations(certName string, urls []string) ([]*state.Authorization, error) {
	existing, err := m.store.ListAuthorizations(certName)
	if err != nil {
		return nil, err
	}
	byURL := make(map[string]*state.Authorization, len(existing))
	for _, a := range existing {
		byURL[a.AuthzURL] = a
	}

	out := make([]*state.Authorization, 0, len(urls))
	for _, u := range urls {
		if a, ok := byURL[u]; ok {
			out = append(out, a)
			continue
		}
		a := &state.Authorization{CertName: certName, AuthzURL: u, Status: "pending"}
		if err := m.store.PutAuthorization(a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (m *Manager) awaitAuthorizations(ctx context.Context, authzs []*state.Authorization) error {
	deadline := m.now().Add(m.authzWait)

	// Only the still-pending subset is polled, and it shrinks as authorizations
	// conclude. Polling the whole set every round means a 25-name certificate that
	// takes the entire budget costs ~1500 CA round trips and ~1500 upserts, of which
	// only the first 25 ever carry new information -- and each upsert is its own WAL
	// commit.
	pending := make([]*state.Authorization, len(authzs))
	copy(pending, authzs)

	for {
		current, err := m.fetchAuthzs(ctx, pending)
		if err != nil {
			return err
		}

		stillPending := pending[:0]
		for i, a := range pending {
			cur := current[i]

			// Persist a transition only. The row is what the next pass reads to decide
			// where to resume, so rewriting an unchanged status is pure fsync.
			if cur.Status == "valid" {
				// It validated, so the name is not in trouble: forget any cooldown so a later
				// failure starts a fresh window rather than inheriting this one. The ledger
				// row is pruned separately, by applyFallback, once the name is healthy.
				m.clearIdentifierCooldown(challenge.GetTargetedDomain(cur))
			}
			if a.Status != cur.Status {
				a.Status = cur.Status
				if perr := m.store.PutAuthorization(a); perr != nil {
					return perr
				}
			}

			switch cur.Status {
			case "valid":
			case "invalid":
				// This is the common failure timing: the challenge was accepted,
				// then the CA later marks the authorization invalid. Keep the
				// ledger key wildcard-aware, just as solveChallenges does.
				targeted := challenge.GetTargetedDomain(cur)
				m.noteIdentifierFailure(targeted)
				// The same budget as in solveChallenges: whichever poll observes the invalid
				// authorization first is the one that spends the identifier's hourly failure slot,
				// and both paths can be the first to see it.
				m.spendAuthzFailure(targeted)
				if rerr := m.store.RecordIdentifierFailure(a.CertName, targeted, authzError(cur), m.now()); rerr != nil {
					m.log.Warn("failed to record the identifier failure", "cert", a.CertName, "identifier", targeted, "err", rerr)
				}
				return fmt.Errorf("validation failed for identifier %s: %s", targeted, authzError(cur))
			default:
				stillPending = append(stillPending, a)
			}
		}
		pending = stillPending

		if len(pending) == 0 {
			return nil
		}
		if m.now().After(deadline) {
			return fmt.Errorf("authorizations did not complete within %s; keeping the order for the next pass", m.authzWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.pollInterval):
		}
	}
}

// registerRecoveredLeases re-registers every TXT this state store still believes is in
// DNS, before anything is cleaned up.
//
// The lease registry (see challengeLeases) only knows the values this *process* wrote.
// lego's provider cleanup deletes **every** TXT at the challenge name, so a row recovered
// from a previous process -- the pass that wrote it died before marking Presented -- is a
// live value the registry cannot see. A cleanup for a different certificate sharing the
// challenge name would then find "no other live values" and delete it, taking out a
// challenge that is still pending and burning the per-identifier authorization-failure
// quota.
//
// Re-reading the rows first makes the registry's view match what is actually in DNS, so
// "no other live values" becomes true rather than merely believed.
func (m *Manager) registerRecoveredLeases() {
	rows, err := m.store.ListPresentedAuthorizations()
	if err != nil {
		// Not fatal: the worst case is the behaviour without this call, which is what
		// every version before it did.
		m.log.Warn("cannot list presented authorizations to re-register their TXT leases", "err", err)
		return
	}
	for _, a := range rows {
		if a.TxtName != "" && a.TxtValue != "" {
			// Under the name's mutex: these are exactly the leases that must be visible to a
			// concurrent CleanUp's check-then-delete (see addUnderLock).
			challengeLeases.addUnderLock(a.TxtName, a.TxtValue)
		}
	}
}

// releaseStaleLease drops one TXT lease whose value the caller has established is dead.
//
// The registry cannot tell a dead value from a live one by itself: a value stays in it until
// someone removes it, and while one is held every later cleanup at that name takes the "another
// challenge is still live" branch -- so the provider's delete-EVERY-TXT call never fires again for
// the rest of the process, every TXT record written at that name afterwards stays in DNS until a
// restart, and the name's record quota fills up with values nothing will ever collect. The two
// callers are the places where a value's fate is actually known: a row repointed at a different
// challenge token, and a probe that proved the record absent.
//
// A presented authorization row that still claims the same (name, value) keeps the lease. That is
// the one way a value the caller has given up on can still be needed: another certificate's record
// at the same name, whose rows this call does not own. The check reads the store, so a store that
// cannot be read keeps the lease -- the safe direction, because a leftover lease only delays a
// delete-all, while dropping a live one takes out a record another certificate is waiting on.
func (m *Manager) releaseStaleLease(fqdn, value string) {
	m.releaseStaleLeaseExcept(fqdn, value, nil)
}

// releaseStaleLeaseExcept is releaseStaleLease with one row excluded from the "another row still
// claims this value" check.
//
// The exclusion exists for the row being cleaned up right now: that row is itself a presented
// authorization claiming (name, TxtValue), so asking "does any presented row still need this value"
// would always answer yes and the lease would never be released. See releaseRowStaleLease.
func (m *Manager) releaseStaleLeaseExcept(fqdn, value string, except *state.Authorization) {
	if fqdn == "" || value == "" {
		return
	}
	rows, err := m.store.ListPresentedAuthorizations()
	if err != nil {
		m.log.Warn("cannot check whether another authorization still needs a TXT record; keeping its lease",
			"name", fqdn, "err", err)
		return
	}
	for _, r := range rows {
		if except != nil && r.CertName == except.CertName && r.AuthzURL == except.AuthzURL {
			continue
		}
		if r.TxtName == fqdn && r.TxtValue == value {
			return
		}
	}
	if othersLive := challengeLeases.remove(fqdn, value); othersLive {
		m.log.Info("another challenge is still live at the TXT name; the provider's delete-all waits for the last leaver",
			"name", fqdn)
		return
	}
	m.log.Info("released a TXT lease whose record is gone; the name can be cleaned up again",
		"name", fqdn)
}

// releaseRowStaleLease drops the lease a row's PERSISTED value is holding when its token no longer
// hashes to that value.
//
// The registry has two writers for one row. registerRecoveredLeases (and Present) register
// a.TxtValue, because that is the value recorded as being in DNS; CleanUp removes the value derived
// from the challenge token, because that is what lego's provider deletes by. For a row written
// before the token was refreshed -- the shape the comment in removeAuthzTXT describes as real -- the
// two differ, so the lease that went in can never come out: every later cleanup at that name takes
// the "another challenge is still live" branch, the provider's delete-all never fires again for the
// process lifetime, and the record this row owns stays in DNS. Releasing it here is what makes the
// decision correct rather than making it earlier: the value is this row's own record, and the
// exclusion keeps a different certificate's claim on it intact.
func (m *Manager) releaseRowStaleLease(a *state.Authorization, keyAuth string) {
	if a == nil || a.TxtName == "" || a.TxtValue == "" {
		return
	}
	if dns01.GetChallengeInfo(a.Identifier, keyAuth).Value == a.TxtValue {
		return
	}
	m.releaseStaleLeaseExcept(a.TxtName, a.TxtValue, a)
}

// cleanup deletes every TXT this round wrote. It is only called once all authorizations pass.
func (m *Manager) cleanup(ctx context.Context, certName string, authzs []*state.Authorization) {
	m.registerRecoveredLeases()

	for _, a := range authzs {
		cleaned, err := m.removeAuthzTXT(ctx, a)
		if err != nil {
			// Keep Presented=true: the next round (or cleanupOrphanTXT at wrap-up) will retry.
			m.log.Warn("failed to clean up TXT",
				"cert", certName, "identifier", a.Identifier, "name", a.TxtName, "err", err)
			continue
		}
		if !cleaned {
			// The record cannot even be located, so Presented must stay -- do not rub out the
			// only clue there is.
			continue
		}
		a.Presented = false
		if err := m.store.PutAuthorization(a); err != nil {
			m.log.Warn("failed to update the authorization state", "cert", certName, "identifier", a.Identifier, "err", err)
		}
	}
}

// removeAuthzTXT deletes the TXT record that one authorization wrote into DNS.
//
// The cleaned return means "this record is no longer in DNS": either it was never written or
// this call deleted it. cleaned=false with err=nil means the record cannot be located (the
// token is missing), and the caller **must keep the authorization row** -- the TxtName in it
// is the only remaining clue a human can use to investigate.
func (m *Manager) removeAuthzTXT(ctx context.Context, a *state.Authorization) (cleaned bool, err error) {
	if a == nil || !a.Presented {
		return true, nil
	}
	if a.ChallengeToken == "" || a.Identifier == "" {
		m.log.Warn("the authorization has no token, so the TXT record cannot be located (keeping the row for manual investigation)",
			"cert", a.CertName, "identifier", a.Identifier, "name", a.TxtName)
		return false, nil
	}
	keyAuth, err := m.keyAuth.GetKeyAuthorization(a.ChallengeToken)
	if err != nil {
		return false, fmt.Errorf("compute the key authorization: %w", err)
	}
	// Register exactly the value CleanUp is about to remove, so the registry stays
	// symmetric: a lease that goes in must be the one that comes out, or the leftover
	// entry makes "another challenge is still live here" true forever and the provider's
	// delete-all never fires again for the name for the lifetime of this process.
	//
	// It cannot be a.TxtValue unconditionally. A row written before the challenge token
	// was refreshed can carry a TxtValue that its token no longer hashes to, and
	// registering that stale value would create precisely that phantom lease.
	if a.TxtName != "" {
		challengeLeases.add(a.TxtName, dns01.GetChallengeInfo(a.Identifier, keyAuth).Value)
	}
	// And release the lease the row's own persisted value is holding, if it is not the value this
	// call is about to remove: otherwise that lease blocks the delete-all forever.
	m.releaseRowStaleLease(a, keyAuth)
	if err := m.dns.CleanUp(ctx, a.Identifier, a.ChallengeToken, keyAuth); err != nil {
		return false, fmt.Errorf("clean up TXT %s: %w", a.TxtName, err)
	}
	return true, nil
}

// cleanupOrphanTXT reclaims TXT records that "were written into DNS but no longer belong to
// any order in progress".
//
// Two sources:
//   - the normal cleanup when an order is discarded (discardOrder calls it first);
//   - the previous wrap-up only half succeeded (order deleted, authorization delete failed),
//     or the process was killed.
//
// The second source is exactly why this function exists: it is idempotent and self-healing,
// and nobody has to go digging around in the DNSPod console.
func (m *Manager) cleanupOrphanTXT(ctx context.Context, certName string) error {
	m.registerRecoveredLeases()

	authzs, err := m.store.ListAuthorizations(certName)
	if err != nil {
		return err
	}

	var cleaned, stuck int
	for _, a := range authzs {
		if !a.Presented {
			// A row carrying a token may still have its record up: the pass that wrote
			// it died (or its persist failed) before marking Presented. Probe and try to
			// reclaim before deleting the row -- deleting it blind would orphan that TXT
			// for good, because the row is the only clue to the record's value.
			if a.ChallengeToken != "" && !m.reclaimUnpresentedTXT(ctx, a) {
				stuck++
				continue
			}
			// Rows that provably never reached DNS are deleted outright; leave no
			// rubbish behind.
			if err := m.store.DeleteAuthorization(certName, a.AuthzURL); err != nil {
				m.log.Warn("failed to delete authorization rows", "cert", certName, "authz", a.AuthzURL, "err", err)
			}
			continue
		}

		ok, err := m.removeAuthzTXT(ctx, a)
		if err != nil {
			m.log.Warn("failed to reclaim a leftover TXT record",
				"cert", certName, "identifier", a.Identifier, "name", a.TxtName, "err", err)
			continue
		}
		if !ok {
			// The record cannot be located: keep the authorization row, do not lose the TxtName
			// clue as well.
			stuck++
			continue
		}
		cleaned++
		if err := m.store.DeleteAuthorization(certName, a.AuthzURL); err != nil {
			m.log.Warn("failed to delete authorization rows", "cert", certName, "authz", a.AuthzURL, "err", err)
		}
	}

	if cleaned > 0 {
		m.log.Info("reclaimed a leftover _acme-challenge TXT record", "cert", certName, "count", cleaned)
	}
	if stuck > 0 {
		m.log.Warn("some TXT records could not be reclaimed automatically; their rows are kept and retried next round",
			"cert", certName, "count", stuck,
			"hint", "if this persists, clean the records up in the DNS console; the kept rows carry their names")
	}
	return nil
}

// reclaimUnpresentedTXT probes DNS for the record of an authorization whose row says
// Presented=false but which carries a challenge token -- the fingerprint of a pass that
// died between the DNS write and the state persist. It returns false when the record's
// fate is unknown (the probe failed, or the record is up but would not delete), and then
// the caller must keep the row: its token is the only clue for locating the record again.
func (m *Manager) reclaimUnpresentedTXT(ctx context.Context, a *state.Authorization) bool {
	keyAuth, err := m.keyAuth.GetKeyAuthorization(a.ChallengeToken)
	if err != nil {
		m.log.Warn("cannot compute the key authorization for an unpresented row; keeping it",
			"cert", a.CertName, "identifier", a.Identifier, "err", err)
		return false
	}
	rec, found, err := m.dns.LookupTXT(ctx, a.Identifier, keyAuth)
	if err != nil {
		m.log.Warn("could not probe for the TXT of an interrupted pass; keeping the row",
			"cert", a.CertName, "identifier", a.Identifier, "err", err)
		return false
	}
	if !found {
		// A denial is only evidence once the write would have had time to appear.
		//
		// The row this probes exists for the pass that died between the DNS write and the state
		// persist -- but it also exists for the one that died between persisting the challenge and
		// writing DNS, and the two are indistinguishable from the record alone. What separates them
		// is time: if the challenge was chosen moments ago, every authoritative server may simply
		// not have it yet (DNSPod's addresses lag the API write, measured at up to ~60s for a
		// deletion this session), and deleting the row then drops the only clue to a record that is
		// about to appear -- which stays in DNS and can poison a later challenge at the same name.
		//
		// A row with no timestamp predates the column, so its age is unknown and the previous
		// behaviour is kept: refusing to delete those would strand every one of them forever.
		if age := m.now().Sub(a.ChallengePreparedAt); !a.ChallengePreparedAt.IsZero() &&
			age < m.dns.PropagationTimeout() {
			m.log.Info("an unpresented row's record was denied, but its challenge is newer than the "+
				"propagation window; keeping the row so a record that is still propagating is not lost",
				"cert", a.CertName, "identifier", a.Identifier, "name", a.TxtName,
				"preparedAgo", age.Round(time.Second),
				"window", m.dns.PropagationTimeout())
			return false
		}

		// Every reachable authoritative nameserver denied this value, which is the
		// only answer that licenses deleting the row: the write genuinely never
		// happened. Any other outcome -- including one that merely could not be
		// confirmed -- reaches the caller as err, and the row is kept.
		//
		// The lease an interrupted Present registered for this value is dead for the same
		// reason, and leaving it behind is not harmless: the registry would keep reporting
		// "another challenge is still live at this name" for a record that is not there, so
		// the provider's delete-EVERY-TXT call would never fire again for the rest of the
		// process and every record written here afterwards would stay in DNS. Proof of
		// absence is what makes dropping it safe: nothing can depend on a record that is not
		// there, and the probe is the same evidence the row deletion rests on.
		m.releaseStaleLease(rec.FQDN, rec.Value)
		return true
	}
	m.log.Info("found the TXT of an interrupted pass; reclaiming it before deleting the row",
		"cert", a.CertName, "identifier", a.Identifier, "name", rec.FQDN)
	// Register it before asking for cleanup. CleanUp removes one lease and only fires the
	// provider's delete-all when no other value is live at the name; without registering,
	// this value is invisible to the registry and the delete-all would go ahead -- taking
	// out any other certificate's record at the same name.
	challengeLeases.add(rec.FQDN, rec.Value)
	// The row's persisted value may be a different one (a token refresh before either was written);
	// its lease would block the delete-all for the rest of the process. See releaseRowStaleLease.
	m.releaseRowStaleLease(a, keyAuth)
	if err := m.dns.CleanUp(ctx, a.Identifier, a.ChallengeToken, keyAuth); err != nil {
		m.log.Warn("failed to reclaim the TXT of an interrupted pass; keeping the row",
			"cert", a.CertName, "identifier", a.Identifier, "name", rec.FQDN, "err", err)
		return false
	}
	return true
}

func (m *Manager) finalize(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder, rd round,
) error {
	key, err := ParsePrivateKeyPEM(o.KeyPEM)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("load the order's private key: %w", err))
	}
	csr, err := CreateCSRDER(key, c.Domains)
	if err != nil {
		return m.recordFailure(st, err)
	}

	if o.FinalizeURL == "" {
		return m.recordFailure(st, errors.New("the order has no finalize URL; cannot submit the CSR"))
	}

	// RFC 8555 section 7.4: the CSR must be POSTed to the order's finalize URL.
	//
	// lego's parameter is named orderURL, which is misleading -- UpdateForCSR POSTs straight to
	// whatever URL you hand it. Passing the order URL makes LE treat it as POST-as-GET and
	// fail with "POST-as-GET requests must have an empty payload".
	if _, err := m.core.UpdateOrderForCSR(o.FinalizeURL, csr); err != nil {
		return m.recordFailure(st, fmt.Errorf("submit CSR (finalize): %w", err))
	}

	final, err := m.awaitOrderStatus(ctx, o.OrderURL, "valid", orderWaitTimeout)
	if err != nil {
		return m.recordFailure(st, err)
	}
	if err := m.persistOrder(o, final); err != nil {
		return m.recordFailure(st, err)
	}
	return m.download(ctx, c, st, o, final, rd)
}

func (m *Manager) awaitOrderStatus(
	ctx context.Context, orderURL, want string, timeout time.Duration,
) (legoacme.ExtendedOrder, error) {
	deadline := m.now().Add(timeout)
	var last legoacme.ExtendedOrder

	for {
		o, err := m.core.GetOrder(orderURL)
		if err != nil {
			return last, fmt.Errorf("poll order: %w", err)
		}
		last = o

		switch o.Status {
		case want, "valid":
			return o, nil
		case "invalid":
			return o, fmt.Errorf("order became invalid: %v", o.Err())
		}

		if m.now().After(deadline) {
			// The argument order matters and nothing checks it: %q accepts a time.Duration (it is
			// a string verb, and Duration has a String method), so swapping the first two produced
			// `did not reach "3m0s" within ready` with go vet still clean.
			return last, fmt.Errorf("the order did not reach %q within %s (currently %q)", want, timeout, o.Status)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(m.pollInterval):
		}
	}
}

// spendAuthzFailure books one failed authorization against the identifier's hourly budget.
//
// This is one of the five failed authorizations per identifier per hour that Let's Encrypt allows.
// Nobody spent it while a gauge for it was published anyway, and Remaining on a bucket nobody
// writes returns Capacity by design -- so the number was structurally always full and the alert
// built on it could never fire, on the limit a DNS-01 misconfiguration burns first.
//
// The scope matches the one publishQuota derives (the lowercased identifier), so the spend and the
// gauge land on the same series.
func (m *Manager) spendAuthzFailure(identifier string) {
	if m.quota == nil {
		return
	}
	m.quota.Spend(ratelimit.AuthzFailuresPerIdentifier, strings.ToLower(identifier), 1)
}
