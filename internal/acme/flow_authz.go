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

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// Split out so one concern lives in one file. Same package.

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
		return false, m.recordFailure(ctx, st, err)
	}

	current, err := m.fetchAuthzs(ctx, authzs)
	if err != nil {
		return false, m.recordFailure(ctx, st, err)
	}

	// As in the polling loop: a pass that sees several invalid authorizations books ALL of them.
	// The ledger is what the degraded-set decision reads, so learning about one of two broken names
	// leaves the certificate re-ordering a set that still contains a name the CA rejects.
	var invalid []string
	var invalidErr error

	// Phase 1: write every TXT that is still awaiting validation, all in one go.
	// Here we must never do "write one -> validate one -> delete one": for
	// example.com + *.example.com both authorizations' challenge values land on
	// _acme-challenge.example.com and have to exist at the same time.
	//
	// pendingEntry carries the ledger/cooldown name alongside the row: the row's Identifier
	// is deliberately the bare apex for a wildcard (the apex and its wildcard share one TXT
	// name, so the row must stay unprefixed), while the identifier-failure budget and the
	// cooldown are keyed by the name as the operator wrote it -- "*.example.com" for a
	// wildcard. Phase 3 claims that budget, so it needs the prefixed name too.
	type pendingEntry struct {
		row      *state.Authorization
		targeted string
	}
	var pending []pendingEntry
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
				return false, m.recordFailure(ctx, st, fmt.Errorf("persist a validated authorization (%s): %w", a.Identifier, err))
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

			// Booked, not returned: the ledger is what the degraded-set decision reads, so a pass
			// that sees two invalid identifiers has to record both. See the loop tail.
			invalid = append(invalid, targeted)
			if invalidErr == nil {
				invalidErr = fmt.Errorf(
					"the authorization for identifier %s is invalid: %s", targeted, authzError(cur))
			}
			continue

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
				return false, m.recordFailure(ctx, st, fmt.Errorf(
					"the authorization for %s is %s and discarding the order failed: %w",
					targeted, cur.Status, derr))
			}
			return false, m.recordFailure(ctx, st, fmt.Errorf(
				"the authorization for identifier %s is %s, which cannot be satisfied; a fresh order "+
					"will be placed on the next pass", targeted, cur.Status))
		}

		if !a.Presented {
			chlg, err := pickDNS01(cur)
			if err != nil {
				return false, m.recordFailure(ctx, st, err)
			}
			keyAuth, err := m.keyAuth.GetKeyAuthorization(chlg.Token)
			if err != nil {
				return false, m.recordFailure(ctx, st, fmt.Errorf("compute the key authorization: %w", err))
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
			// Remember when this challenge was chosen. Crash recovery probes for the record of a row
			// that was never marked presented, and a denial is only evidence once the write would
			// have had time to reach the authoritative servers (see reclaimUnpresentedTXT).
			a.ChallengePreparedAt = m.now()

			// The refreshed instant has to be durable BEFORE the DNS write it describes: persisting
			// it afterwards leaves a stored age older than the write, and the reclaim probe could
			// then trust an authoritative denial for a record that is still propagating.
			//
			// What else may be persisted along with it depends on whether this row already names a
			// record, because the row's token is the only clue that locates one (reclaimUnpresentedTXT
			// derives the value it probes for from it).
			if firstVisit {
				// Nothing can belong to this row yet -- there is no token -- so the new one may go
				// to disk before the write: if the pass dies in between, recovery probes for a value
				// that was never written, is denied, and strands nothing.
				a.ChallengeURL = chlg.URL
				a.ChallengeToken = chlg.Token
				if err := m.store.PutAuthorization(a); err != nil {
					return false, m.recordFailure(ctx, st, fmt.Errorf("persist a new challenge (%s): %w", a.Identifier, err))
				}
			} else {
				// The row already names the record an earlier attempt wrote, so only the refreshed
				// age may be persisted here. Writing the new token first means that a write which
				// then fails -- an ordinary DNSPod API error, no crash needed -- overwrites that
				// clue: recovery probes the new value, is authoritatively denied, drops the row, and
				// the old record stays in DNS with nothing naming it. See
				// TestAFailedWriteOnTheRevisitPathKeepsTheTokenThatNamesTheRecord.
				if err := m.store.PutAuthorization(a); err != nil {
					return false, m.recordFailure(ctx, st, fmt.Errorf("persist the age of a new challenge (%s): %w", a.Identifier, err))
				}
				a.ChallengeURL = chlg.URL
				a.ChallengeToken = chlg.Token
			}

			adopted := false
			if !firstVisit {
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
					return false, m.recordFailure(ctx, st, fmt.Errorf("present TXT (%s): %w", a.Identifier, err))
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
			// The record is in DNS and the state write that would have named it failed, so nothing
			// on disk points at it any more: the row still carries the token of the earlier attempt
			// (that is exactly what the revisit path holds back until the write succeeds), and
			// recovery derives the value it probes for from the token. Left alone, the record stays
			// in DNS for the rest of the certificate's life -- a stale TXT at the challenge name that
			// no row, no lease and no log line mentions. Take it back out instead.
			if a.Presented {
				if cleaned, cerr := m.removeAuthzTXT(ctx, a); cerr != nil || !cleaned {
					m.log.Warn("the presented TXT could not be reclaimed after the state write failed, "+
						"so it is in DNS under the name recorded in the row's txt_name",
						"cert", c.Name, "identifier", a.Identifier, "name", a.TxtName, "err", cerr)
				} else {
					m.log.Warn("the state write failed after the TXT was presented, so the record was "+
						"taken back out rather than left unnamed in DNS",
						"cert", c.Name, "identifier", a.Identifier, "name", a.TxtName)
				}
			}
			return false, m.recordFailure(ctx, st, fmt.Errorf("persist a presented challenge (%s): %w", a.Identifier, err))
		}
		records = append(records, DNSRecord{FQDN: a.TxtName, Value: a.TxtValue})
		pending = append(pending, pendingEntry{row: a, targeted: targeted})
	}

	if invalidErr != nil {
		if len(invalid) > 1 {
			m.log.Warn("several identifiers were already invalid at the start of this pass; all of "+
				"them are in the failure ledger, which is what the degraded-set decision reads",
				"cert", c.Name, "identifiers", strings.Join(invalid, ","))
		}
		return false, m.recordFailure(ctx, st, invalidErr)
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
		return false, m.recordFailure(ctx, st, fmt.Errorf("wait for TXT propagation: %w", err))
	}

	// Phase 3: only once propagation is confirmed do we tell the CA, one by one, to validate.
	for _, p := range pending {
		a := p.row
		if a.ChallengeSent {
			continue
		}
		// The identifier's failure budget is claimed BEFORE the CA is asked to validate.
		//
		// This is the point of no return for spending it: once the challenge is accepted, a failure
		// costs one of the five authorizations per identifier per hour, and the budget belongs to
		// the IDENTIFIER -- several certificates for the same name share it. The decision used to be
		// check-then-act, and the webhook fan-out admits up to eight passes at once, so eight
		// certificates sharing a name all read "not cooling" and all failed inside one window,
		// leaving the bucket at -3 against a capacity of five. Claiming here means the second pass
		// sees the first pass's claim whatever order the scheduler picks; a success clears it again
		// (see awaitAuthorizations), and an order that is merely refused by the CA never claims
		// anything, which is why this is not done where the order is placed.
		//
		// Claimed under the targeted name, not the row's Identifier: for a wildcard the row
		// deliberately holds the bare apex (see the targeted comment above), and claiming the
		// budget against the apex would cool down the wrong name -- the healthy apex -- while
		// the wildcard that is actually about to be validated keeps spending.
		m.noteIdentifierFailure(p.targeted)
		if err := m.core.AcceptChallenge(a.ChallengeURL); err != nil {
			return false, m.recordFailure(ctx, st, fmt.Errorf("trigger validation (%s): %w", a.Identifier, err))
		}
		a.ChallengeSent = true
		if err := m.store.PutAuthorization(a); err != nil {
			// The challenge WAS accepted; only the record of it failed. Counting the pass as a
			// failure is still right: without the row, the next pass cannot tell that this
			// challenge is already in flight, and the pass has not finished its job.
			return false, m.recordFailure(ctx, st, fmt.Errorf("persist that a challenge was accepted (%s): %w", a.Identifier, err))
		}
	}

	// Phases 4 and 5 want the bare rows again.
	pendingRows := make([]*state.Authorization, len(pending))
	for i, p := range pending {
		pendingRows[i] = p.row
	}

	// Phase 4: poll until everything is valid.
	if err := m.awaitAuthorizations(ctx, pendingRows); err != nil {
		return false, m.recordFailure(ctx, st, err)
	}

	// Phase 5: only after every validation passes do we clean up the TXT records together.
	m.cleanup(ctx, c.Name, pendingRows)
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
		// Every invalid authorization this poll sees is booked, not just the first.
		//
		// Returning on the first one left the failure ledger knowing about one name of however many
		// the CA rejected: measured with a certificate whose [a,b,c] had a AND b invalid, the ledger
		// recorded a three times, the degraded round ordered [b,c] -- still containing the invalid b --
		// and the certificate could never degrade far enough to issue at all. The ledger is what the
		// fallback decides from, so a name the CA calls invalid has to be in it after this pass.
		var invalid []string
		var invalidErr error
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
				invalid = append(invalid, targeted)
				if invalidErr == nil {
					invalidErr = fmt.Errorf("validation failed for identifier %s: %s", targeted, authzError(cur))
				}
				continue
			default:
				stillPending = append(stillPending, a)
			}
		}
		pending = stillPending

		if invalidErr != nil {
			// Reported once, after every invalid authorization in this poll has been booked. The
			// message names the first one; the ledger now holds all of them.
			if len(invalid) > 1 {
				m.log.Warn("several identifiers failed validation in this poll; all of them are in the "+
					"failure ledger, which is what the degraded-set decision reads",
					"identifiers", strings.Join(invalid, ","))
			}
			return invalidErr
		}
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
