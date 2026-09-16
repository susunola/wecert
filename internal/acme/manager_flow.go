package acme

import (
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
func (m *Manager) advance(ctx context.Context, c *config.Certificate, st *state.CertState, o *state.Order) error {
	order, err := m.core.GetOrder(o.OrderURL)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("get order: %w", err))
	}
	// Same contract as the other two call sites: persistOrder returns its write
	// error, and a failed write means crash recovery would resume from stale state.
	// Discarding it would defeat the point of making it return one, and Go does not
	// warn about a dropped return value.
	if err := m.persistOrder(o, order); err != nil {
		return m.recordFailure(st, err)
	}

	switch order.Status {
	case "valid":
		return m.download(ctx, c, st, o, order)

	case "invalid":
		// The order is dead. Clean it up so the next round decides from scratch (which will
		// go through backoff).
		err := fmt.Errorf("order became invalid: %v", order.Err())
		if derr := m.discardOrder(ctx, c.Name); derr != nil {
			return errors.Join(err, derr)
		}
		return m.recordFailure(st, err)

	case "ready":
		return m.finalize(ctx, c, st, o, order)
	}

	// pending / processing: drive the DNS-01 challenges through to the end.
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
		return m.download(ctx, c, st, o, ready)
	}
	return m.finalize(ctx, c, st, o, ready)
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
				return false, err
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
			if rerr := m.store.RecordIdentifierFailure(
				c.Name, targeted, authzError(cur), m.now()); rerr != nil {
				m.log.Warn("failed to record the identifier failure",
					"cert", c.Name, "identifier", targeted, "err", rerr)
			}

			return false, m.recordFailure(st, fmt.Errorf(
				"the authorization for identifier %s is invalid: %s", targeted, authzError(cur)))
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

			// Write only, do not wait for propagation -- wait once after all TXT are written.
			// Waiting per record makes a wildcard and its apex wait twice for nothing on the
			// same TXT name (one propagation round takes over 2 minutes on DNSPod's free tier,
			// so that is minutes right there).
			rec, err := m.dns.Present(ctx, a.Identifier, chlg.Token, keyAuth)
			if err != nil {
				return false, m.recordFailure(st, fmt.Errorf("present TXT (%s): %w", a.Identifier, err))
			}

			a.ChallengeURL = chlg.URL
			a.ChallengeToken = chlg.Token
			a.TxtName = rec.FQDN
			a.TxtValue = rec.Value
			a.Presented = true
			m.log.Info("TXT presented",
				"cert", c.Name, "identifier", a.Identifier, "name", a.TxtName)
		}

		if err := m.store.PutAuthorization(a); err != nil {
			return false, err
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
			return false, err
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
			if a.Status != cur.Status {
				a.Status = cur.Status
				if perr := m.store.PutAuthorization(a); perr != nil {
					return perr
				}
			}

			switch cur.Status {
			case "valid":
			case "invalid":
				return fmt.Errorf("validation failed for identifier %s: %s", a.Identifier, authzError(cur))
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

// cleanup deletes every TXT this round wrote. It is only called once all authorizations pass.
func (m *Manager) cleanup(ctx context.Context, certName string, authzs []*state.Authorization) {
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
	authzs, err := m.store.ListAuthorizations(certName)
	if err != nil {
		return err
	}

	var cleaned, stuck int
	for _, a := range authzs {
		if !a.Presented {
			// Rows that never reached DNS are deleted outright; leave no rubbish behind.
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
		m.log.Warn("some TXT records could not be reclaimed automatically; clean them up in the DNS console",
			"cert", certName, "count", stuck,
			"hint", "no challenge token, so the specific record cannot be located")
	}
	return nil
}

func (m *Manager) finalize(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder,
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
	return m.download(ctx, c, st, o, final)
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
			return last, fmt.Errorf("the order did not reach %q within %s (currently %q)", timeout, want, o.Status)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(m.pollInterval):
		}
	}
}
