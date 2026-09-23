package acme

import (
	"context"
	"errors"
	"fmt"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// Split out so one concern lives in one file. Same package.

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
				return m.recordFailure(ctx, st, errors.Join(fmt.Errorf("get order: %w", err), derr))
			}
			return m.recordFailure(ctx, st, fmt.Errorf(
				"get order: %w (the order was discarded; the next attempt places a new one)", err))
		}
		return m.recordFailure(ctx, st, fmt.Errorf("get order: %w", err))
	}
	// It answered, so the URL is alive: forget any earlier failures.
	m.clearOrderFetchFailures(o.OrderURL)
	// Same contract as the other two call sites: persistOrder returns its write
	// error, and a failed write means crash recovery would resume from stale state.
	// Discarding it would defeat the point of making it return one, and Go does not
	// warn about a dropped return value.
	if err := m.persistOrder(o, order); err != nil {
		return m.recordFailure(ctx, st, err)
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
		return m.recordFailure(ctx, st, err)

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
			return m.recordFailure(ctx, st, err)
		}
		if err := m.persistOrder(o, final); err != nil {
			return m.recordFailure(ctx, st, err)
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
		return m.recordFailure(ctx, st, err)
	}
	if err := m.persistOrder(o, ready); err != nil {
		return m.recordFailure(ctx, st, err)
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
