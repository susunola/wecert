package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/ratelimit"
)

// The failed-authorization budget is accounted under the BARE identifier in all three places
// that touch it: the spend, the CA-refusal bookkeeping and the ordering gate.
//
// RFC 8555 §7.1.3 forbids the "*." prefix in an authorization's identifier, so a CA refusing a
// wildcard certificate's order names "example.com" -- while the spend path and the gate are
// handed the name as the operator wrote it, "*.example.com". Booking those under different
// scopes splits one budget into two buckets: the spend lands on a series the refusal never
// gates, and the refusal gates a scope nothing ever spends against, so the wildcard keeps
// ordering inside the very window the CA named.
func TestAWildcardFailureIsSpentAgainstTheBareIdentifier(t *testing.T) {
	store, m, _, _ := newAPITestHarness(t, []string{"*.example.com"})

	m.spendAuthzFailure("*.example.com")

	bucket, err := store.GetRateBucket(ratelimit.AuthzFailuresPerIdentifier.Name, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if want := ratelimit.AuthzFailuresPerIdentifier.Capacity - 1; bucket.Tokens != want {
		t.Errorf("the wildcard's failed authorization must be booked against the bare identifier: "+
			"tokens=%v want %v", bucket.Tokens, want)
	}
	wildcardBucket, err := store.GetRateBucket(ratelimit.AuthzFailuresPerIdentifier.Name, "*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if wildcardBucket.Tokens != 0 || !wildcardBucket.ObservedAt.IsZero() {
		t.Errorf("nothing may be spent against the \"*.\" form; the CA never accounts under it: %+v",
			wildcardBucket)
	}
}

// The gate half of the same contract: a wildcard-only certificate whose order the CA refused
// with a failed-authorizations deadline naming the BARE domain must not place another order
// inside that window.
func TestAWildcardRefusalGatesTheBareIdentifier(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"*.example.com"})
	// A mutable clock: the refused pass schedules a 1-minute backoff, and the second pass must
	// get PAST it to reach the gate -- the CA's deadline (3 hours out) is what has to stop it.
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })
	dueForRenewal(t, store, cert, now)
	fake.orders = append(fake.orders, terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"))
	// Boulder names the authorization identifier, which never carries the wildcard prefix.
	fake.newOrderErr = errors.New("acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many " +
		"failed authorizations (5) for \"example.com\" in the last 1h0m0s, retry after " +
		"2026-09-16 15:00:00 UTC: see https://letsencrypt.org/docs/rate-limits/")

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a rate-limited order must be reported as a failure")
	}
	if _, _, blocked := m.quota.BlockedUntil(ratelimit.AuthzFailuresPerIdentifier, "example.com"); !blocked {
		t.Fatal("the refusal names the bare identifier, so that deadline must be recorded")
	}

	// The next pass must be stopped by the gate BEFORE NewOrder: the scope the gate consults
	// for "*.example.com" is the same bare "example.com" the refusal was booked against. The
	// clock steps past the refused pass's own 1-minute backoff so the gate is what decides.
	now = now.Add(2 * time.Minute)
	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a pass inside the CA's failed-authorization window must not converge")
	}
	orders := 0
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "NewOrder") {
			orders++
		}
	}
	if orders != 1 {
		t.Errorf("the refusal must gate the wildcard's next order (scope \"example.com\"); "+
			"NewOrder was called %d times, want 1", orders)
	}
}
