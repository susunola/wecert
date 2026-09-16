package ratelimit

import (
	"math"
	"testing"
	"time"
)

func TestRemainingStartsFull(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	// Nothing ever spent: the bucket is full. Reporting 0 here would tell an operator they
	// have no quota on a fresh install.
	if got := Remaining(Snapshot{}, NewOrdersPerAccount, now); got != NewOrdersPerAccount.Capacity {
		t.Errorf("an untouched bucket must read full, got %v want %v", got, NewOrdersPerAccount.Capacity)
	}
}

func TestSpendThenRefill(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	l := NewOrdersPerAccount

	s := Spend(Snapshot{}, l, 1, now)
	if got, want := Remaining(s, l, now), l.Capacity-1; got != want {
		t.Errorf("after one order: %v, want %v", got, want)
	}

	// The published refill is 1 per 36 seconds, so 36s restores exactly one token.
	later := now.Add(36 * time.Second)
	if got, want := Remaining(s, l, later), l.Capacity; got != want {
		t.Errorf("after one refill interval: %v, want %v", got, want)
	}

	// Half an interval restores half a token, not zero: the bucket is continuous, and
	// flooring would make a long run of closely spaced renewals look safer than it is.
	half := now.Add(18 * time.Second)
	if got, want := Remaining(s, l, half), l.Capacity-0.5; math.Abs(got-want) > 1e-9 {
		t.Errorf("after half a refill interval: %v, want %v", got, want)
	}
}

func TestRefillIsCappedAtCapacity(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	l := CertsPerExactIdentifierSet

	s := Spend(Snapshot{}, l, 5, now)
	if got := Remaining(s, l, now); got != 0 {
		t.Fatalf("spending the whole bucket must leave 0, got %v", got)
	}
	// Idle long enough and the bucket must stop at its capacity, never above: a certificate
	// issued once a month must not look able to issue 50 at once.
	//
	// The duration is the refill time times the capacity, not "a week": the published refill
	// for this limit (1 per 34h) is deliberately slower than 7d/5, so a week leaves it just
	// short of full. That is the safe direction and the test asserts the real behaviour rather
	// than the arithmetic the window suggests.
	if got := Remaining(s, l, now.Add(time.Duration(l.Capacity)*l.Refill)); got != l.Capacity {
		t.Errorf("a long idle period must refill to capacity and stop, got %v want %v", got, l.Capacity)
	}
	// And it must never exceed capacity, even after far longer.
	if got := Remaining(s, l, now.Add(365*24*time.Hour)); got != l.Capacity {
		t.Errorf("the bucket must cap at capacity, got %v want %v", got, l.Capacity)
	}
}

func TestOverSpendIsNotForgiven(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	l := CertsPerExactIdentifierSet

	// Spend six against a bucket of five. The CA would have rejected the sixth, so the
	// estimate has to remember the debt rather than clamp to zero -- otherwise the next
	// request looks allowed after a single refill interval.
	s := Spend(Snapshot{}, l, 6, now)
	if got := Remaining(s, l, now); got != 0 {
		t.Errorf("an overdrawn bucket must read 0, got %v", got)
	}
	if got := Remaining(s, l, now.Add(l.Refill)); math.Abs(got) > 1e-9 {
		t.Errorf("after one refill interval the debt is not yet worked off, got %v", got)
	}
	// Borrowing 1 against an empty bucket: the refill must work off the debt before any
	// allowance reappears.
	// Two intervals: the first works off the debt, the second provides a token.
	if got := Remaining(s, l, now.Add(2*l.Refill)); math.Abs(got-1) > 1e-9 {
		t.Errorf("after two refill intervals one token is available, got %v", got)
	}
}

func TestBackwardClockDoesNotCreateTokens(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	l := NewOrdersPerAccount
	s := Spend(Snapshot{}, l, 10, now)

	// A corrected clock steps backwards. Treating that as negative elapsed time would ADD
	// tokens and report quota that does not exist.
	if got := Remaining(s, l, now.Add(-time.Hour)); got != l.Capacity-10 {
		t.Errorf("a backward clock must not mint tokens, got %v want %v", got, l.Capacity-10)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want time.Time
		ok   bool
	}{
		{
			name: "the documented format",
			msg: "too many new registrations (10) from this IP address in the last 3h0m0s, " +
				"retry after 1970-01-01 00:18:15 UTC.",
			want: time.Date(1970, 1, 1, 0, 18, 15, 0, time.UTC),
			ok:   true,
		},
		{
			name: "wrapped in the error chain lego produces",
			msg: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: " +
				"too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, " +
				"retry after 2026-09-23 04:00:00 UTC",
			want: time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC),
			ok:   true,
		},
		{
			name: "a rate-limit error with no instant",
			msg:  "acme: error: 429 :: too many requests",
			ok:   false,
		},
		{
			name: "a non-rate-limit error that happens to mention retry",
			msg:  "acme: error: 500 :: please retry later",
			ok:   false,
		},
		{
			name: "an unparseable instant is refused rather than guessed",
			msg:  "too many new orders, retry after soon",
			ok:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseRetryAfter(c.msg)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (got %v)", ok, c.ok, got)
			}
			if c.ok && !got.Equal(c.want) {
				t.Errorf("instant = %s, want %s", got, c.want)
			}
		})
	}
}

func TestWorstCaseBlockedByTakesTheLatest(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	deadlines := []Deadline{
		{At: now.Add(time.Hour), Reason: "new-orders"},
		{At: now.Add(6 * time.Hour), Reason: "certs-per-registered-domain"},
		{At: now.Add(-time.Hour), Reason: "already passed"},
		{},
	}

	got, ok := WorstCaseBlockedBy(deadlines, now)
	if !ok {
		t.Fatal("expected a deadline")
	}
	// The CA reports the furthest-resetting limit when several are exceeded; waiting for
	// anything less means the next request fails again.
	if !got.At.Equal(now.Add(6 * time.Hour)) {
		t.Errorf("worst deadline = %s, want the 6h one", got.At)
	}
	if _, ok := WorstCaseBlockedBy(nil, now); ok {
		t.Error("no deadlines must report not blocked")
	}
}
