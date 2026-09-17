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

// A spend taken while the clock is behind must not move the anchor back with it.
//
// Remaining refuses to credit an interval that has not passed, but Spend still stamped the
// snapshot with `now`. s.Tokens had already been credited up to s.At, so anchoring at an earlier
// instant made [now, s.At] creditable a second time: after the clock caught up, the same hour was
// refilled twice and the estimate reported quota the CA would refuse. The anchor therefore only
// moves forward, and an already-credited interval can never be credited again.
func TestASpendOnABackwardClockDoesNotReAnchorTheSnapshot(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	l := NewOrdersPerAccount

	// Spend 100, then spend again while the clock reads an hour earlier, then read at the
	// original instant.
	s := Spend(Snapshot{}, l, 100, now)
	s = Spend(s, l, 1, now.Add(-time.Hour))

	want := l.Capacity - 101
	if got := Remaining(s, l, now); got != want {
		t.Errorf("tokens after a spend taken on a backward clock = %v, want %v: the anchor moved back, "+
			"so the interval between the two instants is credited twice and the estimate hands out "+
			"quota the CA would refuse", got, want)
	}
	if s.At.Before(now) {
		t.Errorf("the snapshot anchor moved backwards to %v (was %v): every later read re-credits the "+
			"interval in between", s.At, now)
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

// A negative cost must not hand quota back.
//
// The API records consumption, so the only defensible reading of a negative cost is "nothing was
// consumed". Treating it as credit would mean a sign error in a caller *increases* the reported
// allowance -- the direction that leads to issue attempts the CA then refuses.
func TestNegativeCostDoesNotCreditTheBucket(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	l := NewOrdersPerAccount

	spent := Spend(Snapshot{}, l, 10, now)
	if got := Remaining(spent, l, now); got != l.Capacity-10 {
		t.Fatalf("after spending 10: %v, want %v", got, l.Capacity-10)
	}

	credited := Spend(spent, l, -5, now)
	if got := Remaining(credited, l, now); got != l.Capacity-10 {
		t.Errorf("a negative cost credited the bucket: %v, want %v (unchanged)",
			got, l.Capacity-10)
	}
}

// A limit with no refill interval must not panic, and must not hand out tokens it cannot justify.
//
// Remaining divides by the interval, so this was `integer divide by zero`. Every Limit currently
// comes from the table in this file, but Remaining takes one, so the function has to be total.
func TestZeroRefillIntervalIsHandledNotPanicked(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	l := Limit{Name: "no-refill", Capacity: 5, Refill: 0}

	// An exhausted bucket stays exhausted: it never refills.
	spent := Snapshot{Tokens: 0, At: now.Add(-time.Hour)}
	if got := Remaining(spent, l, now); got != 0 {
		t.Errorf("a bucket with no refill interval gained tokens: %v, want 0", got)
	}
	// A full one stays full rather than dividing by zero.
	if got := Remaining(Snapshot{Tokens: 5, At: now.Add(-time.Hour)}, l, now); got != 5 {
		t.Errorf("got %v, want 5", got)
	}
	// And an overdrawn one reports empty rather than negative.
	if got := Remaining(Snapshot{Tokens: -3, At: now}, l, now); got != 0 {
		t.Errorf("got %v, want 0 (no negative allowance)", got)
	}
}

// The zero instant must be rejected rather than reported as a parsed deadline.
//
// "retry after 0001-01-01 00:00:00 UTC" parses cleanly and equals time.Time{}, which is the value
// callers use for "no deadline". Returning it with ok=true would mean "blocked until the zero
// time", i.e. not blocked, while looking like a successful parse -- so a malformed instant would
// silently disable the block that protects the rate-limit budget.
func TestZeroInstantIsNotADeadline(t *testing.T) {
	if at, ok := ParseRetryAfter("retry after 0001-01-01 00:00:00 UTC"); ok {
		t.Errorf("the zero instant means no deadline, not a parsed one; got %v with ok=true", at)
	}
	// The documented format still parses.
	if _, ok := ParseRetryAfter("retry after 2026-09-23 04:00:00 UTC"); !ok {
		t.Error("the documented format must still parse")
	}
}

// Spending while in debt must carry the debt, not forgive it.
//
// Spend subtracted from Remaining(), which clamps a debt to zero: a bucket at -5 that was spent
// again landed at -1 instead of -6, so the next token arrived several refill intervals early. The
// package's own contract is the opposite ("an over-spend is not silently forgiven"), and the
// existing over-spend test only ever READS the bucket afterwards, so it never saw this.
func TestSpendingWhileInDebtCarriesTheDebt(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	l := AuthzFailuresPerIdentifier // capacity 5, one token back every 12m

	// Ten against a capacity of five: five spent, five of debt.
	s := Spend(Snapshot{}, l, 10, now)
	if s.Tokens != -5 {
		t.Fatalf("an over-spend of 5 against a capacity of 5 must leave -5, got %v", s.Tokens)
	}

	// One refill interval later, one more spend. Remaining() would report 0 here, so subtracting
	// from it turns -5 into -1 and hands back four tokens that do not exist.
	after := now.Add(l.Refill)
	s = Spend(s, l, 1, after)
	if s.Tokens != -5 {
		t.Errorf("spending 1 while in debt must leave -5 (one refill earned, one token spent), got %v: "+
			"the debt below zero was forgiven", s.Tokens)
	}
	if got := Remaining(s, l, after); got != 0 {
		t.Errorf("a bucket in debt has nothing available, got %v", got)
	}

	// The debt is worked off by refills, not forgiven: the bucket is at -5, so five refills bring it
	// to exactly zero and the sixth is the first spendable token.
	if got := Remaining(s, l, after.Add(4*l.Refill)); got != 0 {
		t.Errorf("after 4 more refills the bucket is still in debt, got %v", got)
	}
	if got := Remaining(s, l, after.Add(5*l.Refill)); got != 0 {
		t.Errorf("five refills clear the debt to exactly zero, got %v", got)
	}
	if got := Remaining(s, l, after.Add(6*l.Refill)); got != 1 {
		t.Errorf("the sixth refill is the first available token, got %v (forgiven debt shows up here "+
			"as several)", got)
	}
}
