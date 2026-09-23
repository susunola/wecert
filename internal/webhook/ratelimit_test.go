package webhook

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var limiterT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Concurrent wrong-token requests must not slip past the lockout.
//
// auth used to call allowed() and then recordFailure() as two steps: a burst of N concurrent
// failures all saw failures==0 and all counted, so one burst could place far more than
// authMaxFailures guesses. fail() checks and counts under one mutex; this is what keeps it
// that way.
func TestConcurrentFailuresCannotBypassTheLockout(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()

	const n = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	blocked := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			blocked[i], _ = l.fail("1.2.3.4", limiterT0)
		}(i)
	}
	close(start)
	wg.Wait()

	admitted := 0
	for _, b := range blocked {
		if !b {
			admitted++
		}
	}
	// The request that tips the count over the limit is still answered 401 (block engages
	// for the next one), so exactly authMaxFailures are admitted -- never more.
	if admitted != authMaxFailures {
		t.Errorf("a concurrent burst admitted %d failed attempts, want exactly %d", admitted, authMaxFailures)
	}
	if ok, _ := l.allowed("1.2.3.4", limiterT0); ok {
		t.Error("the address must be blocked after the concurrent burst")
	}
}

// The lockout must survive continued failures: resetting the failure window
// while a block is active would also drop blockedUntil, shrinking the
// 15-minute lockout to the 5-minute window under a sustained attack.
func TestRecordFailureDoesNotResetDuringBlock(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()

	for i := 0; i < authMaxFailures; i++ {
		l.recordFailure("1.2.3.4", limiterT0)
	}
	if ok, _ := l.allowed("1.2.3.4", limiterT0); ok {
		t.Fatal("should be blocked after hitting the failure limit")
	}

	// The window has expired but the block has not; one more failure must not
	// wipe the state.
	t1 := limiterT0.Add(authWindow + time.Minute)
	l.recordFailure("1.2.3.4", t1)

	ok, retryAfter := l.allowed("1.2.3.4", t1)
	if ok {
		t.Fatal("the block should still be active")
	}
	if min := limiterT0.Add(authBlockFor).Sub(t1); retryAfter < min {
		t.Errorf("the lockout must not be cut short: got %v, want at least %v", retryAfter, min)
	}
}

// Once both the block and the window are over, the address starts clean.
func TestRecordFailureResetsAfterBlockExpires(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()

	for i := 0; i < authMaxFailures; i++ {
		l.recordFailure("1.2.3.4", limiterT0)
	}
	t1 := limiterT0.Add(authBlockFor + authWindow + time.Minute)
	l.recordFailure("1.2.3.4", t1)

	if ok, _ := l.allowed("1.2.3.4", t1); !ok {
		t.Error("a single failure long after the block expired should not re-block")
	}
}

// A success decays the failure count instead of wiping it: one interleaved
// legit call must not forgive a shared-egress-IP attacker outright.
func TestRecordSuccessDecaysFailures(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()

	// 8 failures -> success halves to 4 -> 5 more failures reach 9, still below
	// the limit; the 6th reaches 10 and locks the address out.
	for i := 0; i < 8; i++ {
		l.recordFailure("1.2.3.4", limiterT0)
	}
	l.recordSuccess("1.2.3.4", limiterT0)

	t1 := limiterT0.Add(time.Minute)
	for i := 0; i < 5; i++ {
		l.recordFailure("1.2.3.4", t1)
	}
	if ok, _ := l.allowed("1.2.3.4", t1); !ok {
		t.Fatal("9 decayed failures should not lock the address out")
	}
	l.recordFailure("1.2.3.4", t1)
	if ok, _ := l.allowed("1.2.3.4", t1); ok {
		t.Error("the 10th failure after the decay must lock the address out -- " +
			"a full wipe would never reach this point under an interleaved attack")
	}
}

// Sustained brute force from a shared IP must still lock out even with a legit
// success after every burst: each success only halves the count, so bursts
// larger than the residual keep accumulating.
func TestSustainedBruteForceLocksOutDespiteSuccesses(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()

	// First burst: one below the limit, then a legit success (halves to 4).
	for i := 0; i < authMaxFailures-1; i++ {
		l.recordFailure("1.2.3.4", limiterT0)
	}
	l.recordSuccess("1.2.3.4", limiterT0)

	// Second identical burst: the residual carries over, so it locks out well
	// before the burst ends. With wipe-on-success semantics this loop could
	// repeat forever without ever locking out.
	t1 := limiterT0.Add(time.Minute)
	for i := 0; i < authMaxFailures-1; i++ {
		l.recordFailure("1.2.3.4", t1)
	}
	if ok, _ := l.allowed("1.2.3.4", t1); ok {
		t.Error("a second full burst after one success must lock the address out")
	}
}

// Below the forgive floor the residue is noise (a typo or two), so a success
// clears it entirely -- a legit caller is not permanently dogged by old slips.
func TestRecordSuccessForgivesBelowTheFloor(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()

	for i := 0; i < 3; i++ {
		l.recordFailure("1.2.3.4", limiterT0)
	}
	l.recordSuccess("1.2.3.4", limiterT0)

	for i := 0; i < authMaxFailures-1; i++ {
		l.recordFailure("1.2.3.4", limiterT0.Add(time.Minute))
	}
	if ok, _ := l.allowed("1.2.3.4", limiterT0.Add(time.Minute)); !ok {
		t.Error("three forgiven failures must not count towards the limit")
	}
}

// The sweep must be amortized once the map is large.
//
// Sweeping on every failure hands an attacker a quadratic cost: one failed request from
// each of many source addresses, and every failure scans the whole map. The sweep is
// therefore rate-limited by time, not only by size.
func TestGcIsAmortizedOnceTheMapIsLarge(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()

	// A map well past the threshold, every entry long expired.
	for i := 0; i < authLimiterGCThreshold+100; i++ {
		l.byAddr[fmt.Sprintf("10.0.%d.%d", i/256, i%256)] = &authLimiterState{
			failures:    1,
			windowStart: limiterT0.Add(-time.Hour),
		}
	}
	// Pretend a sweep just happened: within the interval, no second sweep may run.
	l.lastGC = limiterT0

	l.recordFailure("1.2.3.4", limiterT0)

	if got := len(l.byAddr); got <= authLimiterGCThreshold {
		t.Fatalf("a second sweep ran inside the interval: the map dropped to %d entries", got)
	}

	// Once the interval has passed, the sweep does run and reclaims the expired entries.
	l.recordFailure("1.2.3.4", limiterT0.Add(authLimiterGCInterval+time.Second))

	if got := len(l.byAddr); got > 2 {
		t.Errorf("the sweep must reclaim expired entries after the interval, %d left", got)
	}
}

// A burst of failed authentications must not leave the limiter map populated forever.
//
// gc used to be reached only from recordFailure, so once the failures stopped nothing
// ever swept the entries the burst created -- there is no background ticker, and
// recordSuccess did not call it either. A client with an IPv6 /64 can produce unbounded
// distinct source addresses, so the map is not bounded by "the number of attackers".
func TestSuccessSweepsExpiredLimiterState(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()

	// Fill past the sweep threshold with entries that are already outside the window.
	// They are written directly because recordFailure would stamp them with `now`.
	old := limiterT0.Add(-2 * authWindow)
	for i := 0; i < authLimiterGCThreshold+10; i++ {
		addr := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		l.byAddr[addr] = &authLimiterState{windowStart: old, failures: 1}
	}

	// A single successful authentication is enough to trigger the sweep.
	l.recordSuccess("192.0.2.1", limiterT0.Add(time.Minute))

	if got := len(l.byAddr); got > 1 {
		t.Errorf("limiter map holds %d entries after a success swept it; expired state must not accumulate", got)
	}
}

// The hard cap bounds the map even while every entry is still inside the window, which
// is the state a flood produces (the time-based sweep deliberately keeps those).
func TestLimiterMapIsCapped(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter()
	for i := 0; i < authLimiterMaxEntries+100; i++ {
		addr := fmt.Sprintf("2001:db8::%x", i)
		l.recordFailure(addr, limiterT0.Add(time.Duration(i)*time.Millisecond))
	}
	if got := len(l.byAddr); got > authLimiterMaxEntries {
		t.Errorf("limiter map holds %d entries, want at most %d", got, authLimiterMaxEntries)
	}
}
