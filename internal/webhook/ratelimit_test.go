package webhook

import (
	"fmt"
	"testing"
	"time"
)

var limiterT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// The lockout must survive continued failures: resetting the failure window
// while a block is active would also drop blockedUntil, shrinking the
// 15-minute lockout to the 5-minute window under a sustained attack.
func TestRecordFailureDoesNotResetDuringBlock(t *testing.T) {
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

// A success deletes the address state outright, so failures before it no
// longer count.
func TestRecordSuccessClearsFailures(t *testing.T) {
	l := newAuthLimiter()

	for i := 0; i < authMaxFailures-1; i++ {
		l.recordFailure("1.2.3.4", limiterT0)
	}
	l.recordSuccess("1.2.3.4")

	for i := 0; i < authMaxFailures-1; i++ {
		l.recordFailure("1.2.3.4", limiterT0.Add(time.Minute))
	}
	if ok, _ := l.allowed("1.2.3.4", limiterT0.Add(time.Minute)); !ok {
		t.Error("failures before a success should not count towards the limit")
	}
}

// The sweep must be amortized once the map is large.
//
// Sweeping on every failure hands an attacker a quadratic cost: one failed request from
// each of many source addresses, and every failure scans the whole map. The sweep is
// therefore rate-limited by time, not only by size.
func TestGcIsAmortizedOnceTheMapIsLarge(t *testing.T) {
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
