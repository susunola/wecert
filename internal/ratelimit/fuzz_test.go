package ratelimit

import (
	"math"
	"testing"
	"time"
)

// The invariants this package promises, checked on every input a fuzzer can build.
//
// These are properties, not examples: the seeds below are ordinary, and the fuzzer's job is to
// find the input nobody would have written down. That is the point of doing this instead of
// another round of reading — the failure modes here are all "some combination of a clock, a
// bucket and a cost that no one enumerated".

// FuzzRemainingStaysWithinItsBucket checks the bounds and the no-minting rule.
func FuzzRemainingStaysWithinItsBucket(f *testing.F) {
	base := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	// Seeds: ordinary states, plus the ones that look suspicious to a reader.
	f.Add(int64(0), 0.0, int64(0), 300.0, int64(36*time.Second), int64(0))
	f.Add(base.UnixNano(), 150.0, int64(time.Hour), 300.0, int64(36*time.Second), int64(time.Hour))
	f.Add(base.UnixNano(), 0.0, int64(-time.Hour), 5.0, int64(34*time.Hour), int64(-time.Hour))
	f.Add(base.UnixNano(), 5.0, int64(0), 5.0, int64(34*time.Hour), int64(0))
	f.Add(int64(1), 1.0, int64(1), 1.0, int64(1), int64(1))

	f.Fuzz(func(t *testing.T, atNano int64, tokens float64, elapsedNano int64,
		capacity float64, refillNano int64, nowDeltaNano int64) {

		l := Limit{Name: "fuzz", Scope: "fuzz", Capacity: capacity, Refill: time.Duration(refillNano)}
		s := Snapshot{Tokens: tokens, At: time.Unix(0, atNano)}
		now := s.At.Add(time.Duration(elapsedNano)).Add(time.Duration(nowDeltaNano))

		got := Remaining(s, l, now)

		// A non-finite bucket is never an acceptable answer: it would poison every comparison
		// downstream and, in a metric, publish NaN.
		if math.IsNaN(got) || math.IsInf(got, 0) {
			t.Fatalf("Remaining returned %v for limit %+v snapshot %+v", got, l, s)
		}
		if l.Capacity > 0 && (got < 0 || got > l.Capacity) {
			t.Fatalf("Remaining = %v outside [0, %v] for limit %+v snapshot %+v now=%v",
				got, l.Capacity, l, s, now)
		}
	})
}

// FuzzSpendNeverCreatesTokens checks that spending cannot increase what is left.
//
// The specific hazard: a clock that moved backwards must not mint tokens. Remaining guards it
// with `if now.After(s.At)`, and Spend passes the same `now` into the new snapshot, so the
// composition is what has to be checked rather than either half.
func FuzzSpendNeverCreatesTokens(f *testing.F) {
	base := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	f.Add(base.UnixNano(), 10.0, 1.0, int64(time.Minute), 300.0, int64(36*time.Second), 100)
	f.Add(base.UnixNano(), 0.0, 1.0, int64(-time.Hour), 300.0, int64(36*time.Second), 100)
	f.Add(base.UnixNano(), 300.0, 300.0, int64(0), 300.0, int64(36*time.Second), 1000)
	f.Add(base.UnixNano(), 1.0, -5.0, int64(time.Hour), 5.0, int64(34*time.Hour), 1000)

	f.Fuzz(func(t *testing.T, atNano int64, tokens, cost float64, elapsedNano int64,
		capacity float64, refillNano int64, _ int) {

		l := Limit{Name: "fuzz", Scope: "fuzz", Capacity: capacity, Refill: time.Duration(refillNano)}
		s := Snapshot{Tokens: tokens, At: time.Unix(0, atNano)}
		now := s.At.Add(time.Duration(elapsedNano))

		before := Remaining(s, l, now)
		next := Spend(s, l, cost, now)
		after := Remaining(next, l, now)

		if math.IsNaN(after) || math.IsInf(after, 0) {
			t.Fatalf("after Spend the bucket is %v: limit %+v snapshot %+v cost %v", after, l, s, cost)
		}
		// Spending a non-negative amount can never leave more than was there. (A negative cost
		// is a caller bug rather than a supported credit, so it is excluded rather than
		// asserted about.)
		if cost >= 0 && after > before+1e-9 {
			t.Fatalf("Spend increased the bucket from %v to %v (cost %v, limit %+v, snapshot %+v)",
				before, after, cost, l, s)
		}
		// And the result is bounded by the bucket, whatever the cost was.
		if l.Capacity > 0 && after > l.Capacity+1e-9 {
			t.Fatalf("Spend left %v above capacity %v", after, l.Capacity)
		}
	})
}

// FuzzLimitWithDegenerateRefill checks the arithmetic against a limit nobody would configure.
//
// Capacity and Refill come from a table today, so a zero Refill cannot be reached through the
// config -- but Remaining divides by it, and "unreachable through today's caller" is exactly the
// assumption that stops holding when a caller is added. A fuzzer is the cheap way to find out
// whether the arithmetic itself is total.
func FuzzLimitWithDegenerateRefill(f *testing.F) {
	f.Add(int64(0), 1.0, 1.0, int64(0))
	f.Add(int64(time.Hour), 1.0, 1.0, int64(-time.Second))
	f.Add(int64(time.Hour), 1.0, 1.0, int64(time.Nanosecond))

	f.Fuzz(func(t *testing.T, elapsedNano int64, tokens, capacity float64, refillNano int64) {
		l := Limit{Name: "fuzz", Capacity: capacity, Refill: time.Duration(refillNano)}
		at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
		s := Snapshot{Tokens: tokens, At: at}
		now := at.Add(time.Duration(elapsedNano))

		got := Remaining(s, l, now)
		if math.IsNaN(got) || math.IsInf(got, 0) {
			t.Fatalf("Remaining returned %v for Refill=%v Capacity=%v elapsed=%v",
				got, l.Refill, l.Capacity, time.Duration(elapsedNano))
		}
	})
}
