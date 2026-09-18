package ratelimit

import (
	"log/slog"
	"math"
	"time"
)

// bucketStore is the persistence the tracker needs. Defined here at the consumer so the
// tracker can be tested without a real database, and so ratelimit does not depend on the
// state package (which imports nothing of this one, keeping the layering one-way).
// bucketReader is what reading a limit needs.
type bucketReader interface {
	GetRateBucket(limitName, scopeID string) (*BucketRecord, error)
}

// bucketWriter is what changing a limit needs.
//
// UpdateRateBucket applies fn to the stored bucket as ONE operation. A read-modify-write through
// Get then Put loses concurrent updates -- the manager runs one goroutine per certificate and they
// all spend on the same account-scoped bucket -- which is why there is no Put here: a caller that
// wants to change a bucket has no business writing a value it read earlier.
//
// fn runs under the store's lock and must not call back into the store.
type bucketWriter interface {
	UpdateRateBucket(limitName, scopeID string, fn func(*BucketRecord) error) error
}

// bucketStore is what the tracker needs: it both reads buckets and changes them.
type bucketStore interface {
	bucketReader
	bucketWriter
}

// BucketRecord mirrors state.RateBucket.
//
// A local type rather than importing state: this package is pure arithmetic and should stay
// testable and dependency-free, while the adapter in the acme package translates. The fields
// are identical, which is the point -- it is a boundary, not a second model.
type BucketRecord struct {
	LimitName string
	ScopeID   string

	Tokens     float64
	ObservedAt time.Time

	ResetAt     time.Time
	ResetReason string
}

// Tracker answers "how much is left" for the limits this program spends.
//
// It owns the mapping from a Limit plus a scope (an account-wide limit has none, a
// per-registered-domain limit has the domain) to a persisted bucket, so callers only ever say
// "I just spent one order" or "the CA told me to wait until T".
type Tracker struct {
	store bucketStore
	log   *slog.Logger
	now   func() time.Time
}

// NewTracker builds a tracker. A nil store makes every method a no-op, so a caller that has
// no state store (a test, or a diagnostics binary) needs no special case.
func NewTracker(store bucketStore, log *slog.Logger, now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Tracker{store: store, log: log, now: now}
}

// SetNow replaces the tracker's clock, so a caller that simulates time keeps the accounting
// on the same timeline as its own decisions.
func (t *Tracker) SetNow(now func() time.Time) {
	if t == nil || now == nil {
		return
	}
	t.now = now
}

// Spend records cost tokens against a limit and scope.
//
// A nil tracker or store is a no-op rather than an error: this is accounting, and accounting
// must never be the reason a renewal fails.
func (t *Tracker) Spend(l Limit, scopeID string, cost float64) {
	if t == nil || t.store == nil {
		return
	}
	// A non-finite amount never reaches the arithmetic.
	//
	// Spend sanitises a negative cost (an over-spend, which is the realistic mistake) but not NaN
	// or +Inf, and one such value leaves Tokens non-finite for the rest of the bucket's life:
	// every comparison against NaN is false, so Remaining reports NaN forever and the debt clamp
	// never fires. No caller computes a cost today -- all four pass the literal 1 -- which is
	// exactly why the guard belongs here rather than in a comment.
	if math.IsNaN(cost) || math.IsInf(cost, 0) {
		t.log.Warn("refusing a rate-limit spend with a non-finite cost; the bucket would be "+
			"unreadable for the rest of its life", "limit", l.Name, "scope", scopeID, "cost", cost)
		return
	}
	now := t.now()
	// One operation, not Get then Put: a concurrent pass spending on the same bucket would
	// otherwise read the same token count and overwrite this spend, and the estimate is what keeps
	// the fleet under the CA's limits.
	err := t.store.UpdateRateBucket(l.Name, scopeID, func(rec *BucketRecord) error {
		snap := Snapshot{Tokens: rec.Tokens, At: rec.ObservedAt}
		next := Spend(snap, l, cost, now)
		// The deadline travels with the estimate. The real store also guards this with a
		// COALESCE, but relying on that would make the tracker's behaviour depend on which
		// implementation is behind the interface -- and a spend that silently dropped a
		// CA-reported deadline would unblock issuance the CA has already refused.
		rec.Tokens = next.Tokens
		rec.ObservedAt = next.At
		return nil
	})
	if err != nil {
		t.log.Warn("cannot record the rate-limit spend; the local quota estimate will drift",
			"limit", l.Name, "scope", scopeID, "err", err)
	}
}

// Remaining reports how many tokens a limit has left, or (0, false) when it cannot be read.
//
// The estimate is an UPPER BOUND on what is left: it counts only what this program spent, while
// "certs per registered domain" and "certs per exact set" are global across accounts, so another
// account's spend makes the true remainder smaller, never larger. A value here is therefore "at
// most this much". (The wording used to say "at least", which is the same fact read backwards --
// and the direction matters, because "at least" invites spending quota that may not be there.)
func (t *Tracker) Remaining(l Limit, scopeID string) (float64, bool) {
	if t == nil || t.store == nil {
		return 0, false
	}
	rec, err := t.store.GetRateBucket(l.Name, scopeID)
	if err != nil {
		return 0, false
	}
	if !rec.ResetAt.IsZero() && t.now().Before(rec.ResetAt) {
		// The CA refused a request and said when to try again. That instant governs: the
		// local estimate cannot see the other accounts that helped exhaust a global bucket.
		return 0, true
	}
	return Remaining(Snapshot{Tokens: rec.Tokens, At: rec.ObservedAt}, l, t.now()), true
}

// BlockedUntil reports an authoritative CA-reported deadline for a limit and scope.
func (t *Tracker) BlockedUntil(l Limit, scopeID string) (time.Time, string, bool) {
	if t == nil || t.store == nil {
		return time.Time{}, "", false
	}
	rec, err := t.store.GetRateBucket(l.Name, scopeID)
	if err != nil || rec.ResetAt.IsZero() {
		return time.Time{}, "", false
	}
	if !t.now().Before(rec.ResetAt) {
		return time.Time{}, "", false
	}
	return rec.ResetAt, rec.ResetReason, true
}

// NoteRetryAfter records an authoritative deadline parsed from a CA error message.
//
// It is stored alongside the estimate rather than replacing it: the estimate tells the
// operator how much is left, the deadline tells them when the CA will listen again, and the
// second is the one to act on because it accounts for every other spend the local estimate
// cannot see.
func (t *Tracker) NoteRetryAfter(l Limit, scopeID, errMsg string) (time.Time, bool) {
	at, ok := ParseRetryAfter(errMsg)
	if !ok {
		return time.Time{}, false
	}
	return t.NoteDeadline(l, scopeID, at, "retry after")
}

// NoteDeadline records an authoritative deadline that was read from somewhere other than the
// error's prose -- in practice the 429 Retry-After HEADER, which lego exposes on its typed error.
//
// The field is the protocol's own answer and the prose is commentary, so a CA may send the header
// alone. Parsing only the message meant such a refusal recorded no deadline at all: the metric
// stayed optimistic and the pass retried inside the window the CA had just named.
func (t *Tracker) NoteDeadline(l Limit, scopeID string, at time.Time, source string) (time.Time, bool) {
	if t == nil || t.store == nil || at.IsZero() {
		return time.Time{}, false
	}
	if err := t.store.UpdateRateBucket(l.Name, scopeID, func(rec *BucketRecord) error {
		rec.ResetAt = at
		rec.ResetReason = l.Name
		return nil
	}); err != nil {
		t.log.Warn("cannot record the CA-reported rate-limit deadline",
			"limit", l.Name, "scope", scopeID, "until", at, "source", source, "err", err)
		return time.Time{}, false
	}
	t.log.Error("the CA refused a request against a documented rate limit; no request against "+
		"this limit will succeed before the reported instant",
		"limit", l.Name, "scope", scopeID, "until", at, "source", source)
	return at, true
}
