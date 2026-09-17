// Package ratelimit estimates how much certificate-issuance quota is left.
//
// Why this exists. Let's Encrypt publishes its limits but offers NO endpoint to query the
// remaining allowance -- the official documentation defines the limits, their token-bucket
// refill rates, and a form for requesting an override, and nothing else. "How much is left"
// is therefore not answerable by asking, and the operator's only signal was an error after
// the quota was already gone.
//
// It is answerable by modelling, because every event that consumes quota goes through this
// program. Two sources, in order of authority:
//
//  1. The CA itself. A rate-limited request comes back with a message of a fixed documented
//     shape -- "too many new orders ... retry after 1970-01-01 00:18:15 UTC" -- and when
//     several limits are exceeded at once the CA reports the one that resets FURTHEST in the
//     future. That is an authoritative reset instant, better than any estimate, and it is
//     stored as an override (see Deadline).
//  2. Local accounting. Limits are token buckets: capacity N refilling at a published rate.
//     Knowing what we spent and when is enough to compute what is left, because the refill is
//     deterministic. This is a LOWER BOUND: other accounts sharing a domain, and any operator
//     activity outside this program, consume from the same bucket and are invisible here.
//
// The lower bound is the honest framing and the useful one: it answers "can I safely do this
// now", and the estimate can only be wrong in the direction that makes the operator more
// careful. The package name says estimate, not quota.
package ratelimit

import (
	"fmt"
	"math"
	"time"
)

// Limit describes one published rate limit as a token bucket.
type Limit struct {
	// Name identifies the limit, e.g. "new-orders".
	Name string

	// Scope names what the bucket is per: "account", "registered-domain",
	// "exact-identifier-set". It is part of the metric label set, so the values are fixed.
	Scope string

	// Capacity is the bucket size, i.e. the most that can be spent in one burst.
	Capacity float64

	// Refill is how long one token takes to come back.
	Refill time.Duration

	// Source records where the numbers come from, so a future change to the CA's published
	// limits is traceable to the page it was read from rather than to folklore.
	Source string
}

// RefillPerSecond is the bucket's refill rate.
func (l Limit) RefillPerSecond() float64 {
	if l.Refill <= 0 {
		return 0
	}
	return 1 / l.Refill.Seconds()
}

// String renders the limit for a log line.
func (l Limit) String() string {
	return fmt.Sprintf("%s (%s): %g per %s", l.Name, l.Scope, l.Capacity, l.Refill)
}

// The limits this program can spend. Values and refill rates are from
// https://letsencrypt.org/docs/rate-limits/ (read 2026-09-16); the rates are the page's own
// "refills at a rate of ..." figures, converted to a per-token interval.
var (
	// NewOrdersPerAccount bounds order creation. 300 per 3 hours is 10800s/300 = 36s.
	NewOrdersPerAccount = Limit{
		Name: "new-orders", Scope: "account",
		Capacity: 300, Refill: 36 * time.Second,
		Source: "letsencrypt.org/docs/rate-limits: 300 new orders per account per 3h, refills 1 per 36s",
	}

	// CertsPerRegisteredDomain is GLOBAL across all accounts, so the local estimate is
	// weaker for it than for the others -- another account can spend it without this program
	// seeing anything. 50 per 7 days is 604800s/50 = 12096s = 202 minutes.
	CertsPerRegisteredDomain = Limit{
		Name: "certs-per-registered-domain", Scope: "registered-domain",
		Capacity: 50, Refill: 202 * time.Minute,
		Source: "letsencrypt.org/docs/rate-limits: 50 certs per registered domain per 7d (global), refills 1 per 202m",
	}

	// CertsPerExactIdentifierSet is also global, and has NO override path -- the page says
	// outright that overrides are not offered for it. 5 per 7 days, refilling 1 per 34h.
	//
	// Note that 34h is not 7d/5 = 33.6h: the published interval refills more slowly than the
	// window implies, so this bucket is slightly more conservative than the limit itself.
	// That is the safe direction for an estimate and it is also what the CA documents, so the
	// published figure is used verbatim rather than "corrected".
	CertsPerExactIdentifierSet = Limit{
		Name: "certs-per-exact-identifier-set", Scope: "exact-identifier-set",
		Capacity: 5, Refill: 34 * time.Hour,
		Source: "letsencrypt.org/docs/rate-limits: 5 certs per exact set per 7d, refills 1 per 34h, no overrides",
	}

	// AuthzFailuresPerIdentifier is what a DNS-01 misconfiguration spends. 5 per hour is
	// 3600s/5 = 720s = 12 minutes.
	AuthzFailuresPerIdentifier = Limit{
		Name: "authz-failures-per-identifier", Scope: "identifier",
		Capacity: 5, Refill: 12 * time.Minute,
		Source: "letsencrypt.org/docs/rate-limits: 5 authorization failures per identifier per hour, refills 1 per 12m",
	}
)

// Spendable returns every limit this program consumes.
func Spendable() []Limit {
	return []Limit{
		NewOrdersPerAccount,
		CertsPerRegisteredDomain,
		CertsPerExactIdentifierSet,
		AuthzFailuresPerIdentifier,
	}
}

// Snapshot is one bucket's state at a known instant.
//
// Tokens is what was left immediately after the last event, and At is when that was. Together
// they are enough to reconstruct the bucket at any later time, which is why the state store
// keeps this and not an event log: the bucket model is the memory.
type Snapshot struct {
	Tokens float64
	At     time.Time
}

// Remaining computes how many tokens are available at now.
//
// A zero At means nothing has been spent yet, so the bucket is full. That is the honest answer
// for "this program has never done this", not a guess.
// level is the token count before the public clamps: negative means the bucket is in debt.
//
// Remaining and Spend share it deliberately. Remaining clamps a debt to zero for callers asking
// "how much may I spend right now"; Spend must subtract from the UNCLAMPED value, because
// subtracting from a clamped zero forgives whatever debt lies below it -- a bucket at -5 that is
// spent again would land at -1 instead of -6, so its next token would arrive several refill
// intervals early, which is the opposite of what this package promises.
func level(s Snapshot, l Limit, now time.Time) float64 {
	if l.Capacity <= 0 {
		return 0
	}
	if s.At.IsZero() {
		return l.Capacity
	}
	tokens := s.Tokens
	// A limit with no refill interval has no meaningful rate, and the arithmetic below divides
	// by it: `elapsed / 0` panicked with "integer divide by zero". This is unreachable through
	// today's callers -- every Limit comes from the table in this file, whose intervals are
	// published constants -- but Remaining takes a Limit, so it is reachable through the API,
	// and "no caller does that yet" is the assumption that stops being true when one does.
	//
	// Treating it as a bucket that never refills is the conservative reading: fewer tokens
	// available means less issuance, never more.
	if l.Refill <= 0 {
		return s.Tokens
	}
	if now.After(s.At) {
		// Computed as whole refills plus a fraction of the next one, rather than as
		// elapsed x (1/Refill). The inverse form rounds: 34h as a float, multiplied back by
		// 34h, lands on 9.7e-17 instead of 0 and 1.0000000000000002 instead of 1. Those
		// crumbs are invisible in a metric but they make an "is it exactly full / exactly
		// empty" comparison impossible, and this package is read by tests and by operators
		// deciding whether one more issuance fits.
		elapsed := now.Sub(s.At)
		whole := float64(elapsed / l.Refill)
		frac := float64(elapsed%l.Refill) / float64(l.Refill)
		tokens += whole + frac
	}
	return tokens
}

// Remaining reports how many tokens are available now, never less than zero.
func Remaining(s Snapshot, l Limit, now time.Time) float64 {
	tokens := level(s, l, now)
	// A clock that moved backwards must not create tokens, and a bucket in debt cannot be spent
	// from: both read as "nothing available".
	if tokens > l.Capacity {
		tokens = l.Capacity
	}
	if tokens < 0 {
		tokens = 0
	}
	return tokens
}

// Spend records that cost tokens were consumed at now, returning the new snapshot.
//
// The subtraction happens after refilling to now, so a bucket that has been idle long enough
// is full again before the withdrawal -- which is what makes "50 per 7 days, 1 back every 202
// minutes" behave as the CA does rather than as a naive counter would.
//
// A spend that exceeds what is available drives the bucket negative on purpose: the negative
// value is what makes Remaining report 0 AND tells the next refill how much debt to work off,
// so an over-spend is not silently forgiven. The CA would have rejected that request, so a
// negative bucket is itself a signal worth keeping.
func Spend(s Snapshot, l Limit, cost float64, now time.Time) Snapshot {
	// A negative cost is not a credit, and treating it as one is how a caller's sign error
	// silently hands back quota: `tokens - (-c)` is `tokens + c`, so a bug in the caller would
	// *increase* the reported allowance. The API records consumption, so the only defensible
	// reading of a negative cost is "nothing was consumed".
	if cost < 0 {
		cost = 0
	}
	// The anchor only moves forward.
	//
	// Remaining already refuses to credit an interval that has not passed, but the snapshot this
	// returns would still move its anchor back to `now`. If the clock steps backwards (NTP, a VM
	// restored from a snapshot, a manual change), s.Tokens has already been credited up to s.At,
	// and storing At=now makes the interval [now, s.At] creditable a second time -- free tokens,
	// on the limits this estimate exists to stay under. An interval that has been credited can
	// never be credited again if the anchor never goes backwards.
	if now.Before(s.At) {
		now = s.At
	}
	tokens := level(s, l, now) - cost
	// Clamp the debt. Without a floor, one catastrophic burst (or a clock jump) could leave a
	// bucket so negative that it takes longer than the window to recover and the estimate
	// stays pinned at zero long after the CA would have allowed the request again.
	if tokens < -l.Capacity {
		tokens = -l.Capacity
	}
	return Snapshot{Tokens: tokens, At: now}
}

// Deadline is an authoritative "this limit will not accept a request until" instant, as
// reported by the CA.
//
// It exists because the estimate above cannot see other accounts, while the CA's own answer
// is exact for the bucket that was actually exhausted. When both are known, the later instant
// wins: being told to wait is stronger evidence than arithmetic that says otherwise.
type Deadline struct {
	At     time.Time
	Reason string
}

// ParseRetryAfter extracts the reset instant from a rate-limit error message.
//
// The documented format is fixed:
//
//	too many new registrations (10) from this IP address in the last 3h0m0s,
//	retry after 1970-01-01 00:18:15 UTC.
//
// Matching a message is normally the wrong way to classify an error, and this package does it
// only because there is no alternative: the ACME protocol carries a Retry-After HEADER on
// rate-limit responses, but lego surfaces errors as strings without the response, so the
// instant reaches us only inside the message. The parse is therefore deliberately strict
// (exact prefix, exact "2006-01-02 15:04:05 MST" layout) and a miss is reported rather than
// guessed -- a wrong deadline would either block issuance that is allowed or invite requests
// that are not.
//
// The two layouts cover the same instant written with and without a fractional second, and
// "UTC" as Go's reference layout writes it.
func ParseRetryAfter(msg string) (time.Time, bool) {
	const marker = "retry after "
	i := indexOf(msg, marker)
	if i < 0 {
		return time.Time{}, false
	}
	rest := msg[i+len(marker):]
	// Trim the trailing sentence punctuation the message may carry.
	rest = trimTrailing(rest)

	for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05.999999999 MST"} {
		if t, err := time.Parse(layout, rest); err == nil {
			if t.IsZero() {
				// "0001-01-01 00:00:00 UTC" parses successfully and is the zero time, which is
				// exactly the value callers use for "no deadline". Reporting it as a successful
				// parse would hand back a deadline that means "not blocked" while looking like a
				// real one -- the failure mode this whole function exists to avoid. The fuzzer
				// found it; a human reading the documented format would not have.
				return time.Time{}, false
			}
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// indexOf is strings.Index, kept local so the parse is self-contained and testable.
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// trimTrailing drops sentence-ending punctuation and whitespace from the parsed tail.
func trimTrailing(s string) string {
	end := len(s)
	for end > 0 {
		switch s[end-1] {
		case '.', ',', ';', '\n', '\r', ' ', '\t':
			end--
			continue
		}
		break
	}
	return s[:end]
}

// WorstCaseBlockedBy reports the latest deadline among those still in the future, which is
// what a caller should wait for. Multiple limits can be exceeded at once, and the CA reports
// the furthest-resetting one; when several deadlines have been collected individually, the
// same rule applies.
func WorstCaseBlockedBy(deadlines []Deadline, now time.Time) (Deadline, bool) {
	var worst Deadline
	found := false
	for _, d := range deadlines {
		if d.At.IsZero() || !now.Before(d.At) {
			continue
		}
		if !found || d.At.After(worst.At) {
			worst, found = d, true
		}
	}
	return worst, found
}

// Describe renders a remaining-token count for an operator, clamping display at zero so a
// negative bucket does not read as a negative allowance.
func Describe(l Limit, remaining float64) string {
	return fmt.Sprintf("%s: %.0f of %.0f left (1 back every %s)",
		l.Name, math.Max(0, remaining), l.Capacity, l.Refill)
}
