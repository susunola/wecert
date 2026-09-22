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
//     deterministic. This is an UPPER BOUND on what is left: other accounts sharing a domain, and
//     any operator activity outside this program, consume from the same bucket and are invisible
//     here, so the real remainder can only be smaller.
//
// The bound direction is stated because it is the whole safety argument, and this comment used to
// state it backwards ("a lower bound ... at least this much is left"). "At most this much is left"
// answers "can I safely do this now" with the wrong answer if it is read as "at least"; the alert
// file and the metric table in README.reference.md both have it right. The package name says
// estimate, not quota.
package ratelimit

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
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

	// SpentByCA marks a bucket this program does not spend against: the CA's own validators fill
	// it. Nothing here can observe that spend, so a token count computed from our (always zero)
	// local spend would be the bare capacity wearing the estimate's clothes -- see QuotaReport,
	// which publishes Blocked but never Remaining for such a limit.
	SpentByCA bool
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

	// ConsecutiveAuthzFailuresPerIdentifier is the FIFTH published limit, and the only one whose
	// bucket the CA's own validators fill rather than this program.
	//
	// "Consecutive Authorization Failures per Identifier per Account"
	// (https://letsencrypt.org/docs/rate-limits/, read 2026-09-18): up to 1,152 consecutive
	// authorization failures per identifier are allowed; the ability to incur them refills at 1 per
	// identifier per DAY and resets to zero when an authorization for that identifier validates.
	// Crossing it makes Boulder PAUSE (account, identifier): every new order containing that
	// identifier is refused with a link to the CA's self-service portal, and the docs are explicit
	// that the portal is how issuance is unpaused for it. The pause is a row in Boulder's database
	// with no expiry of its own (sa/sa.go, `paused` / `unpausedAt IS NULL`), which is what makes it
	// a different kind of state from a token bucket: waiting does not clear it, and the CA never
	// names an instant at which it will.
	//
	// So the numbers below are used for two things, and neither is a spend estimate: Capacity and
	// Refill document the published model, and Refill is the FLOOR a refusal against this limit is
	// booked with when the CA names no instant (see the acme package's noteNewOrderRefusal). It is
	// a floor in the sense of "the shortest wait the published model can possibly justify", not a
	// measurement of any particular pause and not a promise that ordering will succeed then.
	ConsecutiveAuthzFailuresPerIdentifier = Limit{
		Name: "consecutive-authz-failures-per-identifier", Scope: "identifier",
		Capacity: 1152, Refill: 24 * time.Hour,
		Source: "letsencrypt.org/docs/rate-limits: 1152 consecutive authorization failures per identifier, " +
			"refills 1 per identifier per day, reset to zero by a successful validation; crossing it pauses the identifier",
		SpentByCA: true,
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

// Reportable returns every limit whose CA-reported state belongs in the quota report and its
// metrics: the spendable four, plus the CA-spent identifier pause.
//
// The pause is reportable because a paused identifier is the one state an operator has to ACT on
// (it is cleared in the CA's portal, not by waiting), while it is not spendable because nothing
// here spends against it. Reporting it with the spendable four is what makes
// wecert_ratelimit_blocked carry it; see QuotaReport for why it never carries a token count.
func Reportable() []Limit {
	return append(Spendable(), ConsecutiveAuthzFailuresPerIdentifier)
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
// "Full" is the CAPACITY, not however much the idle interval would have produced. A bucket left
// alone for two refill periods refills to twice its capacity if nothing caps it, and every token
// above the capacity is invisible (Remaining clamps what it reports) while still being there to
// spend: the stored count then reads "full" for many spends longer than the CA would allow, which
// is exactly the direction this estimate must never be wrong in. TestSpendingAnIdleBucketStores-
// NoMoreThanCapacity pins it; Remaining's clamp alone cannot, because the surplus lives in the
// snapshot.
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
	tokens := math.Min(level(s, l, now), l.Capacity) - cost
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
	// The instant is a PREFIX of what follows it, not the whole of it.
	//
	// Boulder formats "retry after 2006-01-02 15:04:05 MST" and then appends the documentation
	// link: a real refusal reads
	//
	//	too many new orders recently, retry after 2026-09-18 12:34:56 UTC: see
	//	https://letsencrypt.org/docs/rate-limits/#new-orders-per-account
	//
	// Requiring the message to end at the instant made every genuine refusal return false, so no
	// deadline was ever recorded and the WecertRateLimitBlocked alert was unreachable -- the one
	// signal that says the whole account has to wait. The test used a fabricated message with no
	// suffix, which is why the suite stayed green.
	if j := indexOf(rest, ": see "); j >= 0 {
		rest = rest[:j]
	}
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

// ParseRetryAfterHeader parses an HTTP Retry-After header value.
//
// RFC 9110 section 10.2.3 allows two forms: a delay in seconds, or an HTTP-date. It is a different
// syntax from the free text Boulder puts in the error MESSAGE (see ParseRetryAfter), and it is the
// authoritative field: a CA may send the header without repeating the instant in the message, and
// lego exposes it on its typed error. Reading only the message meant such a refusal recorded no
// deadline at all, so the pass retried inside the window the CA had just named.
func ParseRetryAfterHeader(value string) (time.Time, bool) {
	v := strings.TrimSpace(value)
	if v == "" {
		return time.Time{}, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return time.Time{}, false
		}
		// time.Duration is int64 nanoseconds, so a delay beyond ~292 years overflows the
		// multiplication and wraps to a NEGATIVE duration -- "retry after 1e13 seconds" would
		// report a deadline in the past, i.e. no deadline at all, for the one response that
		// is telling us to wait longest. A miss is reported rather than guessed, same as an
		// unparseable value.
		if int64(secs) > math.MaxInt64/int64(time.Second) {
			return time.Time{}, false
		}
		return time.Now().Add(time.Duration(secs) * time.Second).UTC(), true
	}
	if t, err := http.ParseTime(v); err == nil && !t.IsZero() {
		return t.UTC(), true
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
