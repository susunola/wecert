package acme

import (
	"maps"
	"sort"
	"time"

	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/state"
)

// rateBucketAdapter lets the pure arithmetic in internal/ratelimit persist through the state
// store without that package depending on it.
//
// The two structs are field-for-field identical on purpose: this is a boundary translation,
// not a second model. Named field literals cannot enforce that -- a new field on either side
// would still compile here and be silently dropped -- so ratelimit_adapter_test.go pins the two
// field sets with reflect instead.
type rateBucketAdapter struct{ store *state.Store }

func (a rateBucketAdapter) GetRateBucket(limitName, scopeID string) (*ratelimit.BucketRecord, error) {
	rec, err := a.store.GetRateBucket(limitName, scopeID)
	if err != nil {
		return nil, err
	}
	return &ratelimit.BucketRecord{
		LimitName:   rec.LimitName,
		ScopeID:     rec.ScopeID,
		Tokens:      rec.Tokens,
		ObservedAt:  rec.ObservedAt,
		ResetAt:     rec.ResetAt,
		ResetReason: rec.ResetReason,
	}, nil
}

// UpdateRateBucket translates the boundary type and applies fn inside the store's own lock, so a
// spend cannot be lost to a concurrent pass spending on the same account-scoped bucket.
func (a rateBucketAdapter) UpdateRateBucket(limitName, scopeID string, fn func(*ratelimit.BucketRecord) error) error {
	return a.store.UpdateRateBucket(limitName, scopeID, func(rec *state.RateBucket) error {
		out := &ratelimit.BucketRecord{
			LimitName:   rec.LimitName,
			ScopeID:     rec.ScopeID,
			Tokens:      rec.Tokens,
			ObservedAt:  rec.ObservedAt,
			ResetAt:     rec.ResetAt,
			ResetReason: rec.ResetReason,
		}
		if err := fn(out); err != nil {
			return err
		}
		rec.Tokens = out.Tokens
		rec.ObservedAt = out.ObservedAt
		rec.ResetAt = out.ResetAt
		rec.ResetReason = out.ResetReason
		return nil
	})
}

// QuotaReport is one limit's state, for metrics, logs and diagnostics.
type QuotaReport struct {
	Limit        string
	Scope        string
	Remaining    float64
	Blocked      bool
	BlockedUntil time.Time

	// Unreadable means the stored bucket could not be read, so Remaining is NOT an answer.
	//
	// It used to be published as zero, which is the strongest possible claim ("no quota left") made
	// on the strength of a failed read: one SQLITE_BUSY made wecert_ratelimit_remaining_tokens read
	// 0 for every limit and fired the "nearly exhausted" alert until the next successful pass. The
	// revocation gauge in this same package already declines to touch itself when its read fails;
	// this is the same rule.
	Unreadable bool

	// SpentByCA means this limit's bucket is filled by the CA's own validators, not by this program
	// (see ratelimit.Limit.SpentByCA). Blocked is then the only field that means anything:
	// Remaining stays zero because a count of what this program spent against a bucket it never
	// spends against would be the limit's bare capacity, published as if it were an estimate.
	SpentByCA bool
}

// QuotaStatus reports every reportable limit for the given per-scope buckets.
//
// The map is limit family -> every scope the caller manages in that family (the registered domains
// it serves, each certificate's identifier set, every identifier). It used to be one scope per
// family, chosen as "the first certificate's first domain" by the only caller -- so for the normal
// one-certificate-per-domain layout, `wecert_ratelimit_remaining_tokens` had no series at all for
// any domain but the first, and `WecertRateLimitNearlyExhausted` could not fire for the rest.
//
// Reportable, not Spendable: the CA-spent identifier pause has no token count to publish but its
// refused deadline is exactly what an operator needs to see.
func (m *Manager) QuotaStatus(scopes map[string][]string) []QuotaReport {
	var out []QuotaReport
	for _, l := range ratelimit.Reportable() {
		if l.Scope == "account" {
			out = append(out, m.quotaReport(l, ""))
			continue
		}
		for _, scopeID := range scopes[l.Scope] {
			if scopeID == "" {
				continue
			}
			out = append(out, m.quotaReport(l, scopeID))
		}
	}
	return out
}

// quotaReport answers one (limit, scope) pair. Unreadable is NOT zero: see QuotaReport.
func (m *Manager) quotaReport(l ratelimit.Limit, scopeID string) QuotaReport {
	rep := QuotaReport{Limit: l.Name, Scope: scopeID, SpentByCA: l.SpentByCA}
	if at, _, blocked := m.quota.BlockedUntil(l, scopeID); blocked {
		rep.Blocked = true
		rep.BlockedUntil = at
	} else if l.SpentByCA {
		// No estimate, but the read still has to happen: "the bucket could not be read" must not be
		// published as "this identifier is not paused", which is the all-clear this whole path
		// exists to avoid.
		if _, ok := m.quota.Remaining(l, scopeID); !ok {
			rep.Unreadable = true
		}
	} else if left, ok := m.quota.Remaining(l, scopeID); ok {
		rep.Remaining = left
	} else {
		rep.Unreadable = true
	}
	return rep
}

// PublishQuota refreshes the rate-limit gauges.
//
// Called after a pass rather than on a timer: the numbers only change when this program
// spends something or the CA reports a deadline, and both happen inside a pass.
//
// Both vectors are rebuilt from scratch on every call, because their labels carry the *scope* and
// the scope comes from the desired state. `WithLabelValues` only ever creates: a deployment that
// renames its first domain, or drops it, leaves the retired scope's series behind at its last
// value, and nothing ever revisits them. The visible consequence is permanent, not cosmetic --
// `WecertRateLimitNearlyExhausted` compares that frozen number against 5 and keeps firing for a
// domain this program no longer manages, which is the same "stale series is a permanent false
// alarm" failure the probe metrics had.
//
// The cost is that a scrape landing in the window between Reset and the Sets below sees no series
// at all. Absent reads as "not published", which is the honest answer for a scope that is no
// longer in the desired state, and it is the same trade the blocked vector already made.
func (m *Manager) PublishQuota(scopes map[string][]string) {
	// The per-identifier family comes from the STORE, not from the desired state.
	//
	// It is the only unbounded family: "every SAN of every certificate" grows with the fleet, while
	// the buckets that can actually be exhausted grow with what has been attempted. A name nobody has
	// validated has a full budget, so a series for it carries no information an operator can act on --
	// and the cost of publishing one per name is real: at 500 certificates of 20 names the round-11
	// scale work measured 17,052 series, a 1.67 MB scrape and 22,002 SQL statements in an ordinary
	// scheduled pass, all dominated by identifiers that had never been spent against.
	//
	// BOTH per-identifier limits are listed. The failure budget is spent here when an authorization
	// comes back invalid; the pause is filled by the CA's validators, so a pause leaves a bucket in
	// the other family -- and a paused identifier whose failures this program never happened to
	// observe would otherwise be blocked in the store and absent from the scrape, which reads as
	// healthy to anyone watching the metric.
	scopes = maps.Clone(scopes)
	if ids, err := m.spentIdentifiers(); err != nil {
		// Not fatal and not silent: publishing the desired-state list is the expensive-but-complete
		// answer, and the warning says the series may be larger than it needs to be.
		m.log.Warn("cannot list the identifiers that have been spent against; publishing a quota "+
			"series for every identifier in the desired state instead (more series than needed, "+
			"and no wrong values)", "err", err)
	} else {
		scopes[ratelimit.AuthzFailuresPerIdentifier.Scope] = ids
	}

	metrics.RateLimitRemaining.Reset()
	metrics.RateLimitBlocked.Reset()
	for _, rep := range m.QuotaStatus(scopes) {
		if rep.Unreadable {
			// No series rather than a zero: absent reads as "not published", which is the honest
			// answer for a bucket whose stored value could not be read.
			continue
		}
		if !rep.SpentByCA {
			// A CA-spent bucket has no estimate to publish: see QuotaReport.SpentByCA. The blocked
			// gauge below is the one that carries it, and it is the one an operator can act on.
			metrics.RateLimitRemaining.WithLabelValues(rep.Limit, rep.Scope).Set(rep.Remaining)
		}
		if rep.Blocked {
			metrics.RateLimitBlocked.WithLabelValues(rep.Limit, rep.Scope).Set(1)
		}
	}
}

// spentIdentifiers is every identifier with a stored bucket in either per-identifier family,
// deduplicated and sorted.
//
// The two families answer the same question for the scrape ("has anything happened to this name?")
// and a name can be in either one alone: a failure this program recorded, or a pause the CA
// reported. Listing only one of them hid the other's scopes.
func (m *Manager) spentIdentifiers() ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, limitName := range []string{
		ratelimit.AuthzFailuresPerIdentifier.Name,
		ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Name,
	} {
		ids, err := m.store.ListRateBucketScopes(limitName)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}
