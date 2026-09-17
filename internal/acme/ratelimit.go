package acme

import (
	"time"

	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/state"
)

// rateBucketAdapter lets the pure arithmetic in internal/ratelimit persist through the state
// store without that package depending on it.
//
// The two structs are field-for-field identical on purpose: this is a boundary translation,
// not a second model, and if one gains a field the compiler will say so here.
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

func (a rateBucketAdapter) PutRateBucket(rec *ratelimit.BucketRecord) error {
	return a.store.PutRateBucket(&state.RateBucket{
		LimitName:   rec.LimitName,
		ScopeID:     rec.ScopeID,
		Tokens:      rec.Tokens,
		ObservedAt:  rec.ObservedAt,
		ResetAt:     rec.ResetAt,
		ResetReason: rec.ResetReason,
	})
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
}

// QuotaStatus reports every spendable limit for the given per-scope buckets.
//
// notes is the account-wide scope plus one entry per limit family whose scope the caller can
// name (the registered domains it manages, the certificate name for the order limit).
func (m *Manager) QuotaStatus(scopes map[string]string) []QuotaReport {
	var out []QuotaReport
	for _, l := range ratelimit.Spendable() {
		scopeID := ""
		if l.Scope != "account" {
			scopeID = scopes[l.Scope]
			if scopeID == "" {
				continue
			}
		}
		rep := QuotaReport{Limit: l.Name, Scope: scopeID}
		if at, _, blocked := m.quota.BlockedUntil(l, scopeID); blocked {
			rep.Blocked = true
			rep.BlockedUntil = at
		} else if left, ok := m.quota.Remaining(l, scopeID); ok {
			rep.Remaining = left
		}
		out = append(out, rep)
	}
	return out
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
func (m *Manager) PublishQuota(scopes map[string]string) {
	metrics.RateLimitRemaining.Reset()
	metrics.RateLimitBlocked.Reset()
	for _, rep := range m.QuotaStatus(scopes) {
		metrics.RateLimitRemaining.WithLabelValues(rep.Limit, rep.Scope).Set(rep.Remaining)
		if rep.Blocked {
			metrics.RateLimitBlocked.WithLabelValues(rep.Limit, rep.Scope).Set(1)
		}
	}
}
