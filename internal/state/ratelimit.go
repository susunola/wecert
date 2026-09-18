package state

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// RateBucket is one rate-limit bucket's last known state.
//
// Tokens/ObservedAt are the local estimate: what was left immediately after the last event
// this program recorded, and when. ResetAt is different in kind -- it is an instant the CA
// itself reported when it refused a request, which is authoritative precisely because the
// local estimate cannot see other accounts spending the same global bucket.
type RateBucket struct {
	LimitName string
	ScopeID   string

	Tokens     float64
	ObservedAt time.Time

	ResetAt     time.Time
	ResetReason string
}

// GetRateBucket reads one bucket. A missing row returns a zero value and no error: "never
// recorded" is the normal state of a limit this program has not spent yet, and every caller
// would otherwise have to special-case it.
func (s *Store) GetRateBucket(limitName, scopeID string) (*RateBucket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		tokens     float64
		observedAt int64
		resetAt    int64
		reason     string
	)
	err := s.db.QueryRow(`
		SELECT tokens, observed_at, reset_at, reset_reason
		FROM rate_buckets WHERE limit_name = ? AND scope_id = ?`,
		limitName, scopeID).Scan(&tokens, &observedAt, &resetAt, &reason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &RateBucket{LimitName: limitName, ScopeID: scopeID}, nil
		}
		return nil, fmt.Errorf("read rate bucket %s/%s: %w", limitName, scopeID, err)
	}

	return &RateBucket{
		LimitName:   limitName,
		ScopeID:     scopeID,
		Tokens:      tokens,
		ObservedAt:  fromUnix(observedAt),
		ResetAt:     fromUnix(resetAt),
		ResetReason: reason,
	}, nil
}

// UpdateRateBucket reads one bucket, applies fn, and writes the result back as a single
// operation under the store's mutex.
//
// fn runs while the store's mutex is held, so it must not call back into the Store: s.mu is a
// plain sync.Mutex, not a reentrant one, and a callback that reads or writes through the same Store
// would deadlock rather than make progress. Every current caller is pure arithmetic on the record
// it is handed; that is the contract, not an accident.
//
// The read and the write have to be one operation, for the same reason UpdateCert exists: the
// mutex covers one statement, not a Get...Put pair, so two concurrent callers both read the same
// token count and the second write silently discards the first caller's spend. That is not a
// theoretical race here -- the manager reconciles certificates concurrently (one goroutine per
// certificate, capped at maxConcurrentStarts) and every one of them spends on the SAME
// account-scoped bucket, so the local estimate drifts optimistic exactly when the fleet is busy.
// The estimate is what keeps this program under the CA's limits, and the limit with no override
// path is the one worth being pessimistic about.
func (s *Store) UpdateRateBucket(limitName, scopeID string, fn func(*RateBucket) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		tokens     float64
		observedAt int64
		resetAt    int64
		reason     string
	)
	err := s.db.QueryRow(`
		SELECT tokens, observed_at, reset_at, reset_reason
		FROM rate_buckets WHERE limit_name = ? AND scope_id = ?`,
		limitName, scopeID).Scan(&tokens, &observedAt, &resetAt, &reason)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read rate bucket %s/%s: %w", limitName, scopeID, err)
	}

	b := &RateBucket{
		LimitName:   limitName,
		ScopeID:     scopeID,
		Tokens:      tokens,
		ObservedAt:  fromUnix(observedAt),
		ResetAt:     fromUnix(resetAt),
		ResetReason: reason,
	}
	if err := fn(b); err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT INTO rate_buckets (limit_name, scope_id, tokens, observed_at, reset_at, reset_reason)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(limit_name, scope_id) DO UPDATE SET
			tokens      = excluded.tokens,
			observed_at = excluded.observed_at,
			reset_at    = CASE WHEN excluded.reset_at != 0 THEN excluded.reset_at ELSE rate_buckets.reset_at END,
			reset_reason = CASE WHEN excluded.reset_at != 0 THEN excluded.reset_reason ELSE rate_buckets.reset_reason END`,
		b.LimitName, b.ScopeID, b.Tokens, toUnix(b.ObservedAt), toUnix(b.ResetAt), b.ResetReason)
	if err != nil {
		return fmt.Errorf("write rate bucket %s/%s: %w", limitName, scopeID, err)
	}
	return nil
}

// ListRateBucketScopes returns the scope IDs this store has a bucket row for, sorted.
//
// It exists for the per-identifier quota series. Those are the one unbounded family: the caller
// derives them from the desired state, so a deployment with 500 certificates of 20 names each asked
// for 10,000 series (and 10,000 bucket reads) every pass -- measured at 17,052 series and a 1.6 MB
// scrape in the round-11 scale work. An identifier nobody has ever attempted has nothing to report:
// its budget is untouched, so the only value the series could carry is the limit's capacity. What
// the operator needs is the identifiers this program has actually spent against -- the ones that can
// be exhausted -- and those are exactly the rows here.
func (s *Store) ListRateBucketScopes(limitName string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT scope_id FROM rate_buckets WHERE limit_name = ?`, limitName)
	if err != nil {
		return nil, fmt.Errorf("list rate buckets for %s: %w", limitName, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var scope string
		if err := rows.Scan(&scope); err != nil {
			return nil, fmt.Errorf("scan rate bucket scope: %w", err)
		}
		out = append(out, scope)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read rate bucket scopes: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

// PutRateBucket writes one bucket.
//
// The reset fields are only overwritten when the new value is non-zero, so recording a spend
// cannot erase a CA-reported deadline that is still in force -- the two facts have different
// lifetimes and the deadline is the stronger one.
//
// A nil bucket is an error, matching PutAuthorization: silently accepting it made a caller's
// bug (a record that was never built) indistinguishable from a write that landed.
func (s *Store) PutRateBucket(b *RateBucket) error {
	if b == nil {
		return fmt.Errorf("nil rate bucket")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO rate_buckets (limit_name, scope_id, tokens, observed_at, reset_at, reset_reason)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(limit_name, scope_id) DO UPDATE SET
			tokens      = excluded.tokens,
			observed_at = excluded.observed_at,
			reset_at    = CASE WHEN excluded.reset_at != 0 THEN excluded.reset_at ELSE rate_buckets.reset_at END,
			reset_reason = CASE WHEN excluded.reset_at != 0 THEN excluded.reset_reason ELSE rate_buckets.reset_reason END`,
		b.LimitName, b.ScopeID, b.Tokens, toUnix(b.ObservedAt), toUnix(b.ResetAt), b.ResetReason)
	if err != nil {
		return fmt.Errorf("write rate bucket %s/%s: %w", b.LimitName, b.ScopeID, err)
	}
	return nil
}
