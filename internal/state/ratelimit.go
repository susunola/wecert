package state

import (
	"database/sql"
	"errors"
	"fmt"
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

// PutRateBucket writes one bucket.
//
// The reset fields are only overwritten when the new value is non-zero, so recording a spend
// cannot erase a CA-reported deadline that is still in force -- the two facts have different
// lifetimes and the deadline is the stronger one.
func (s *Store) PutRateBucket(b *RateBucket) error {
	if b == nil {
		return nil
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
