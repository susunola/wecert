package state

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// IdentifierFailure is the authorization failure ledger for one identifier.
type IdentifierFailure struct {
	CertName     string
	Identifier   string
	Failures     int
	LastError    string
	LastFailedAt time.Time
}

// Fallback records the fact that "this certificate is serving a certificate that is
// missing some names".
//
// It has to be visible: fallback is a trade-off between "partially available" and
// "completely down", and the result of that trade-off cannot live only in logs --
// logs get rotated away.
type Fallback struct {
	CertName string
	Dropped  []string
	Since    time.Time
	Reason   string
}

// RecordIdentifierFailure increments the failure count for one identifier.
//
// This ledger is the only input to "pre-expiry fallback": without it, fallback could
// only drop names at random, and dropping at random sacrifices names that were fine.
func (s *Store) RecordIdentifierFailure(certName, identifier, errMsg string, now time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO identifier_failures (cert_name, identifier, failures, last_error, last_failed_at)
		VALUES (?, ?, 1, ?, ?)
		ON CONFLICT(cert_name, identifier) DO UPDATE SET
			failures       = failures + 1,
			last_error     = excluded.last_error,
			last_failed_at = excluded.last_failed_at`,
		certName, identifier, truncate(errMsg, 512), now.Unix())
	if err != nil {
		return fmt.Errorf("record identifier failure %s/%s: %w", certName, identifier, err)
	}
	return nil
}

// ListIdentifierFailures returns the failure records for every identifier under one
// certificate, sorted by identifier so identical input yields identical output.
func (s *Store) ListIdentifierFailures(certName string) ([]*IdentifierFailure, error) {
	rows, err := s.db.Query(`
		SELECT cert_name, identifier, failures, last_error, last_failed_at
		FROM identifier_failures WHERE cert_name = ? ORDER BY identifier`, certName)
	if err != nil {
		return nil, fmt.Errorf("list identifier failures for %s: %w", certName, err)
	}
	defer rows.Close()

	var out []*IdentifierFailure
	for rows.Next() {
		f := &IdentifierFailure{}
		var lastFailedAt int64
		if err := rows.Scan(&f.CertName, &f.Identifier, &f.Failures, &f.LastError, &lastFailedAt); err != nil {
			return nil, fmt.Errorf("scan identifier failure: %w", err)
		}
		f.LastFailedAt = fromUnix(lastFailedAt)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ClearIdentifierFailures clears every identifier failure record for a certificate.
//
// Called when the full set issues successfully: the ledger means "who is broken
// lately", not "who has ever been broken". Keeping it around would let a long-fixed
// fault keep a name dropped out forever.
func (s *Store) ClearIdentifierFailures(certName string) error {
	if _, err := s.db.Exec(`DELETE FROM identifier_failures WHERE cert_name = ?`, certName); err != nil {
		return fmt.Errorf("clear identifier failures for %s: %w", certName, err)
	}
	return nil
}

// PruneIdentifierFailures drops records that have not failed again for longer than age.
//
// This lets old ledger entries expire on their own instead of waiting for a successful
// full-set issuance -- those identifiers are no longer in the certificate, so their
// authorizations will never be attempted again and there will never be a "success" that
// clears them.
func (s *Store) PruneIdentifierFailures(certName string, now time.Time, age time.Duration) error {
	cutoff := now.Add(-age)
	if _, err := s.db.Exec(`
		DELETE FROM identifier_failures WHERE cert_name = ? AND last_failed_at < ?`,
		certName, cutoff.Unix()); err != nil {
		return fmt.Errorf("prune identifier failures for %s: %w", certName, err)
	}
	return nil
}

// PutFallback records fallback state.
func (s *Store) PutFallback(f *Fallback) error {
	dropped := append([]string(nil), f.Dropped...)
	sort.Strings(dropped)

	_, err := s.db.Exec(`
		INSERT INTO cert_fallback (cert_name, dropped, since, reason)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(cert_name) DO UPDATE SET
			dropped = excluded.dropped,
			since   = excluded.since,
			reason  = excluded.reason`,
		f.CertName, strings.Join(dropped, ","), f.Since.Unix(), truncate(f.Reason, 512))
	if err != nil {
		return fmt.Errorf("put fallback for %s: %w", f.CertName, err)
	}
	return nil
}

// GetFallback reads fallback state; returns (nil, nil) when there is no record.
func (s *Store) GetFallback(certName string) (*Fallback, error) {
	row := s.db.QueryRow(`
		SELECT cert_name, dropped, since, reason FROM cert_fallback WHERE cert_name = ?`, certName)

	f := &Fallback{}
	var dropped string
	var since int64
	err := row.Scan(&f.CertName, &dropped, &since, &f.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get fallback for %s: %w", certName, err)
	}

	for _, d := range strings.Split(dropped, ",") {
		if d = strings.TrimSpace(d); d != "" {
			f.Dropped = append(f.Dropped, d)
		}
	}
	f.Since = fromUnix(since)
	return f, nil
}

// ClearFallback clears fallback state. Called when the full set issues successfully.
func (s *Store) ClearFallback(certName string) error {
	if _, err := s.db.Exec(`DELETE FROM cert_fallback WHERE cert_name = ?`, certName); err != nil {
		return fmt.Errorf("clear fallback for %s: %w", certName, err)
	}
	return nil
}

// truncate cuts off potentially very long error text.
//
// What is stored here is human-facing diagnostic information, not a full log -- and a
// repeatedly failing ACME error can carry an entire response body, so not truncating
// would bloat the state database for no reason.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
