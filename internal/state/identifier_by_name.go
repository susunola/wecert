package state

import (
	"fmt"
)

// ListIdentifierFailuresByIdentifier returns the failure records every certificate holds for
// ONE identifier, sorted by certificate name so identical input yields identical output.
//
// ListIdentifierFailures answers the fallback's question ("which of THIS certificate's names is
// broken lately"); this one answers the opposite cut ("which certificates have seen THIS name
// fail"). The second cut is what restart-time cooldown seeding needs: the budget being protected
// -- 5 failed authorizations per identifier per hour -- belongs to the name, and a failure is
// recorded under whichever certificate happened to attempt the validation, so every certificate
// carrying the name has to see it.
func (s *Store) ListIdentifierFailuresByIdentifier(identifier string) ([]*IdentifierFailure, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_name, identifier, failures, last_error, last_failed_at
		FROM identifier_failures WHERE identifier = ? ORDER BY cert_name`, identifier)
	if err != nil {
		return nil, fmt.Errorf("list identifier failures for identifier %s: %w", identifier, err)
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
