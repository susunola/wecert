// Package state is wecert's persistence layer.
//
// The existence of this layer is itself a requirement: Let's Encrypt explicitly
// names the most common way people hit rate limits -- "deleting the ACME client's
// configuration data on every deploy". Losing the order URL makes a restarted
// process place a fresh order, walking straight into
// "5 certificates per exact set of identifiers / 7 days".
//
// So: account key, order URL, ARI window, and Tencent Cloud CertId all hit disk.
package state

import (
	"fmt"
	_ "modernc.org/sqlite"
)

// Per-table CRUD, split out of state.go so one table lives in one file.
// Same package: every method is still on Store.

func (s *Store) ListAuthorizations(certName string) ([]*Authorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_name, authz_url, identifier, status, challenge_url, challenge_token,
		       txt_name, txt_value, presented, challenge_sent, challenge_prepared_at
		FROM authorizations WHERE cert_name = ? ORDER BY authz_url`, certName)
	if err != nil {
		return nil, fmt.Errorf("list authorizations for %s: %w", certName, err)
	}
	defer rows.Close()

	var out []*Authorization
	for rows.Next() {
		a := &Authorization{}
		var preparedAt int64
		if err := rows.Scan(&a.CertName, &a.AuthzURL, &a.Identifier, &a.Status,
			&a.ChallengeURL, &a.ChallengeToken, &a.TxtName, &a.TxtValue,
			&a.Presented, &a.ChallengeSent, &preparedAt); err != nil {
			return nil, fmt.Errorf("scan authorization: %w", err)
		}
		a.ChallengePreparedAt = fromUnix(preparedAt)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ExecForTest runs one statement against the open database.
//
// For tests that need to inject a fault the public API cannot express -- most often a trigger that
// refuses a specific write, which is how "the write fails but the read did not" (a full disk, a
// corrupt page) is reproduced deterministically. The alternative is a fake store, and a fake store
// would not exercise the real SQL, the real transaction or the real error mapping.
//
// Why an exported method compiled into the production binary instead of an export_test.go symbol:
// its callers live in OTHER packages (internal/acme's fault-injection tests), and Go makes
// test-only symbols visible only to the package's own tests. A _test.go file here simply cannot
// reach them, so the seam has to ship. It is one statement against an already-open handle -- the
// same privilege every other method on this type has -- so the cost of shipping it is a naming
// convention, not an attack surface.

func (s *Store) ExecForTest(query string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(query)
	return err
}

// ListAuthorizationsForTest is ListAuthorizations, exposed for tests in other packages that need to
// observe what is on disk at a specific moment (see the acme package's Present hook).
func (s *Store) ListAuthorizationsForTest(certName string) ([]*Authorization, error) {
	return s.ListAuthorizations(certName)
}

// ListPresentedAuthorizations lists every authorization this state store still believes
// has a TXT record in DNS, across all certificates.
//
// It exists for the challenge-lease registry in internal/acme: that registry only knows
// what the current *process* wrote, and lego's cleanup deletes every TXT at the challenge
// name. A row recovered from a previous process is therefore a live value the registry
// cannot see, and a cleanup for a different certificate sharing the name would delete it.
// Re-registering from here before any cleanup closes that window.
func (s *Store) ListPresentedAuthorizations() ([]*Authorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_name, authz_url, identifier, status, challenge_url, challenge_token,
		       txt_name, txt_value, presented, challenge_sent, challenge_prepared_at
		FROM authorizations WHERE presented = 1 ORDER BY txt_name, cert_name`)
	if err != nil {
		return nil, fmt.Errorf("list presented authorizations: %w", err)
	}
	defer rows.Close()

	var out []*Authorization
	for rows.Next() {
		a := &Authorization{}
		var preparedAt int64
		if err := rows.Scan(&a.CertName, &a.AuthzURL, &a.Identifier, &a.Status,
			&a.ChallengeURL, &a.ChallengeToken, &a.TxtName, &a.TxtValue,
			&a.Presented, &a.ChallengeSent, &preparedAt); err != nil {
			return nil, fmt.Errorf("scan presented authorization: %w", err)
		}
		a.ChallengePreparedAt = fromUnix(preparedAt)
		out = append(out, a)
	}
	return out, rows.Err()
}

// PutAuthorization writes a single authorization.
func (s *Store) PutAuthorization(a *Authorization) error {
	if a == nil {
		return fmt.Errorf("nil authorization")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO authorizations (
			cert_name, authz_url, identifier, status, challenge_url, challenge_token,
			txt_name, txt_value, presented, challenge_sent, challenge_prepared_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cert_name, authz_url) DO UPDATE SET
			identifier      = excluded.identifier,
			status          = excluded.status,
			challenge_url   = excluded.challenge_url,
			challenge_token = excluded.challenge_token,
			txt_name        = excluded.txt_name,
			txt_value       = excluded.txt_value,
			presented       = excluded.presented,
			challenge_sent  = excluded.challenge_sent,
			-- Kept, not overwritten with 0, when the writer does not know: several paths persist a
			-- row they did not pick a challenge for (a status update), and losing the age there
			-- would silently switch the reclaim probe back to trusting a fresh denial.
			challenge_prepared_at = CASE WHEN excluded.challenge_prepared_at > 0
				THEN excluded.challenge_prepared_at ELSE authorizations.challenge_prepared_at END`,
		a.CertName, a.AuthzURL, a.Identifier, a.Status, a.ChallengeURL, a.ChallengeToken,
		a.TxtName, a.TxtValue, a.Presented, a.ChallengeSent, toUnix(a.ChallengePreparedAt))
	if err != nil {
		return fmt.Errorf("put authorization %s: %w", a.AuthzURL, err)
	}
	return nil
}

// DeleteAuthorizations clears every authorization record for a certificate.
//
// Note: the manager no longer goes through this -- discarding an order should call
// cleanupOrphanTXT, which first reclaims TXT records still present in DNS and only
// then deletes rows. This method is a backstop for cases that genuinely need the whole
// table cleared (tests or manual intervention, for example).
func (s *Store) DeleteAuthorizations(certName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM authorizations WHERE cert_name = ?`, certName)
	if err != nil {
		return fmt.Errorf("delete authorizations for %s: %w", certName, err)
	}
	return nil
}

// DeleteAuthorization deletes a single authorization record.
// Used to clean up leftover authorization rows whose TXT has already been reclaimed
// and no longer needs tracking.
func (s *Store) DeleteAuthorization(certName, authzURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`DELETE FROM authorizations WHERE cert_name = ? AND authz_url = ?`, certName, authzURL)
	if err != nil {
		return fmt.Errorf("delete authorization %s: %w", authzURL, err)
	}
	return nil
}

