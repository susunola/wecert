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
	_ "modernc.org/sqlite" // pure Go driver: no CGO, which keeps static builds easy
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
