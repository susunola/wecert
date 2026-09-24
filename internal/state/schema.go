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
	"database/sql"
	"fmt"
	_ "modernc.org/sqlite" // pure Go driver: no CGO, which keeps static builds easy
)

// Split out so one concern lives in one file. Same package.

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schemaDDL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// CREATE TABLE IF NOT EXISTS does not add columns to an **existing** table, so
	// patch old databases separately. The package-level warning -- "losing it means
	// hitting the rate limit" -- applies here too: on upgrade, one extra migration
	// step is always better than demanding that users delete and rebuild the database.
	for _, m := range schemaColumns {
		if err := s.ensureColumn(m.table, m.column, m.decl); err != nil {
			return err
		}
	}
	return nil
}

// schemaTables are the tables this binary creates.
//
// Declared as data for the same reason schemaColumns is: an unlocked open has to be able to say
// whether the database in front of it is one this build understands, without applying anything.
var schemaTables = []string{
	"accounts",
	"certificates",
	"orders",
	"authorizations",
	"retired_certificates",
	"identifier_failures",
	"cert_fallback",
	"revoke_requests",
	"rate_buckets",
	"state_generation",
	"probe_samples",
}

// schemaColumns are the columns added to tables that predate them.
//
// Declared as data, and read by both migrate (which adds them) and pendingMigrations (which only
// reports them), so the unlocked open cannot drift into believing a database is current when it is
// not. A missing column here is a missing migration on both paths at once, which the daemon's own
// migrate call still applies -- the unlocked path simply keeps refusing.
var schemaColumns = []struct{ table, column, decl string }{
	{"certificates", "deploy_confirmed", "INTEGER NOT NULL DEFAULT 0"},
	{"orders", "identifiers", "TEXT NOT NULL DEFAULT ''"},
	{"orders", "deployment_cert_id", "TEXT NOT NULL DEFAULT ''"},
	// Rollback material. Legacy rows keep NULL: there is nothing to recover for a
	// certificate retired before wecert started archiving, and inventing an empty
	// value would look like a usable (empty) certificate.
	{"retired_certificates", "cert_pem", "BLOB"},
	{"retired_certificates", "key_pem", "BLOB"},
	// Certificate identity on a pending revocation. Legacy rows keep the empty default, which
	// reads as "unknown" and makes the retry fall back to the pre-column behaviour (revoke the
	// material stored now); inventing an identity would make the retry refuse to act on the
	// operator's request for a reason that was not true when they made it.
	{"revoke_requests", "cert_identity", "TEXT NOT NULL DEFAULT ''"},
	// When the challenge in an authorization row was chosen. Legacy rows keep 0, which reads as
	// "unknown age" and makes the reclaim probe fall back to its previous behaviour.
	{"authorizations", "challenge_prepared_at", "INTEGER NOT NULL DEFAULT 0"},
	// When the orphan teardown for a name finished (see the certificates schema). Legacy rows keep
	// 0, which reads as "never cleaned" -- the conservative answer: such a name is torn down once
	// more, and only then marked.
	{"certificates", "orphan_cleaned_at", "INTEGER NOT NULL DEFAULT 0"},
	// DNS cleanup guardian (see authorizations in schemaDDL). Legacy rows keep 0 = never
	// stuck, so they are invisible to the stuck queue until a reclaim actually fails.
	{"authorizations", "reclaim_attempts", "INTEGER NOT NULL DEFAULT 0"},
	{"authorizations", "reclaim_last_error", "TEXT NOT NULL DEFAULT ''"},
	{"authorizations", "reclaim_stuck_since", "INTEGER NOT NULL DEFAULT 0"},
}

// pendingMigrations reports schema changes this binary would apply, without applying them.
//
// It is what an unlocked open uses instead of migrating. Check-then-act ALTER TABLE is not safe
// between processes, and the loser of that race aborts the whole open with `duplicate column name`,
// which names neither the cause nor the fix.
func (s *Store) pendingMigrations() ([]string, error) {
	var out []string
	// Tables first, then columns.
	//
	// Checking only columns let an unlocked open accept a database that was missing one of the
	// tables this build adds (the column check cannot see a table that is not there at all), and the
	// operator then got a raw `no such table: revoke_requests` from whichever operation happened to
	// touch it, instead of the "this binary needs a schema update, stop the process and run wecert
	// -once" instruction that exists for exactly this. Reachable for any database written by a build
	// whose column set is current but which predates a table -- which is every release that adds one.
	for _, t := range schemaTables {
		exists, err := s.tableExists(t)
		if err != nil {
			return nil, err
		}
		if !exists {
			out = append(out, t)
		}
	}
	for _, m := range schemaColumns {
		exists, err := s.columnExists(m.table, m.column)
		if err != nil {
			return nil, err
		}
		if !exists {
			out = append(out, m.table+"."+m.column)
		}
	}
	return out, nil
}

// tableExists reports whether the store's schema contains a table.
func (s *Store) tableExists(table string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check table %s: %w", table, err)
	}
	return n > 0, nil
}

// ensureColumn adds a column to a table (when it does not already exist).
//
// columnExists closing rows itself before returning is deliberate: the pool is capped
// at MaxOpenConns(1), and relying on the implicit close triggered by iterating rows to
// EOF to free the connection is too subtle -- if someone changes the loop below to
// return early, ALTER blocks forever waiting for a connection.
func (s *Store) ensureColumn(table, column, decl string) error {
	exists, err := s.columnExists(table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	// String concatenation instead of placeholders here: SQLite DDL does not accept
	// parameterized column names or types. All three arguments are literals in the
	// code and contain no user input.
	if _, err := s.db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + decl); err != nil {
		return fmt.Errorf("alter %s add %s: %w", table, column, err)
	}
	return nil
}

func (s *Store) columnExists(table, column string) (bool, error) {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, fmt.Errorf("pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return false, fmt.Errorf("scan table_info(%s): %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ---------- Time helpers: SQLite stores unix seconds throughout, 0 means zero value ----------
