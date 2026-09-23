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
	const schema = `
CREATE TABLE IF NOT EXISTS accounts (
    directory       TEXT PRIMARY KEY,
    kid             TEXT NOT NULL,
    private_key_pem BLOB NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    name                 TEXT PRIMARY KEY,
    not_after            INTEGER NOT NULL DEFAULT 0,
    cert_url             TEXT    NOT NULL DEFAULT '',
    cert_pem             BLOB,
    key_pem              BLOB,
    issued_at            INTEGER NOT NULL DEFAULT 0,
    ari_cert_id          TEXT    NOT NULL DEFAULT '',
    ari_window_start     INTEGER NOT NULL DEFAULT 0,
    ari_window_end       INTEGER NOT NULL DEFAULT 0,
    ari_checked_at       INTEGER NOT NULL DEFAULT 0,
    ari_retry_after_ns   INTEGER NOT NULL DEFAULT 0,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    next_attempt_at        INTEGER NOT NULL DEFAULT 0,
    last_error             TEXT    NOT NULL DEFAULT '',
    deployed_cert_id       TEXT    NOT NULL DEFAULT '',
    -- Upload success != bound to the listener. Only set once the one-click update
    -- has actually swapped it over; otherwise the first upload is treated as
    -- "deployed" and metrics go green before a human has bound anything.
    deploy_confirmed       INTEGER NOT NULL DEFAULT 0,
    -- When this name's orphan teardown finished (unix seconds). 0 means never.
    --
    -- The row of a certificate that left the desired state is kept on purpose -- that is what
    -- preserves its history if the name comes back -- so the orphan sweep sees it again on every
    -- pass. This column is the durable "already torn down" mark that lets the sweep report it
    -- without paying for its teardown a second time; an in-memory set would be a second map
    -- growing with churn, and would forget everything on restart, which is exactly when a fleet
    -- edit is most likely to happen.
    --
    -- Written only by MarkOrphanCleaned and cleared only by ClearOrphanCleaned: putCertExec
    -- deliberately leaves it out of its column list (see CertState.OrphanCleanedAt).
    orphan_cleaned_at      INTEGER NOT NULL DEFAULT 0,
    updated_at             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
    cert_name    TEXT PRIMARY KEY,
    order_url    TEXT NOT NULL,
    finalize_url TEXT NOT NULL DEFAULT '',
    cert_url     TEXT NOT NULL DEFAULT '',
    expires_at   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT '',
    key_pem      BLOB,
    -- The identifier set submitted at newOrder time (canonical form, see config.DomainKey).
    identifiers  TEXT NOT NULL DEFAULT '',
    deployment_cert_id TEXT NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authorizations (
    cert_name       TEXT NOT NULL,
    authz_url       TEXT NOT NULL,
    identifier      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT '',
    challenge_url   TEXT NOT NULL DEFAULT '',
    challenge_token TEXT NOT NULL DEFAULT '',
    txt_name        TEXT NOT NULL DEFAULT '',
    txt_value       TEXT NOT NULL DEFAULT '',
    presented       INTEGER NOT NULL DEFAULT 0,
    challenge_sent  INTEGER NOT NULL DEFAULT 0,
    -- When the challenge currently in this row was chosen (see the acme package). Crash recovery
    -- needs it: an authoritative "no such record" is only trustworthy once the write would have had
    -- time to propagate, and DNSPod's authoritative servers lag the API write by up to a minute.
    challenge_prepared_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cert_name, authz_url)
);

-- Cloud certificates that are retired but not yet deleted. Kept for a while to allow
-- rollback, then they must be reclaimed: Tencent Cloud accounts have a quota on the
-- number of uploaded certificates.
--
-- cert_pem / key_pem are the archived material for the retired certificate, so it can be
-- re-uploaded and re-bound during the retention window.
--
-- This table used to hold only the CertId, and the retired certificate's key was
-- overwritten in the certificates row at the moment of renewal -- so "rollback" meant
-- "whatever the cloud still has", and after the retention period deleted it, wecert had
-- nothing to restore from. The comment here and in the deployer claimed rollback was the
-- point; now the material is actually retained, and pruned with the row.
CREATE TABLE IF NOT EXISTS retired_certificates (
    cert_id    TEXT PRIMARY KEY,
    cert_name  TEXT NOT NULL,
    retired_at INTEGER NOT NULL,
    cert_pem   BLOB,
    key_pem    BLOB
);

-- Per-identifier authorization failure ledger.
--
-- The certificate-level consecutive_failures only tells you "this certificate cannot
-- be issued", whereas pre-expiry fallback has to answer "**which name** cannot be
-- issued" -- without that, the only option is dropping names at random, which
-- sacrifices names that were fine to begin with.
--
-- last_failed_at also provides self-healing: once a failure record ages out, that
-- identifier stops being dropped and the next round naturally retries the full set.
-- No extra retry state is needed.
CREATE TABLE IF NOT EXISTS identifier_failures (
    cert_name      TEXT NOT NULL,
    identifier     TEXT NOT NULL,
    failures       INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT NOT NULL DEFAULT '',
    last_failed_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cert_name, identifier)
);

-- The currently active fallback state: this certificate is serving a certificate that
-- is missing some names.
--
-- A separate table rather than extra columns on certificates: this is not a property
-- of the certificate but an "incident in progress", and its lifecycle is completely
-- different -- it should be cleared once the full set issues successfully, while
-- certificate renewal must not touch it.
CREATE TABLE IF NOT EXISTS cert_fallback (
    cert_name TEXT PRIMARY KEY,
    dropped   TEXT NOT NULL DEFAULT '',
    since     INTEGER NOT NULL DEFAULT 0,
    reason    TEXT NOT NULL DEFAULT ''
);

-- Rate-limit bucket snapshots.
--
-- Let's Encrypt publishes its limits and their token-bucket refill rates but offers no way
-- to query the remaining allowance, so the only way to answer "how much is left" is to
-- account for what this program spent. A bucket needs no event log: the model is the memory,
-- so one row per (limit, scope) holding the last known level and when it was observed can be
-- rolled forward to any later instant.
--
-- scope_id is empty for account-wide limits and holds the registered domain / identifier
-- otherwise. reset_at is an AUTHORITATIVE instant the CA reported ("retry after ..."), which
-- beats the local estimate because the estimate cannot see other accounts spending the same
-- global bucket.
-- Revocation requests that have not succeeded yet.
--
-- A row here means "an operator decided this certificate must be revoked, and the CA has not
-- accepted it yet". Persisted rather than attempted once because revocation can fail for
-- entirely transient reasons (network, CA 5xx) and the decision must not be lost with the
-- process: a leaked private key does not stop being leaked because the request timed out.
--
-- The alternative -- only revoking synchronously from a CLI -- leaves a failed attempt as a
-- message on someone's terminal, with no record that the operator ever asked.
--
-- reason is the RFC 5280 CRLReason code, so the reason the operator chose survives into every
-- retry rather than being lost after the first attempt.
CREATE TABLE IF NOT EXISTS revoke_requests (
    cert_name   TEXT PRIMARY KEY,
    reason      INTEGER NOT NULL DEFAULT 0,
    -- The certificate the operator asked to revoke, as an identity derived from its material
    -- (see acme.certIdentity). Without it the retry revoked "whatever is stored under this name
    -- now" -- and a renewal between the request and the retry replaces exactly that, so the
    -- request could revoke the NEW certificate while the compromised one stayed valid, then
    -- clear itself as a success. Empty means unknown: a request recorded by an older build.
    cert_identity TEXT NOT NULL DEFAULT '',
    requested_at INTEGER NOT NULL DEFAULT 0,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT NOT NULL DEFAULT '',
    last_attempt_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rate_buckets (
    limit_name TEXT NOT NULL,
    scope_id   TEXT NOT NULL DEFAULT '',
    tokens     REAL NOT NULL DEFAULT 0,
    observed_at INTEGER NOT NULL DEFAULT 0,
    reset_at   INTEGER NOT NULL DEFAULT 0,
    reset_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (limit_name, scope_id)
);
`
	_, err := s.db.Exec(schema)
	if err != nil {
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
