package state

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// Opening a database written before the newest columns must migrate it, and every operation that
// touches those columns must then work.
//
// The two columns added in this round (authorizations.challenge_prepared_at and
// revoke_requests.cert_identity) are declared in schemaColumns, which is what makes an older
// database migrate instead of failing with "no such column" on the first read.
func buildLegacyDB(t *testing.T, path string) error {
	t.Helper()
	db, err := openSQLForTest(path)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(legacySchemaNoNewestColumns)
	return err
}

const legacySchemaNoNewestColumns = `
CREATE TABLE accounts (directory TEXT PRIMARY KEY, kid TEXT NOT NULL, private_key_pem BLOB NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE certificates (name TEXT PRIMARY KEY, not_after INTEGER NOT NULL DEFAULT 0, cert_url TEXT NOT NULL DEFAULT '', cert_pem BLOB, key_pem BLOB, issued_at INTEGER NOT NULL DEFAULT 0, ari_cert_id TEXT NOT NULL DEFAULT '', ari_window_start INTEGER NOT NULL DEFAULT 0, ari_window_end INTEGER NOT NULL DEFAULT 0, ari_checked_at INTEGER NOT NULL DEFAULT 0, ari_retry_after_ns INTEGER NOT NULL DEFAULT 0, consecutive_failures INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', deployed_cert_id TEXT NOT NULL DEFAULT '', deploy_confirmed INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE orders (cert_name TEXT PRIMARY KEY, order_url TEXT NOT NULL, finalize_url TEXT NOT NULL DEFAULT '', cert_url TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT '', key_pem BLOB, identifiers TEXT NOT NULL DEFAULT '', deployment_cert_id TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE authorizations (cert_name TEXT NOT NULL, authz_url TEXT NOT NULL, identifier TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', challenge_url TEXT NOT NULL DEFAULT '', challenge_token TEXT NOT NULL DEFAULT '', txt_name TEXT NOT NULL DEFAULT '', txt_value TEXT NOT NULL DEFAULT '', presented INTEGER NOT NULL DEFAULT 0, challenge_sent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (cert_name, authz_url));
CREATE TABLE retired_certificates (cert_id TEXT PRIMARY KEY, cert_name TEXT NOT NULL, retired_at INTEGER NOT NULL, cert_pem BLOB, key_pem BLOB);
CREATE TABLE identifier_failures (cert_name TEXT NOT NULL, identifier TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', last_failed_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (cert_name, identifier));
CREATE TABLE cert_fallback (cert_name TEXT PRIMARY KEY, dropped TEXT NOT NULL DEFAULT '', since INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '');
CREATE TABLE revoke_requests (cert_name TEXT PRIMARY KEY, reason INTEGER NOT NULL DEFAULT 0, requested_at INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', last_attempt_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE rate_buckets (limit_name TEXT NOT NULL, scope_id TEXT NOT NULL DEFAULT '', tokens REAL NOT NULL DEFAULT 0, observed_at INTEGER NOT NULL DEFAULT 0, reset_at INTEGER NOT NULL DEFAULT 0, reset_reason TEXT NOT NULL DEFAULT '', PRIMARY KEY (limit_name, scope_id));
`

func TestLegacyDatabaseGainsTheNewColumns(t *testing.T) {
	// Copied from the migration test before the columns existed (see the fixture file next to it).
	dir := t.TempDir()
	path := dir + "/legacy.db"
	if err := buildLegacyDB(t, path); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("an older database must migrate on open, got %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

	// The authorizations column round-trips.
	if err := store.PutAuthorization(&Authorization{
		CertName: "c", AuthzURL: "a1", Identifier: "example.com",
		ChallengeToken: "tok", TxtName: "_acme-challenge.example.com.", TxtValue: "v",
		ChallengePreparedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatalf("reading the migrated table failed: %v", err)
	}
	if len(as) != 1 || !as[0].ChallengePreparedAt.Equal(now) {
		t.Fatalf("the new column must round-trip, got %+v", as)
	}
	// A writer that does not know the age must not erase it.
	if err := store.PutAuthorization(&Authorization{
		CertName: "c", AuthzURL: "a1", Identifier: "example.com", Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}
	if as, err = store.ListAuthorizations("c"); err != nil || len(as) != 1 || !as[0].ChallengePreparedAt.Equal(now) {
		t.Fatalf("an update that does not set the age must keep it, got %+v (err=%v)", as, err)
	}

	// The revocation column round-trips too.
	if err := store.AddRevokeRequest("c", 4, "identity-1", now); err != nil {
		t.Fatal(err)
	}
	req, err := store.GetRevokeRequest("c")
	if err != nil || req == nil || req.CertIdentity != "identity-1" {
		t.Fatalf("the revoke request's identity must round-trip, got %+v (err=%v)", req, err)
	}
}

// The orphan-clean column is newer than the two columns above, and it is the one where "rows that
// predate it" is the normal case rather than an edge: every existing deployment that has ever
// dropped a certificate from its document already holds those rows, and the sweep reads the column
// on every pass. The migration must therefore add it to a database that already holds data, the
// legacy rows must read as "never cleaned" (the conservative answer: one more teardown each, once),
// and the mark has to survive being reopened.
func TestLegacyDatabaseGainsTheOrphanCleanedColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	if err := buildLegacyDB(t, path); err != nil {
		t.Fatal(err)
	}

	// A certificate that predates the column, holding material that must not be lost.
	db, err := openSQLForTest(path)
	if err != nil {
		t.Fatalf("open the legacy database: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO certificates (name, not_after, cert_url, cert_pem, key_pem,
		                         deployed_cert_id, consecutive_failures, updated_at)
		VALUES ('legacy', 1893456000, 'https://acme.example/cert/1', x'deadbeef', x'cafe',
		        'ap-live', 2, 1893456000)`); err != nil {
		t.Fatalf("seeding the legacy row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing the legacy database: %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("an older database must migrate on open, got %v", err)
	}

	c, err := store.GetCert("legacy")
	if err != nil {
		t.Fatalf("GetCert on the migrated row: %v", err)
	}
	if c == nil {
		t.Fatal("the legacy certificate was lost by the migration")
	}
	if string(c.CertPEM) != "\xde\xad\xbe\xef" || string(c.KeyPEM) != "\xca\xfe" {
		t.Errorf("certificate material did not survive: cert=%x key=%x", c.CertPEM, c.KeyPEM)
	}
	if c.DeployedCertID != "ap-live" || c.ConsecutiveFailures != 2 {
		t.Errorf("the rest of the row did not survive: %+v", c)
	}
	if !c.NotAfter.Equal(time.Unix(1893456000, 0)) {
		t.Errorf("NotAfter = %s, want the stored unix second", c.NotAfter)
	}
	// Never cleaned: the row cannot know, and "0" costs exactly one more teardown, while the other
	// reading would skip the teardown of every pre-existing orphan in the fleet.
	if !c.OrphanCleanedAt.IsZero() {
		t.Errorf("a legacy row must read as never cleaned, got %s", c.OrphanCleanedAt)
	}

	// The column is writable now, and the mark survives a reopen of the file.
	if marked, err := store.MarkOrphanCleaned("legacy"); err != nil || !marked {
		t.Fatalf("MarkOrphanCleaned on the migrated row = %v, %v; want true, nil", marked, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening the migrated database: %v", err)
	}
	defer reopened.Close()
	if c, err = reopened.GetCert("legacy"); err != nil || c == nil {
		t.Fatalf("GetCert after the reopen: %v (c=%v)", err, c)
	}
	if c.OrphanCleanedAt.IsZero() {
		t.Error("the mark did not survive a reopen: the migration must not run again over it")
	}
}

// ── the other direction: an OLDER binary opening THIS schema ────────────────

// The oldCertSelect and oldCertInsert are the pre-orphan-column build's own statements, copied
// verbatim from the commit before the column was added. They are the whole of what an older binary
// does to this table, so replaying them against a database this build migrated is the rollback
// property docs/backlog.md item 8 records as claimed-but-untested.
const (
	oldCertSelect = `
		SELECT name, not_after, cert_url, cert_pem, key_pem, issued_at,
		       ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
		       consecutive_failures, next_attempt_at, last_error, deployed_cert_id,
		       deploy_confirmed, updated_at
		FROM certificates WHERE name = ?`

	oldCertUpsert = `
		INSERT INTO certificates (
			name, not_after, cert_url, cert_pem, key_pem, issued_at,
			ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
			consecutive_failures, next_attempt_at, last_error, deployed_cert_id,
			deploy_confirmed, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			not_after            = excluded.not_after,
			cert_url             = excluded.cert_url,
			cert_pem             = excluded.cert_pem,
			key_pem              = excluded.key_pem,
			issued_at            = excluded.issued_at,
			ari_cert_id          = excluded.ari_cert_id,
			ari_window_start     = excluded.ari_window_start,
			ari_window_end       = excluded.ari_window_end,
			ari_checked_at       = excluded.ari_checked_at,
			ari_retry_after_ns   = excluded.ari_retry_after_ns,
			consecutive_failures = excluded.consecutive_failures,
			next_attempt_at      = excluded.next_attempt_at,
			last_error           = excluded.last_error,
			deployed_cert_id     = excluded.deployed_cert_id,
			deploy_confirmed     = excluded.deploy_confirmed,
			updated_at           = excluded.updated_at`
)

// A newer binary must migrate an older database (the two tests above), and an OLDER binary must
// still open and write the database the newer one left behind -- otherwise rolling back a bad
// release means restoring a snapshot, and the disaster case of this project is losing the state
// database.
//
// Three things make that work, and this test checks all three against a database this build created
// and migrated:
//
//  1. its CREATE TABLE IF NOT EXISTS batch is a no-op on tables that already exist;
//  2. its column check is check-then-act (`PRAGMA table_info` before `ALTER TABLE ADD COLUMN`), so
//     it never issues a duplicate ADD COLUMN for the columns it knows;
//  3. every read and write names its columns explicitly, so the new column is invisible to it --
//     and, just as important, its whole-row upsert cannot erase the mark, because it does not
//     mention it.
//
// What this does NOT do is run a literal pre-change binary (see the report): the observable contract
// is the SQL, and that is what is replayed here.
func TestAnOlderBinaryStillOpensTheNewSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	// This build creates and migrates the database, writes a row, and marks it orphan-cleaned.
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.PutCert(&CertState{
		Name: "shared", NotAfter: time.Unix(1893456000, 0), CertURL: "https://acme.example/cert/1",
		CertPEM: []byte("new-build-material"), DeployedCertID: "ap-new",
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if marked, err := store.MarkOrphanCleaned("shared"); err != nil || !marked {
		t.Fatalf("MarkOrphanCleaned = %v, %v; want true, nil", marked, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The older binary opens the same file. Its schema batch, copied from the same commit.
	db, err := openSQLForTest(path)
	if err != nil {
		t.Fatalf("the older binary cannot open the new database: %v", err)
	}
	if _, err := db.Exec(`
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
			consecutive_failures INTEGER NOT NULL DEFAULT 0,
			next_attempt_at      INTEGER NOT NULL DEFAULT 0,
			last_error           TEXT    NOT NULL DEFAULT '',
			deployed_cert_id     TEXT    NOT NULL DEFAULT '',
			deploy_confirmed     INTEGER NOT NULL DEFAULT 0,
			updated_at           INTEGER NOT NULL DEFAULT 0
		)`); err != nil {
		t.Fatalf("the older binary's CREATE TABLE IF NOT EXISTS failed: %v", err)
	}

	// Its column check: every column it knows about must be there, or it would try to add one (and
	// a duplicate ADD COLUMN aborts its open with a message that names neither cause nor fix).
	known := []string{
		"name", "not_after", "cert_url", "cert_pem", "key_pem", "issued_at", "ari_cert_id",
		"ari_window_start", "ari_window_end", "ari_checked_at", "ari_retry_after_ns",
		"consecutive_failures", "next_attempt_at", "last_error", "deployed_cert_id",
		"deploy_confirmed", "updated_at",
	}
	present := map[string]bool{}
	rows, err := db.Query(`PRAGMA table_info(certificates)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info: %v", err)
	}
	for rows.Next() {
		var (
			cid, notNull, pk int
			name, ctype      string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		present[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("closing table_info: %v", err)
	}
	for _, col := range known {
		if !present[col] {
			t.Errorf("the older binary's column %q is missing from the new schema: its migrate() would "+
				"run an ALTER TABLE, and its reads would fail", col)
		}
	}
	if !present["orphan_cleaned_at"] {
		t.Error("this test is pointless if the new column is not there")
	}

	// Its read: an explicit column list, which is what makes the new column invisible.
	var (
		name, certURL, ariCertID, lastError, deployedID string
		notAfter, issuedAt, ariStart, ariEnd            int64
		ariChecked, retryAfterNS, failures              int64
		nextAttempt, updatedAt                          int64
		certPEM, keyPEM                                 []byte
		deployConfirmed                                 bool
	)
	if err := db.QueryRow(oldCertSelect, "shared").Scan(
		&name, &notAfter, &certURL, &certPEM, &keyPEM, &issuedAt,
		&ariCertID, &ariStart, &ariEnd, &ariChecked, &retryAfterNS,
		&failures, &nextAttempt, &lastError, &deployedID, &deployConfirmed, &updatedAt,
	); err != nil {
		t.Fatalf("the older binary's SELECT failed on the new schema: %v", err)
	}
	if name != "shared" || string(certPEM) != "new-build-material" {
		t.Errorf("the older binary read %q/%q, want shared/new-build-material", name, certPEM)
	}

	// Its write: the whole-row upsert, which must not erase the new column.
	if _, err := db.Exec(oldCertUpsert,
		"shared", int64(1893456000), "https://acme.example/cert/1",
		[]byte("old-build-material"), []byte("old-key"), int64(0),
		"", int64(0), int64(0), int64(0), int64(0),
		0, int64(0), "", "ap-old", false, int64(1893456001),
	); err != nil {
		t.Fatalf("the older binary's whole-row upsert failed on the new schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Back on the new binary: the old write landed, and the mark it does not know about is intact.
	store, err = Open(path)
	if err != nil {
		t.Fatalf("the new binary cannot reopen a database an older one wrote: %v", err)
	}
	defer store.Close()
	c, err := store.GetCert("shared")
	if err != nil || c == nil {
		t.Fatalf("GetCert: %v (c=%v)", err, c)
	}
	if string(c.CertPEM) != "old-build-material" || c.DeployedCertID != "ap-old" {
		t.Errorf("the older binary's write did not land: %+v", c)
	}
	if c.OrphanCleanedAt.IsZero() {
		t.Error("the older binary's whole-row upsert erased the orphan-clean mark: after a rollback, " +
			"every orphan would be torn down again on every pass by the next upgrade")
	}
}
