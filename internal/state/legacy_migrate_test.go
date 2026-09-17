package state

import (
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
