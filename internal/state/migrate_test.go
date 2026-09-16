package state

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The upgrade path must work in place on a database that **already holds data**.
//
// The entire point of this project is "never make users delete and rebuild the db"
// (losing the order URL walks into 5 certs per exact set of identifiers / 7 days).
// CREATE TABLE IF NOT EXISTS does not add columns to an existing table, so explicit
// column-addition logic is mandatory.
func TestMigrateAddsIdentifiersToLegacyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Build a "legacy" orders table: no identifiers column, and it already holds data.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE orders (
			cert_name    TEXT PRIMARY KEY,
			order_url    TEXT NOT NULL,
			finalize_url TEXT NOT NULL DEFAULT '',
			cert_url     TEXT NOT NULL DEFAULT '',
			expires_at   INTEGER NOT NULL DEFAULT 0,
			status       TEXT NOT NULL DEFAULT '',
			key_pem      BLOB,
			updated_at   INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO orders (cert_name, order_url, finalize_url, status, key_pem)
		VALUES ('legacy', 'https://acme.example/order/1', 'https://acme.example/finalize/1', 'pending', x'deadbeef');
	`)
	if err != nil {
		t.Fatalf("building the legacy table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing the legacy db: %v", err)
	}

	// Open with the new version: columns should be added automatically and not one old
	// row lost.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a legacy db failed (an upgrade that demands deleting the db is worthless): %v", err)
	}
	defer s.Close()

	o, err := s.GetOrder("legacy")
	if err != nil {
		t.Fatalf("GetOrder failed: %v", err)
	}
	if o == nil {
		t.Fatal("legacy order lost after upgrade")
	}
	if o.OrderURL != "https://acme.example/order/1" {
		t.Errorf("OrderURL = %q", o.OrderURL)
	}
	if o.FinalizeURL != "https://acme.example/finalize/1" {
		t.Errorf("FinalizeURL = %q", o.FinalizeURL)
	}
	// The legacy row has no such information, so it must be an empty string -- the layer
	// above uses that to decide "skip the set comparison".
	if o.Identifiers != "" {
		t.Errorf("Identifiers on a legacy order should be empty, got %q", o.Identifiers)
	}
	if o.DeploymentCertID != "" {
		t.Errorf("DeploymentCertID on a legacy order should be empty, got %q", o.DeploymentCertID)
	}
	if string(o.KeyPEM) != "\xde\xad\xbe\xef" {
		t.Errorf("private key not preserved: %x", o.KeyPEM)
	}

	// After the column is added, new values must write normally.
	o.Identifiers = "a.example.com,b.example.com"
	o.DeploymentCertID = "cert-uploaded-before-restart"
	if err := s.PutOrder(o); err != nil {
		t.Fatalf("write failed after the column was added: %v", err)
	}
	got, err := s.GetOrder("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Identifiers != "a.example.com,b.example.com" {
		t.Errorf("Identifiers round-trip failed: %q", got.Identifiers)
	}
	if got.DeploymentCertID != "cert-uploaded-before-restart" {
		t.Errorf("DeploymentCertID round-trip failed: %q", got.DeploymentCertID)
	}
}

// Migration must be idempotent: repeatedly opening the same db must not error.
func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	for i := 0; i < 3; i++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("Open attempt %d failed: %v", i+1, err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close attempt %d failed: %v", i+1, err)
		}
	}
}

// The state db holds the ACME account private key and the private keys of every active
// certificate, so on-disk permissions must be 0600 -- never trust the caller's umask.
func TestStateFileIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX permission assertions on Windows")
	}

	// Simulate the loosest umask (0000): even then the file must be owner read/write only.
	old := setUmask(0)
	defer setUmask(old)

	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	_ = s.PutCert(&CertState{Name: "x", KeyPEM: []byte("PRIVATE")})
	_ = s.PutOrder(&Order{CertName: "x", OrderURL: "u"})
	defer s.Close()

	// Under WAL mode -wal / -shm are also copies of the private keys, so check them too.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := path + suffix
		st, err := os.Stat(p)
		if err != nil {
			// A missing WAL file is normal (it gets removed after a clean close).
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := st.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %o: group/other users can access it (want 0600)", filepath.Base(p), perm)
		}
	}
}

// The create/migrate window must run under a restrictive umask and, just as
// importantly, give the old one back: SQLite derives -wal/-shm permissions from the
// process umask, and those files are copies of the private keys. If Open forgot to
// restore it, every file the caller creates afterwards would silently come out
// owner-only -- so the restored umask is the observable proof the window is scoped.
func TestOpenRestoresTheProcessUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no umask semantics on Windows")
	}

	old := setUmask(0o022)
	defer setUmask(old)

	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// Setting 022 again reports the umask Open left behind; it must be 022, not 077.
	if left := setUmask(0o022); left != 0o022 {
		t.Errorf("Open left the process umask at %o, want it restored to 022", left)
	}
}

// The wrapper itself: a file born inside the window gets no group/other bits even
// when the creating call asks for 0666 and the process umask masks nothing, and the
// previous umask comes back afterwards.
func TestRestrictiveUmaskScopesFileCreation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no umask semantics on Windows")
	}

	old := setUmask(0)
	defer setUmask(old)

	restore := restrictiveUmask()
	p := filepath.Join(t.TempDir(), "born-inside.txt")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	restore()

	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("a file born under restrictiveUmask has mode %o: group/other can access it", perm)
	}
	if left := setUmask(0); left != 0 {
		t.Errorf("restrictiveUmask did not restore the umask: left at %o, want 0", left)
	}
}

// A missing parent directory should be created automatically rather than throwing an
// obscure SQLite error.
// Non-systemd deployments (running -once by hand, e2e scripts) take this path.
func TestOpenCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "c", "state.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open should create the parent directory: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state db was not created: %v", err)
	}
}

// DeleteAuthorization deletes only the one specified, with no collateral damage.
// wildcard and apex authorizations land on the same TXT name, but their rows are separate.
func TestDeleteAuthorizationKeepsSiblings(t *testing.T) {
	s := openTestStore(t)

	for _, a := range []*Authorization{
		{CertName: "c", AuthzURL: "authz-1", Identifier: "example.com", TxtValue: "v1", Presented: true},
		{CertName: "c", AuthzURL: "authz-2", Identifier: "*.example.com", TxtValue: "v2", Presented: true},
	} {
		if err := s.PutAuthorization(a); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.DeleteAuthorization("c", "authz-1"); err != nil {
		t.Fatalf("DeleteAuthorization failed: %v", err)
	}

	got, err := s.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 authorization left, got %d", len(got))
	}
	if got[0].AuthzURL != "authz-2" || got[0].TxtValue != "v2" {
		t.Errorf("deleted the wrong row: %+v", got[0])
	}

	// Deleting a row that does not exist should not error (idempotent).
	if err := s.DeleteAuthorization("c", "authz-1"); err != nil {
		t.Errorf("deleting twice should be idempotent: %v", err)
	}
}

// The deploy_confirmed migration is the other half of the upgrade path, and it had no
// coverage: TestDeployConfirmedMigratesOnOldSchema opens a *fresh* store, so
// ensureColumn never took its "column missing -> ALTER TABLE" branch. A typo in that
// struct literal would be invisible to the suite and surface only as a runtime failure
// on upgrade -- for exactly the users the migration exists to protect.
func TestMigrateAddsDeployConfirmedToLegacyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// A legacy certificates table: no deploy_confirmed, and it already holds a row.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE certificates (
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
			updated_at           INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO certificates (name, not_after, cert_url, deployed_cert_id, key_pem)
		VALUES ('legacy', 1893456000, 'https://acme.example/cert/1', 'ap-live', x'deadbeef');
	`)
	if err != nil {
		t.Fatalf("building the legacy table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing the legacy db: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a legacy db failed (an upgrade that demands deleting the db is worthless): %v", err)
	}
	defer s.Close()

	c, err := s.GetCert("legacy")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if c == nil {
		t.Fatal("legacy certificate lost after upgrade")
	}
	if c.DeployedCertID != "ap-live" {
		t.Errorf("DeployedCertID = %q, want ap-live", c.DeployedCertID)
	}
	if string(c.KeyPEM) != "\xde\xad\xbe\xef" {
		t.Errorf("private key not preserved: %x", c.KeyPEM)
	}
	// A legacy row cannot know, and false is the conservative answer: it only means
	// confirmBinding runs once more.
	if c.DeployConfirmed {
		t.Error("a legacy row must come out unconfirmed, not deployed")
	}

	// After the column is added, new values must write normally.
	c.DeployConfirmed = true
	if err := s.PutCert(c); err != nil {
		t.Fatalf("write failed after the column was added: %v", err)
	}
	got, err := s.GetCert("legacy")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if !got.DeployConfirmed {
		t.Error("deploy_confirmed did not round-trip after the migration")
	}
}
