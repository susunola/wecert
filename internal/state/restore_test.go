package state

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// restoreHarness is a state database with one certificate, a snapshot of it, and then one more
// certificate written afterwards -- the shape every restore question is asked about: does the
// restored database carry the snapshot's content and not the later writes?
type restoreHarness struct {
	dir      string
	dbPath   string
	snapDir  string
	snapshot string
}

func newRestoreHarness(t *testing.T) restoreHarness {
	t.Helper()
	dir := t.TempDir()
	h := restoreHarness{
		dir:     dir,
		dbPath:  filepath.Join(dir, "state.db"),
		snapDir: filepath.Join(dir, "snapshots"),
	}

	s, err := Open(h.dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.PutAccount(&Account{
		Directory: "https://acme.test/d", KID: "kid-1", PrivateKeyPEM: []byte("ACCOUNT KEY"),
	}); err != nil {
		t.Fatalf("PutAccount: %v", err)
	}
	if err := s.PutCert(&CertState{Name: "old-cert", KeyPEM: []byte("OLD KEY")}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	snap, err := s.Snapshot(h.snapDir, 3)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	h.snapshot = snap
	// Written AFTER the snapshot: the restore must lose this, and the copy it displaced must keep it.
	if err := s.PutCert(&CertState{Name: "new-cert", KeyPEM: []byte("NEW KEY")}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return h
}

func (h restoreHarness) certNames(t *testing.T) []string {
	t.Helper()
	s, err := Open(h.dbPath)
	if err != nil {
		t.Fatalf("Open after restore: %v", err)
	}
	defer s.Close()
	names, err := s.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	return names
}

func TestRestoreInstallsTheSnapshotAndKeepsWhatItReplaced(t *testing.T) {
	h := newRestoreHarness(t)

	res, err := Restore(h.dbPath, h.snapshot)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Certificates != 1 || !res.Account {
		t.Errorf("the report should describe the snapshot (1 certificate, account present), got %+v", res)
	}
	if res.Replaced == "" {
		t.Fatal("the database that was replaced must be kept, and named in the result")
	}
	if res.ReplacedWrittenAt.IsZero() {
		t.Error("the result should carry the replaced database's timestamp so an operator can tell how much newer it was")
	}
	if _, err := os.Stat(res.Replaced); err != nil {
		t.Errorf("the replaced database is not at %s: %v", res.Replaced, err)
	}
	if _, err := os.Lstat(h.dbPath + restoreStagedSuffix); !os.IsNotExist(err) {
		t.Errorf("the staged copy was left behind at %s", h.dbPath+restoreStagedSuffix)
	}

	// The restored database is the snapshot's: one certificate, the old one.
	got := h.certNames(t)
	if len(got) != 1 || got[0] != "old-cert" {
		t.Errorf("after the restore the certificates should be exactly the snapshot's, got %v", got)
	}

	// ... and the displaced file is the newer one, so the restore is reversible.
	moved, err := Open(res.Replaced)
	if err != nil {
		t.Fatalf("the displaced database should still open: %v", err)
	}
	defer moved.Close()
	names, err := moved.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames on the displaced database: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("the displaced database should still hold both certificates, got %v", names)
	}

	// And the record the next start reads exists.
	notice, err := LoadRestoreNotice(h.dbPath)
	if err != nil {
		t.Fatalf("LoadRestoreNotice: %v", err)
	}
	if notice == nil {
		t.Fatal("a successful restore must leave a record for the next start")
	}
	if notice.Source != h.snapshot {
		t.Errorf("the record names %s as the source, want %s", notice.Source, h.snapshot)
	}
	if !notice.CaveatApplies(time.Now()) {
		t.Error("a restore that just happened must still be inside the caveat window")
	}
}

func TestRestoreRefusesWhileAnotherProcessHoldsTheDatabase(t *testing.T) {
	h := newRestoreHarness(t)

	held, err := Open(h.dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer held.Close()

	res, err := Restore(h.dbPath, h.snapshot)
	if err == nil {
		t.Fatal("a restore under a running process must be refused")
	}
	if !strings.Contains(err.Error(), "refusing to replace the state database") {
		t.Errorf("the refusal should say what it refused and why, got: %v", err)
	}
	if res.Replaced != "" {
		t.Errorf("nothing may be moved when the restore is refused, but %s was", res.Replaced)
	}
	if _, err := os.Stat(h.snapshot); err != nil {
		t.Errorf("the snapshot must survive a refused restore: %v", err)
	}

	// The live database is untouched: both certificates are still there.
	names, err := held.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("a refused restore must not change the database, got %v", names)
	}
}

func TestRestoreRefusesTheStateDatabaseItself(t *testing.T) {
	h := newRestoreHarness(t)

	_, err := Restore(h.dbPath, h.dbPath)
	if err == nil {
		t.Fatal("restoring the database over itself must be refused")
	}
	if !strings.Contains(err.Error(), "same file") {
		t.Errorf("the refusal should say the two paths are one file, got: %v", err)
	}
	if got := h.certNames(t); len(got) != 2 {
		t.Errorf("the database changed: %v", got)
	}
}

func TestRestoreRefusesAFileThatIsNotADatabase(t *testing.T) {
	h := newRestoreHarness(t)

	notADB := filepath.Join(h.dir, "notes.txt")
	if err := os.WriteFile(notADB, []byte("this is not a snapshot\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Restore(h.dbPath, notADB)
	if err == nil {
		t.Fatal("restoring a non-database must be refused")
	}
	if !strings.Contains(err.Error(), "not a SQLite database") {
		t.Errorf("the refusal should say the file is not a database, got: %v", err)
	}
	assertNothingWasMoved(t, h)
}

func TestRestoreRefusesAForeignSQLiteDatabase(t *testing.T) {
	h := newRestoreHarness(t)

	// A real SQLite database that simply is not ours. This is the mistake the schema check exists
	// for: a Terraform state file, or another deployment's state.db, opens perfectly well.
	foreign := filepath.Join(h.dir, "terraform.db")
	raw, err := sql.Open("sqlite", sqliteDSN(foreign))
	if err != nil {
		t.Fatalf("open a foreign database: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE resources (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("create the foreign schema: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Restore(h.dbPath, foreign)
	if err == nil {
		t.Fatal("a SQLite database without wecert's tables must be refused by name")
	}
	if !strings.Contains(err.Error(), "not a wecert state snapshot") {
		t.Errorf("the refusal should say the database is not wecert's, got: %v", err)
	}
	assertNothingWasMoved(t, h)
}

func TestRestoreRefusesADamagedSnapshot(t *testing.T) {
	h := newRestoreHarness(t)

	damaged := filepath.Join(h.dir, "damaged.db")
	data, err := os.ReadFile(h.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Zero the SQLite header's page-size and format fields. The 16-byte magic stays intact, so this
	// is exactly the case the magic check cannot catch and SQLite must: a file that looks like a
	// database and is not a usable one.
	for i := 16; i < 100 && i < len(data); i++ {
		data[i] = 0
	}
	if err := os.WriteFile(damaged, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Restore(h.dbPath, damaged)
	if err == nil {
		t.Fatal("a damaged snapshot must be refused")
	}
	assertNothingWasMoved(t, h)
}

func TestRestoreMovesTheWriteAheadLogAsideWithTheDatabase(t *testing.T) {
	h := newRestoreHarness(t)

	// A -wal and -shm belonging to the database that is about to be displaced. If they stayed next
	// to the restored file, the pages in them describe a different database.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(h.dbPath+suffix, []byte("belongs to the old database"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	res, err := Restore(h.dbPath, h.snapshot)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Replaced == "" {
		t.Fatal("the displaced database should have been moved aside")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(h.dbPath + suffix); !os.IsNotExist(err) {
			t.Errorf("%s is still beside the restored database", h.dbPath+suffix)
		}
		body, err := os.ReadFile(res.Replaced + suffix)
		if err != nil {
			t.Errorf("the sidecar %s should have moved with the database: %v", res.Replaced+suffix, err)
			continue
		}
		if string(body) != "belongs to the old database" {
			t.Errorf("%s does not hold the old sidecar's bytes", res.Replaced+suffix)
		}
	}

	// And the restored database is usable, with the snapshot's content.
	if got := h.certNames(t); len(got) != 1 || got[0] != "old-cert" {
		t.Errorf("the restored database should hold the snapshot's certificate, got %v", got)
	}
}

func TestRestoreLeavesTheDatabaseInPlaceWhenTheSnapshotCannotBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unreadable file is readable")
	}
	h := newRestoreHarness(t)

	unreadable := filepath.Join(h.dir, "unreadable.db")
	data, err := os.ReadFile(h.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unreadable, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}

	if _, err := Restore(h.dbPath, unreadable); err == nil {
		t.Fatal("an unreadable snapshot must be refused")
	}
	assertNothingWasMoved(t, h)
}

func TestRestoreRefusesASymlinkedSnapshot(t *testing.T) {
	h := newRestoreHarness(t)

	link := filepath.Join(h.dir, "link.db")
	if err := os.Symlink(h.snapshot, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	_, err := Restore(h.dbPath, link)
	if err == nil {
		t.Fatal("a symlinked snapshot must be refused")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the refusal should say the path is a symlink, got: %v", err)
	}
	assertNothingWasMoved(t, h)
}

// assertNothingWasMoved is the shared assertion for every refused restore: the live database is
// still there, still holds both certificates, and no displaced copy was created.
func assertNothingWasMoved(t *testing.T, h restoreHarness) {
	t.Helper()
	got := h.certNames(t)
	if len(got) != 2 {
		t.Errorf("a refused restore must leave the database exactly as it was, got %v", got)
	}
	matches, err := filepath.Glob(h.dbPath + replacedSuffix + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("a refused restore moved files aside: %v", matches)
	}
	if _, err := os.Lstat(h.dbPath + restoreStagedSuffix); !os.IsNotExist(err) {
		t.Error("a refused restore left a staged copy behind")
	}
}

func TestTheRestoreCaveatExpiresWithTheLongestQuotaWindow(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		restoredAt time.Time
		want       bool
	}{
		{"just restored", now.Add(-time.Minute), true},
		{"six days ago", now.Add(-6 * 24 * time.Hour), true},
		{"inside the window by a minute", now.Add(-(RestoreCaveatWindow - time.Minute)), true},
		{"just past the window", now.Add(-(RestoreCaveatWindow + time.Minute)), false},
		{"a clock that stepped backwards must not silence it", now.Add(time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &RestoreNotice{RestoredAt: tc.restoredAt}
			if got := n.CaveatApplies(now); got != tc.want {
				t.Errorf("CaveatApplies = %v, want %v", got, tc.want)
			}
		})
	}

	var absent *RestoreNotice
	if absent.CaveatApplies(now) {
		t.Error("no record means no caveat")
	}
}

func TestLoadRestoreNoticeDistinguishesAbsentFromUnreadable(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	notice, err := LoadRestoreNotice(dbPath)
	if err != nil || notice != nil {
		t.Fatalf("no marker should be (nil, nil), got (%v, %v)", notice, err)
	}

	// Unreadable is an error, not silence: the caller is about to decide whether the rate-limit
	// ledger may be short, and "I could not tell" must not read as "no".
	if err := os.WriteFile(dbPath+RestoreMarkerSuffix, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRestoreNotice(dbPath); err == nil {
		t.Error("an unreadable restore record must be reported")
	}

	// A record with no timestamp cannot answer the only question it exists for.
	if err := os.WriteFile(dbPath+RestoreMarkerSuffix, []byte(`{"source":"/tmp/x.db"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRestoreNotice(dbPath); err == nil {
		t.Error("a restore record without a timestamp must be reported")
	}
}

// Restoring onto a fresh host is the disaster case, and there the state directory may not exist yet.
func TestRestoreCreatesTheStateDirectory(t *testing.T) {
	h := newRestoreHarness(t)

	fresh := filepath.Join(h.dir, "fresh-host", "lib", "wecert", "state.db")
	res, err := Restore(fresh, h.snapshot)
	if err != nil {
		t.Fatalf("Restore onto a missing directory: %v", err)
	}
	if res.Replaced != "" {
		t.Errorf("there was nothing to replace, got %s", res.Replaced)
	}
	store, err := Open(fresh)
	if err != nil {
		t.Fatalf("Open the restored database: %v", err)
	}
	defer store.Close()
	names, err := store.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	if len(names) != 1 || names[0] != "old-cert" {
		t.Errorf("the restored database should hold the snapshot's certificate, got %v", names)
	}
	if fi, err := os.Stat(filepath.Dir(fresh)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the created state directory should be 0700 (mode %v, err %v)", fi.Mode().Perm(), err)
	}
}

// A symlinked state path is a supported arrangement, and the restore has to work through it: the
// alternative is reporting success while putting the bytes where the daemon will never read them.
func TestRestoreFollowsASymlinkedStatePath(t *testing.T) {
	h := newRestoreHarness(t)

	realDir := filepath.Join(h.dir, "volume")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(realDir, "state.db")
	if err := os.Rename(h.dbPath, realPath); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(h.dir, "state.db")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	res, err := Restore(linkPath, h.snapshot)
	if err != nil {
		t.Fatalf("Restore through a symlink: %v", err)
	}
	// EvalSymlinks canonicalises every component (on macOS /var is itself a symlink to
	// /private/var), so the expectation is the canonical target, not the string that was written.
	canonical, err := filepath.EvalSymlinks(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dest != canonical {
		t.Errorf("the bytes should land on the link's target %s, got %s", canonical, res.Dest)
	}
	if fi, err := os.Lstat(linkPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink must survive the restore (lstat err %v)", err)
	}
	if _, err := os.Stat(res.Replaced); err != nil {
		t.Errorf("the displaced database should sit beside the real file: %v", err)
	}

	// The configured path, followed, is the restored database.
	store, err := Open(linkPath)
	if err != nil {
		t.Fatalf("Open through the link: %v", err)
	}
	defer store.Close()
	names, err := store.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	if len(names) != 1 || names[0] != "old-cert" {
		t.Errorf("the daemon reading through the link must see the snapshot's state, got %v", names)
	}

	// The record is looked up beside the CONFIGURED path, so that is where it has to be.
	notice, err := LoadRestoreNotice(linkPath)
	if err != nil || notice == nil {
		t.Fatalf("the next start looks beside the configured path; notice=%v err=%v", notice, err)
	}
}

// The displaced database is the one file in the directory that holds state nothing else has, so a
// name collision must not silently replace it (os.Rename does).
func TestAFreeReplacedNameNeverPicksAnOccupiedOne(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "state.db")

	first, err := freeReplacedName(dest)
	if err != nil {
		t.Fatalf("freeReplacedName: %v", err)
	}
	if err := os.WriteFile(first, []byte("the only copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := freeReplacedName(dest)
	if err != nil {
		t.Fatalf("freeReplacedName: %v", err)
	}
	if second == first {
		t.Fatalf("freeReplacedName returned the occupied name %s", second)
	}
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatalf("%s is not free (stat err %v)", second, err)
	}
	body, err := os.ReadFile(first)
	if err != nil || string(body) != "the only copy" {
		t.Errorf("the first name's contents changed: %q err=%v", body, err)
	}
}

func TestSnapshotsInListsOneStoresSnapshotsOldestFirst(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	// Two snapshots of state.db, plus the decoys that must not be offered as recovery points: a
	// displaced database from an earlier restore, and another deployment's snapshot.
	for _, name := range []string{
		"state.db.backup-20260101T000000.000Z.db",
		"state.db.backup-20260102T000000.000Z.db",
		"state.db.replaced-20260103T000000.000Z",
		"other.db.backup-20260104T000000.000Z.db",
		"notes.txt",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := SnapshotsIn(dir, dbPath)
	if err != nil {
		t.Fatalf("SnapshotsIn: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected exactly this store's two snapshots, got %v", got)
	}
	if !strings.HasSuffix(got[0], "20260101T000000.000Z.db") {
		t.Errorf("oldest first: got %v", got)
	}
}
