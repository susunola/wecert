package state

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// snapshotStore builds a store with one row worth protecting, in its own directory so the
// "was there a database before" logic and the snapshot listing see only this test's files.
func snapshotStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.PutCert(&CertState{Name: "example-com", KeyPEM: []byte("PRIVATE KEY")}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if err := s.PutAccount(&Account{
		Directory: "https://acme.test/d", KID: "kid-1", PrivateKeyPEM: []byte("ACCOUNT KEY"),
	}); err != nil {
		t.Fatalf("PutAccount: %v", err)
	}
	return s, dir
}

// A snapshot must be a self-contained database, not a copy of the main file.
//
// The store runs in WAL mode, so the bytes on disk are state.db plus a -wal holding
// everything since the last checkpoint. A byte copy of state.db alone can therefore be
// missing the order URL that was just persisted -- which is precisely the loss a backup
// exists to prevent. VACUUM INTO asks SQLite for a consistent logical copy instead.
func TestSnapshotIsASelfContainedDatabase(t *testing.T) {
	s, dir := snapshotStore(t)

	// A fresh row that is almost certainly still in the WAL rather than checkpointed.
	if err := s.PutOrder(&Order{
		CertName: "example-com", OrderURL: "https://acme.test/order/just-written", Status: "pending",
	}); err != nil {
		t.Fatalf("PutOrder: %v", err)
	}

	backups := filepath.Join(dir, "backups")
	path, err := s.Snapshot(backups, 3)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Open the snapshot on its own: it must not need the live -wal to be readable.
	snap, err := Open(path)
	if err != nil {
		t.Fatalf("the snapshot is not a usable database on its own: %v", err)
	}
	defer snap.Close()

	o, err := snap.GetOrder("example-com")
	if err != nil {
		t.Fatalf("GetOrder from snapshot: %v", err)
	}
	if o == nil || o.OrderURL != "https://acme.test/order/just-written" {
		t.Errorf("the snapshot is missing the order committed just before it: %+v", o)
	}
	c, err := snap.GetCert("example-com")
	if err != nil {
		t.Fatalf("GetCert from snapshot: %v", err)
	}
	if c == nil || string(c.KeyPEM) != "PRIVATE KEY" {
		t.Errorf("the snapshot is missing the certificate key: %+v", c)
	}
}

// The snapshot holds the ACME account key and every certificate private key, so it must be
// 0600. SQLite creates the destination with the process umask (0644 on a default machine),
// which is exactly the leak the state file itself was fixed for.
func TestSnapshotIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX permission assertions on Windows")
	}

	old := setUmask(0)
	defer setUmask(old)

	s, dir := snapshotStore(t)
	path, err := s.Snapshot(filepath.Join(dir, "backups"), 3)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("snapshot has mode %o: group/other can read the private keys (want 0600)", perm)
	}
}

// Retention must bound the directory, newest first.
func TestSnapshotPrunesToKeep(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")

	for i := 0; i < 5; i++ {
		if _, err := s.Snapshot(backups, 2); err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
	}

	names, err := s.Snapshots(backups)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Errorf("kept %d snapshots, want 2: %v", len(names), names)
	}
	// The survivors must be usable, not empty husks.
	for _, n := range names {
		info, err := os.Stat(n)
		if err != nil {
			t.Fatalf("stat %s: %v", n, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", n)
		}
	}
}

// Snapshots written in the same second must not clobber one another: a duplicate timestamp
// is not worth losing a backup over.
func TestSnapshotWithADuplicateTimestampKeepsBoth(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")

	first, err := s.Snapshot(backups, 5)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Snapshot(backups, 5)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("the second snapshot reused the first path %s, overwriting it", first)
	}
	names, err := s.Snapshots(backups)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Errorf("kept %d snapshots, want both: %v", len(names), names)
	}
}

// A failing snapshot must not leave a temporary or half-written file behind: a broken file
// in the backup directory that looks like a backup is worse than no backup at all.
func TestSnapshotLeavesNoLitterOnFailure(t *testing.T) {
	s, dir := snapshotStore(t)

	// A directory path that cannot be created as a directory, because a file is in the way.
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(filepath.Join(blocked, "sub"), 3); err == nil {
		t.Fatal("expected the snapshot to fail when its directory cannot be created")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".snapshot-") {
			t.Errorf("a temporary snapshot file was left behind: %s", e.Name())
		}
	}
}

// Snapshot must be usable on an empty database too: the first snapshot of a fresh
// deployment is what makes the case "the database was created and then lost" recoverable.
func TestSnapshotOnAFreshDatabase(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	path, err := s.Snapshot(filepath.Join(dir, "backups"), 1)
	if err != nil {
		t.Fatalf("Snapshot on a fresh database: %v", err)
	}
	snap, err := Open(path)
	if err != nil {
		t.Fatalf("the fresh snapshot is not usable: %v", err)
	}
	defer snap.Close()
	// The schema must be there, or restoring it would not give a working store.
	if _, err := snap.ListCertNames(); err != nil {
		t.Errorf("the snapshot has no usable schema: %v", err)
	}
}

// A read-only destination must fail the snapshot cleanly, leaving no temporary file behind.
//
// A half-written file in the backup directory is worse than no backup: it has the shape and the
// name of a snapshot, and the moment someone reaches for it is the moment they need it to work.
func TestSnapshotReportsAReadOnlyDestination(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions, so the failure cannot be provoked")
	}

	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "readonly")
	if err := os.Mkdir(backups, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(backups, 0o755) })

	path, err := s.Snapshot(backups, 3)
	if err == nil {
		t.Fatalf("a read-only destination must fail the snapshot, got %q", path)
	}
	// The error must say where the problem is, not just "permission denied".
	if !strings.Contains(err.Error(), backups) {
		t.Errorf("the error should name the directory, got: %v", err)
	}
	if path != "" {
		t.Errorf("no path should be reported on failure, got %q", path)
	}

	entries, readErr := os.ReadDir(backups)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a failed snapshot left %v behind", names)
	}
}

// A snapshot must still work when a previous one exists and retention is 1: pruning happens after
// the new file is in place, so a bug there would either delete the new snapshot or keep all of
// them forever.
func TestSnapshotRetentionOfOneKeepsTheNewest(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")

	var paths []string
	for i := 0; i < 3; i++ {
		p, err := s.Snapshot(backups, 1)
		if err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
		paths = append(paths, p)
	}

	names, err := s.Snapshots(backups)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 {
		t.Fatalf("kept %d snapshots with keep=1: %v", len(names), names)
	}
	if names[0] != paths[len(paths)-1] {
		t.Errorf("kept %q, want the newest (%q)", names[0], paths[len(paths)-1])
	}
	// And the survivor must be usable.
	snap, err := Open(names[0])
	if err != nil {
		t.Fatalf("the newest snapshot is not usable: %v", err)
	}
	defer snap.Close()
	if _, err := snap.ListCertNames(); err != nil {
		t.Errorf("the surviving snapshot has no usable schema: %v", err)
	}
}

// An unwritable state directory must fail at Open with a message about the path, not a SQLite
// error: the operator needs to know which directory to fix.
func TestOpenReportsAnUnwritableStateDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions, so the failure cannot be provoked")
	}

	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	_, err := Open(filepath.Join(locked, "state.db"))
	if err == nil {
		t.Fatal("an unwritable state directory must fail Open")
	}
	if !strings.Contains(err.Error(), locked) {
		t.Errorf("the error should name the directory, got: %v", err)
	}
}

// Two deployments sharing one backup directory must not delete each other's snapshots.
//
// Nothing refuses a shared stateBackup.dir -- it is a reasonable thing to configure, and the
// config layer cannot see who else writes there -- so the snapshot name has to carry the
// identity of the store that wrote it. It used to hardcode "state", which meant the two
// stores produced byte-identical filenames and each one's retention pruned the other's
// backups: the survivor was whichever happened to run last.
func TestSnapshotsOfTwoStoresInOneDirectoryDoNotCollide(t *testing.T) {
	dir := t.TempDir()
	backups := filepath.Join(dir, "backups")

	open := func(name string) *Store {
		t.Helper()
		s, err := Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("Open(%s): %v", name, err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := s.PutCert(&CertState{Name: "example-com", KeyPEM: []byte("KEY")}); err != nil {
			t.Fatalf("PutCert: %v", err)
		}
		return s
	}

	first := open("state.db")
	second := open("other.db")

	// keep=1 each: with a shared name, the second store's prune deletes the first's only
	// snapshot.
	firstPath, err := first.Snapshot(backups, 1)
	if err != nil {
		t.Fatalf("first Snapshot: %v", err)
	}
	secondPath, err := second.Snapshot(backups, 1)
	if err != nil {
		t.Fatalf("second Snapshot: %v", err)
	}

	if firstPath == secondPath {
		t.Fatalf("both stores wrote the same snapshot path %s; their retention will delete each other's backups", firstPath)
	}
	for _, p := range []string{firstPath, secondPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("snapshot %s was removed by the other store's retention: %v", p, err)
		}
	}

	firstSeen, err := first.Snapshots(backups)
	if err != nil {
		t.Fatalf("first Snapshots: %v", err)
	}
	if len(firstSeen) != 1 || firstSeen[0] != firstPath {
		t.Errorf("the first store must only ever see its own snapshots, got %v", firstSeen)
	}
	secondSeen, err := second.Snapshots(backups)
	if err != nil {
		t.Fatalf("second Snapshots: %v", err)
	}
	if len(secondSeen) != 1 || secondSeen[0] != secondPath {
		t.Errorf("the second store must only ever see its own snapshots, got %v", secondSeen)
	}
}

// A file wecert did not write must never be counted as a snapshot, because counting it means
// pruning it.
//
// The matcher used to be "the name contains .backup- and ends in .db". An operator keeping
// state.backup-before-upgrade.db in the same directory then had their own copy deleted --
// it sorts before every real timestamp and pruning removes from the front -- while the
// genuine newest snapshot was evicted in the same pass.
func TestForeignFilesInTheBackupDirectoryAreLeftAlone(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	foreign := filepath.Join(backups, "state.backup-before-upgrade.db")
	if err := os.WriteFile(foreign, []byte("an operator's own copy"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// A file for a DIFFERENT store in the same directory is also not ours to prune.
	otherStore := filepath.Join(backups, "other.db.backup-20200101T000000.000Z.db")
	if err := os.WriteFile(otherStore, []byte("someone else's snapshot"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := s.Snapshot(backups, 1); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	for _, p := range []string{foreign, otherStore} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was pruned as though it were one of our snapshots: %v", filepath.Base(p), err)
		}
	}

	seen, err := s.Snapshots(backups)
	if err != nil {
		t.Fatalf("Snapshots: %v", err)
	}
	if len(seen) != 1 {
		t.Errorf("only our own snapshots may be listed, got %v", seen)
	}
}

// The snapshot must be CREATED with restrictive permissions, not tightened after the fact.
//
// The file is a logical copy of the ACME account key and every certificate private key, and SQLite
// creates it with the process umask -- 0644 on a default system. Chmod'ing afterwards leaves a
// window any local user can read through, and a crash inside the window leaves a world-readable
// `.snapshot-*.tmp` behind that nothing revisits: the listing matches only the final
// `<base>.backup-<stamp>.db` names. Asserting the final mode cannot see the difference (the chmod
// is a backstop), so the mode is observed at the moment the copy lands.
func TestSnapshotIsBornWithRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX permission assertions on Windows")
	}

	old := setUmask(0)
	defer setUmask(old)

	saved := snapshotCopied
	var modeAtCopy os.FileMode
	var statErr error
	snapshotCopied = func(path string) {
		info, err := os.Stat(path)
		if err != nil {
			statErr = err
			return
		}
		modeAtCopy = info.Mode().Perm()
	}
	defer func() { snapshotCopied = saved }()

	s, dir := snapshotStore(t)
	if _, err := s.Snapshot(filepath.Join(dir, "backups"), 3); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if statErr != nil {
		t.Fatalf("the snapshot was not readable when the copy landed: %v", statErr)
	}
	if modeAtCopy&0o077 != 0 {
		t.Errorf("the snapshot was created with mode %o (umask 0): group and other can read every "+
			"private key for the whole duration of the copy, and a crash in that window leaves a "+
			"world-readable temp file nothing ever cleans up (want 0600 from the start)", modeAtCopy)
	}
}

// A same-millisecond collision must sort AFTER the name it collides with.
//
// Retention prunes from the front of a lexicographic sort, so the collision suffix has to be
// greater than '.': with "<stamp>-1.db" ('-' is 0x2D, '.' is 0x2E) the suffixed file sorted first
// and keep=1 deleted the NEWER snapshot while keeping the older one -- the opposite of what the
// code comment claimed, and the very failure the pid suffix had been blamed for.
func TestACollisionSnapshotSortsLastAndStillCountsAsOurs(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")

	first, err := s.Snapshot(backups, 3)
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	stamp, ok := s.snapshotStampOf(filepath.Base(first))
	if !ok {
		t.Fatalf("%s is not recognised as a snapshot of this store", filepath.Base(first))
	}

	// The name a collision produces, and the ordering property retention depends on.
	collision := s.snapshotName(stamp + "~1")
	if !(collision > filepath.Base(first)) {
		t.Errorf("the collision name %q must sort after %q, or pruning keeps the older snapshot",
			collision, filepath.Base(first))
	}
	if _, ok := s.snapshotStampOf(collision); !ok {
		t.Errorf("%q must still count as a snapshot of this store, or retention never prunes it",
			collision)
	}
	// The separator this used before must keep being recognised, or snapshots written by an older
	// build stay on disk forever.
	if _, ok := s.snapshotStampOf(s.snapshotName(stamp + "-1")); !ok {
		t.Error("the old '-' collision suffix must keep counting as a snapshot")
	}
}

// Retiring a certificate restarts the retention clock.
//
// The orphan path records a certificate that was merely uploaded (no material) so the reaper can
// delete it; the retirement path later records the same cert_id WITH the fullchain and key, which is
// the material docs/recovery.md's manual rollback needs. The upsert refreshed the material but not
// retired_at, so the row was reaped on the orphan's clock: the cloud copy and the just-archived
// rollback material went away as soon as the earlier window expired.
func TestRetiringACertificateRestartsTheRetentionClock(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// The orphan write: no material, and an old timestamp.
	if err := store.AddRetiredCert("cert-1", "site", nil, nil); err != nil {
		t.Fatal(err)
	}
	orphanAt := time.Now().Add(-6 * 24 * time.Hour)
	if _, err := store.db.Exec(`UPDATE retired_certificates SET retired_at = ? WHERE cert_id = ?`,
		orphanAt.Unix(), "cert-1"); err != nil {
		t.Fatal(err)
	}

	// The retirement write: real material, now.
	if err := store.AddRetiredCert("cert-1", "site", []byte("fullchain"), []byte("key")); err != nil {
		t.Fatal(err)
	}

	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 {
		t.Fatalf("expected one retired row, got %+v", retired)
	}
	if !retired[0].RetiredAt.After(orphanAt.Add(time.Hour)) {
		t.Errorf("retired_at is still the orphan's timestamp (%v): retention would reap this row -- "+
			"cloud copy and archived key material included -- on the earlier clock, not from the "+
			"retirement", retired[0].RetiredAt)
	}
	if string(retired[0].CertPEM) != "fullchain" {
		t.Errorf("the archived material must survive the upsert, got %q", retired[0].CertPEM)
	}
}
