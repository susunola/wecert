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

// A collision probe that cannot answer must be reported, not treated as "taken".
//
// The suffix loop exists for the millisecond collision, and it used to treat ANY Stat failure as
// "this name is taken". "Unknown" is not "taken": every candidate suffix fails the same way, so the
// loop spins forever -- a directory that lost its search permission, an unreachable mount, a
// symlink loop -- burning a core in the backup goroutine while no snapshot is ever written and
// nothing is logged. This is the same failure mode, one layer down, as reading an unreadable quota
// as zero: a failed read must not be turned into an answer.
func TestAnUnanswerableCollisionProbeIsReported(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	const stamp = "20260101T000000.000Z"

	// A free name is used as-is.
	name, err := s.freeSnapshotName(backups, stamp)
	if err != nil {
		t.Fatalf("a free directory must produce a name: %v", err)
	}
	if want := filepath.Join(backups, s.snapshotName(stamp)); name != want {
		t.Errorf("name = %s, want the unsuffixed %s", name, want)
	}

	// A real collision advances to the next suffix, which still sorts after it.
	if err := os.WriteFile(name, []byte("existing snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := s.freeSnapshotName(backups, stamp)
	if err != nil {
		t.Fatalf("a collision must produce the next free name: %v", err)
	}
	if next == name {
		t.Fatalf("the occupied name %s must not be handed out again: the snapshot would overwrite "+
			"an existing one", name)
	}
	if !(filepath.Base(next) > filepath.Base(name)) {
		t.Errorf("the collision name %q must sort after %q, or retention keeps the older snapshot",
			filepath.Base(next), filepath.Base(name))
	}

	// Now make the probe itself unanswerable: a symlink pointing at itself fails with ELOOP,
	// which is neither "free" nor "taken".
	loop := filepath.Join(backups, s.snapshotName("20260102T000000.000Z"))
	if err := os.Symlink(filepath.Base(loop), loop); err != nil {
		t.Skipf("this filesystem cannot create a symlink loop: %v", err)
	}
	if got, err := s.freeSnapshotName(backups, "20260102T000000.000Z"); err == nil {
		t.Errorf("a probe that cannot answer must be reported, not silently worked around; got %q. "+
			"Treating it as \"taken\" spins the suffix loop forever when every candidate fails the "+
			"same way", got)
	}
}

// A backward clock step must not make retention delete the snapshot it just wrote.
//
// Snapshot names are wall-clock stamps and pruning deletes from the front of a lexicographic sort,
// which is "oldest first" only while the clock moves forwards. After an NTP correction, a VM resumed
// from a snapshot, or a backup directory restored from a host whose clock was ahead, the file just
// written carries the newest CONTENT and the oldest NAME -- so the old code deleted exactly that
// file, logged a fresh snapshot at a path that no longer existed, and left the recovery point stuck
// on an older copy without saying so.
func TestPruningKeepsTheSnapshotItJustWroteWhenTheClockWentBackwards(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}

	// A snapshot from "before" the clock stepped backwards: its name sorts after anything this
	// process will write now.
	future := filepath.Join(backups, s.snapshotName(time.Now().UTC().Add(time.Hour).Format(snapshotStamp)))
	if err := os.WriteFile(future, []byte("older content, later name"), 0o600); err != nil {
		t.Fatal(err)
	}

	path, err := s.Snapshot(backups, 1)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the snapshot this call just wrote was deleted by its own pruning: %v", err)
	}
	if _, err := os.Stat(future); !os.IsNotExist(err) {
		t.Errorf("retention still has to hold at keep=1, so the other snapshot must be the victim, "+
			"got stat err %v", err)
	}
	left, err := s.Snapshots(backups)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Errorf("keep=1 must leave one snapshot, got %d: %v", len(left), left)
	}
}

// An empty database is not worth snapshotting, and the daemon must not treat it as one.
//
// This is what the daemon gates on before writing a snapshot. Without it, after the documented
// state.db loss every restart wrote a snapshot of the empty replacement and retention evicted a
// genuine backup -- three restarts with keep=3 destroyed all three.
func TestHasRecoverableStateTracksWhatASnapshotCouldRecover(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if has, err := s.HasRecoverableState(); err != nil || has {
		t.Fatalf("a freshly created database holds nothing to recover: has=%v err=%v", has, err)
	}

	// Rate buckets and failure counters are not recovery material: losing them costs
	// rate-limit knowledge, not a certificate.
	if err := s.PutRateBucket(&RateBucket{
		LimitName: "new-orders", ScopeID: "acct", Tokens: 1, ObservedAt: time.Now(),
	}); err != nil {
		t.Fatalf("PutRateBucket: %v", err)
	}
	if has, err := s.HasRecoverableState(); err != nil || has {
		t.Errorf("rate-limit bookkeeping is not a recovery point: has=%v err=%v", has, err)
	}

	if err := s.PutCert(&CertState{Name: "example-com", KeyPEM: []byte("PRIVATE KEY")}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if has, err := s.HasRecoverableState(); err != nil || !has {
		t.Errorf("a stored certificate is exactly what a snapshot exists for: has=%v err=%v", has, err)
	}
}

// A snapshot named in the future must not hold a retention slot forever.
//
// Names are wall-clock stamps and retention keeps the newest, so one forward clock excursion writes
// a file that sorts after every honest stamp and is therefore never pruned again: with keep=3 the
// deployment kept only two genuine recovery points and deleted the oldest fresh one every round.
// The file's contents are fine, so it is renamed to when it was actually written.
func TestAFutureDatedSnapshotIsAgedRatherThanKeptForever(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}

	// Two honest snapshots and one from "the future".
	for _, d := range []time.Duration{-2 * time.Hour, -time.Hour} {
		if _, err := s.Snapshot(backups, 10); err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		_ = d
	}
	future := filepath.Join(backups, s.snapshotName(time.Now().UTC().Add(48*time.Hour).Format(snapshotStamp)))
	if err := os.WriteFile(future, []byte("snapshot from a host whose clock was ahead"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Snapshot(backups, 3); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	left, err := s.Snapshots(backups)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 3 {
		t.Fatalf("keep=3 must leave three snapshots, got %d: %v", len(left), left)
	}
	for _, name := range left {
		stamp, ok := s.snapshotStampOf(filepath.Base(name))
		if !ok {
			t.Fatalf("unexpected file in the snapshot list: %s", name)
		}
		at, err := time.Parse(snapshotStamp, stamp)
		if err != nil {
			t.Fatal(err)
		}
		if at.After(time.Now().Add(time.Minute)) {
			t.Errorf("a future-dated name survived: %s. It sorts after every honest stamp, so "+
				"retention can never pick it and one recovery point is lost for good", filepath.Base(name))
		}
	}
}

// One undeletable snapshot must not stop pruning the rest.
//
// Returning on the first os.Remove failure meant a single immutable snapshot (chattr +i, an ACL, a
// read-only attribute -- ransomware hardening an operator may well have applied) stalled pruning for
// the life of the directory: the backup directory grew by one file per interval while every round
// reported the same error against the same oldest name.
func TestPruningAttemptsEveryVictim(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	for i := 0; i < 4; i++ {
		if _, err := s.Snapshot(backups, 10); err != nil {
			t.Fatalf("Snapshot %d: %v", i, err)
		}
	}

	// The oldest snapshot cannot be removed; the next two must still go.
	saved := removeSnapshotFile
	t.Cleanup(func() { removeSnapshotFile = saved })
	blocked := ""
	removeSnapshotFile = func(name string) error {
		if blocked == "" {
			blocked = name
			return os.ErrPermission
		}
		return os.Remove(name)
	}

	if _, err := s.Snapshot(backups, 2); err == nil {
		t.Error("the failure has to be reported: the operator needs to know a snapshot could not be " +
			"removed and the directory will grow")
	}
	removeSnapshotFile = saved

	left, err := s.Snapshots(backups)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 3 {
		t.Errorf("keep=2 with one undeletable snapshot must leave 3 files (the two newest plus the "+
			"one that cannot go), got %d: %v", len(left), left)
	}
	if blocked == "" {
		t.Fatal("the fixture never blocked a removal, so this test proves nothing")
	}
	found := false
	for _, name := range left {
		if name == blocked {
			found = true
		}
	}
	if !found {
		t.Errorf("the undeletable snapshot must still be there, got %v", left)
	}
}

// A stale temporary snapshot is swept; a fresh one is left alone.
//
// A crash between VACUUM INTO and the rename leaves a partial copy under a `.snapshot-*.tmp` name
// that nothing else revisits. The sweep is age-based so it can never delete a write in progress.
func TestStaleSnapshotTempsAreSweptAndFreshOnesKept(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}

	stale := filepath.Join(backups, ".snapshot-state.db-20200101T000000.000-0.tmp")
	fresh := filepath.Join(backups, ".snapshot-state.db-29990101T000000.000-0.tmp")
	journal := stale + "-journal"
	for _, p := range []string{stale, fresh, journal} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Snapshot(backups, 3); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Both of THIS store's temps go, whatever their age -- and with no age threshold.
	//
	// An earlier version of this test kept the fresh one because "a write may be in progress". That
	// cannot be true here: the sweep runs inside Snapshot, which holds the store mutex (so no second
	// snapshot of this database can be in flight in this process) and the cross-process lock on this
	// state path (so no other process can be writing one either). Leaving the fresh file alone was
	// therefore not caution, it was junk: the round-11 crash-fault verification killed the daemon
	// mid-copy and found the partial temp AND its `-journal` still sitting in the state directory
	// after the next start had already taken a clean snapshot.
	for _, p := range []string{stale, fresh} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("this store's own leftover temp must be swept, %s: stat err %v", filepath.Base(p), err)
		}
	}
	// The journal SQLite writes beside a VACUUM INTO target is part of the same leftover, and it
	// never matched the old ".tmp" suffix test.
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Errorf("the temp's -journal must be swept with it, stat err %v", err)
	}
}

// A temp file this store cannot attribute is left alone while it could be live, and swept once it
// cannot be: no base in the name means another deployment sharing the directory (deleting its
// in-flight snapshot is the failure the prefix exists to prevent) or a file from before the prefix
// carried the base, and the hour is far longer than any snapshot takes.
func TestForeignSnapshotTempsAreSweptOnlyWhenOld(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}

	foreign := filepath.Join(backups, ".snapshot-other.db-20200101T000000.000-0.tmp")
	legacy := filepath.Join(backups, ".snapshot-20200101T000000.000-0.tmp")
	for _, p := range []string{foreign, legacy} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-3 * time.Hour)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.Snapshot(backups, 3); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for _, p := range []string{foreign, legacy} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is stale by an hour and belongs to no live writer; it must be swept, stat err %v",
				filepath.Base(p), err)
		}
	}

	// A FRESH foreign temp is left alone: another deployment may be writing it right now.
	freshForeign := filepath.Join(backups, ".snapshot-other.db-29990101T000000.000-0.tmp")
	if err := os.WriteFile(freshForeign, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(backups, 3); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := os.Stat(freshForeign); err != nil {
		t.Errorf("a fresh temp that may belong to another deployment's live write must be left alone: %v", err)
	}
}

// The sweep must not touch another store's temporary files, however stale they are.
//
// Nothing refuses a shared backup directory, and temp names that carried no store identity made
// this sweep match every deployment's in-progress or crashed writes: one store's interval pass
// deleted the other's partial snapshot. Temp names now carry the store's base, like the final
// snapshot names, and the sweep matches only its own.
func TestTheSweepLeavesAnotherStoresTempsAlone(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}

	// A temp file whose owner cannot be established: another deployment sharing the directory, or a
	// file from before the name carried the base.
	foreign := filepath.Join(backups, ".snapshot-other.db-20200101T000000.000-0.tmp")
	legacy := filepath.Join(backups, ".snapshot-20200101T000000.000-0.tmp")
	freshForeign := filepath.Join(backups, ".snapshot-other.db-29990101T000000.000-0.tmp")
	for _, p := range []string{foreign, legacy, freshForeign} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-3 * time.Hour)
	for _, p := range []string{foreign, legacy} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.Snapshot(backups, 3); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// The FRESH one may be another deployment's live write, so it is never touched -- that is the
	// property the prefix exists for, and it is what this test guard against.
	if _, err := os.Stat(freshForeign); err != nil {
		t.Errorf("a fresh temp that may belong to another deployment's live write must be left alone: %v", err)
	}

	// The three-hour-old ones are swept. This used to say "nobody may delete them", and the reasoning
	// was that the age check exists for OUR crashed writes -- but then nothing ever removes them: a
	// pre-base leftover holds a partial copy of a private-key database for the rest of the host's
	// life, and there is no process left that could still be writing it (an hour is far longer than
	// any snapshot takes, which is what the threshold meant in the first place, before the crash-fault
	// verification showed that for OUR OWN files the lock is the stronger proof and the age rule was
	// only leaving the partial copy behind for an hour).
	for _, p := range []string{foreign, legacy} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is unattributable but hours old, so no live writer can hold it and it must be swept: %v",
				filepath.Base(p), err)
		}
	}
}

// The temporary name must carry the store's identity, like the final snapshot name.
//
// Two deployments sharing one backup directory pick trial names under the same prefix otherwise,
// and a sweep on one side cannot tell its own crashed writes from the other's in-progress ones.
func TestSnapshotTempNamesCarryTheStoresBase(t *testing.T) {
	s, _ := snapshotStore(t)
	dir := t.TempDir()

	name, err := s.freeTempName(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := s.snapshotTempPrefix(); !strings.HasPrefix(filepath.Base(name), want) {
		t.Errorf("temp name %q does not start with the store-scoped prefix %q: two stores sharing "+
			"this directory could collide, and the sweep would clean the other deployment's "+
			"in-progress write", filepath.Base(name), want)
	}
}

// A repaired (renamed) future-dated snapshot must be made durable with a directory fsync.
//
// rename(2) updates the directory's own block, and without the sync a power cut can resurrect the
// future-dated name -- silently undoing the repair. The fsync itself leaves no trace a test can
// stat for, so the hook next to it is what proves the step runs.
func TestRepairedSnapshotsAreMadeDurable(t *testing.T) {
	s, dir := snapshotStore(t)
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}

	future := filepath.Join(backups, s.snapshotName(time.Now().UTC().Add(48*time.Hour).Format(snapshotStamp)))
	if err := os.WriteFile(future, []byte("snapshot from a host whose clock was ahead"), 0o600); err != nil {
		t.Fatal(err)
	}

	saved := repairDirSynced
	synced := ""
	repairDirSynced = func(d string) { synced = d }
	defer func() { repairDirSynced = saved }()

	if _, err := s.Snapshot(backups, 3); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if synced != backups {
		t.Errorf("the repair rename was not followed by a directory fsync of %q (hook saw %q): a "+
			"power cut here resurrects the future-dated name, and retention never prunes it again",
			backups, synced)
	}
	if _, err := os.Stat(future); !os.IsNotExist(err) {
		t.Errorf("the future-dated name must be gone after the repair, stat err %v", err)
	}
}
