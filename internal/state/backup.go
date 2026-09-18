package state

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// defaultBackupKeep is the fallback when a caller passes a non-positive keep. The
// policy itself lives in internal/config (the lower layer); this is only so Snapshot is
// usable without one.
const defaultBackupKeep = 7

// backupSuffix marks a snapshot file. The state file's own name is part of the snapshot
// name (see Store.base) so several deployments sharing a directory cannot collide.
const backupSuffix = ".backup-"

// snapshotStamp is the timestamp layout in a snapshot name. Fixed width and zero padded, so
// lexicographic order is chronological order.
const snapshotStamp = "20060102T150405.000Z"

// snapshotCopied runs after the copy lands and before its permissions are tightened. Tests use it
// to observe the mode the copy was CREATED with: the chmod that follows makes the window invisible
// to any assertion made after Snapshot returns, so without this hook the umask above could be
// dropped without a test noticing.
var snapshotCopied = func(string) {}

// Snapshot writes a consistent copy of the state database, and prunes older snapshots.
//
// Why VACUUM INTO rather than copying the file: the database runs in WAL mode, so the
// bytes on disk are the *main* file plus a -wal that has not been checkpointed. Copying
// state.db alone can therefore miss everything committed since the last checkpoint --
// including a just-persisted order URL, which is exactly what makes restore dangerous.
// VACUUM INTO asks SQLite for a consistent logical copy, so the result is a single
// self-contained database with no sidecars to keep in step.
//
// It returns the path written, so a caller can log it.
func (s *Store) Snapshot(dir string, keep int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if dir == "" {
		return "", fmt.Errorf("snapshot: no directory configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup dir %s: %w", dir, err)
	}
	if keep <= 0 {
		keep = defaultBackupKeep
	}

	// Millisecond precision, zero padded. The suffix used to be "-<pid>", which sorts BEFORE the
	// bare timestamp: "state.backup-STAMP-1234.db" < "state.backup-STAMP.db" because '-' < '.'.
	// Since listing is lexicographic and pruning removes from the front, two snapshots in the same
	// second meant keep=1 deleted the NEWER one and kept the older -- silently, and only under
	// load, which is exactly when a fresh snapshot matters.
	stamp := time.Now().UTC().Format(snapshotStamp)

	// VACUUM INTO refuses to overwrite, and creating the file itself would be the wrong
	// way to get the 0600 mode: the driver creates it 0644 (the process umask), and this
	// file holds the ACME account key and every certificate private key. Write to a
	// private temp name, tighten it, then rename into place.
	tmp, err := os.CreateTemp(dir, ".snapshot-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create snapshot temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("close snapshot temp file: %w", err)
	}
	// VACUUM INTO needs a path that does not exist yet.
	if err := os.Remove(tmpName); err != nil {
		return "", fmt.Errorf("clear snapshot temp file %s: %w", tmpName, err)
	}

	defer func() {
		// Every failure path must clean up, or a broken snapshot accumulates on disk
		// looking like a usable backup.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	// Two snapshots can still collide at millisecond precision; the collision name has to sort
	// after the unsuffixed one, which freeSnapshotName explains.
	final, err := s.freeSnapshotName(dir, stamp)
	if err != nil {
		return "", err
	}

	// The copy is born under a restrictive umask, not tightened afterwards.
	//
	// Open() does the same for the database it migrates (see restrictiveUmask in state.go) for the
	// same reason: this file is a logical copy of the ACME account key and every certificate private
	// key, and the driver creates it with the process umask -- 0644 on a default system. Chmod after
	// the copy left a window in which any local user could read it, and a crash inside that window
	// left behind a world-readable `.snapshot-*.tmp` that nothing ever revisits (listing matches
	// only the final `<base>.backup-<stamp>.db` names). The chmod stays as the backstop for a file
	// that already existed.
	restoreUmask := restrictiveUmask()
	_, execErr := s.db.Exec(`VACUUM INTO ?`, tmpName)
	restoreUmask()
	snapshotCopied(tmpName)
	if execErr != nil {
		return "", fmt.Errorf("snapshot state database: %w", execErr)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return "", fmt.Errorf("tighten snapshot permissions: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return "", fmt.Errorf("install snapshot %s: %w", final, err)
	}
	// Verify the rename landed before pruning, so a failure here cannot leave us with
	// fewer snapshots than before.
	if _, err := os.Stat(final); err != nil {
		return "", fmt.Errorf("snapshot %s is missing after rename: %w", final, err)
	}

	if err := s.pruneSnapshots(dir, keep, final); err != nil {
		// The snapshot itself succeeded; failing to prune is worth reporting but must not
		// be reported as a failed snapshot.
		return final, fmt.Errorf("snapshot written to %s, but pruning old snapshots failed: %w", final, err)
	}
	return final, nil
}

// freeSnapshotName returns the first snapshot name under dir that is free for this stamp.
//
// The suffix has to sort AFTER the unsuffixed name or retention keeps the wrong one: pruning
// deletes from the front of a lexicographic sort, so "<stamp>-1.db" ('-' is 0x2D) sorted BEFORE
// "<stamp>.db" ('.' is 0x2E) and keep=1 deleted the newer snapshot while the comment claimed the
// opposite. "~" is 0x7E.
func (s *Store) freeSnapshotName(dir, stamp string) (string, error) {
	final := filepath.Join(dir, s.snapshotName(stamp))
	for n := 1; ; n++ {
		_, statErr := os.Stat(final)
		if statErr == nil {
			// Taken. Try the next suffix.
			final = filepath.Join(dir, s.snapshotName(fmt.Sprintf("%s~%d", stamp, n)))
			continue
		}
		// Any other failure leaves the name's state UNKNOWN, and "unknown" must not be read as
		// "taken": every candidate suffix fails the same way, so the loop would spin here forever
		// -- a directory that lost its search permission, an unreachable mount, a symlink loop --
		// burning a core in the backup goroutine while no snapshot is ever written. Reporting it
		// skips this round, which the caller logs, and the next round tries again.
		if !os.IsNotExist(statErr) {
			return "", fmt.Errorf("cannot tell whether snapshot %s already exists: %w", final, statErr)
		}
		return final, nil
	}
}

// snapshotName builds the filename for one snapshot of this store.
func (s *Store) snapshotName(stamp string) string {
	return s.base + backupSuffix + stamp + ".db"
}

// snapshotStampOf returns the timestamp part of a snapshot filename belonging to this store,
// and whether the name is one at all.
//
// The test is deliberately strict -- exact prefix, exact layout, exact suffix -- rather than
// "contains .backup- and ends in .db". A loose matcher counts files wecert never wrote as
// snapshots and then prunes them, and because it prunes from the front of a lexicographic
// sort, a hand-made name like state.backup-before-upgrade.db sorts before every real
// timestamp and is deleted first -- evicting the genuine newest snapshot and destroying the
// operator's own copy at the same time.
func (s *Store) snapshotStampOf(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, s.base+backupSuffix)
	if !ok {
		return "", false
	}
	rest, ok = strings.CutSuffix(rest, ".db")
	if !ok {
		return "", false
	}
	// A collision suffix ("<stamp>~2") is not part of the timestamp. The '-' form is still
	// accepted: snapshots written before the separator changed must keep counting as ours, or
	// retention stops seeing them and they stay on disk forever.
	if i := strings.IndexByte(rest, '~'); i >= 0 {
		rest = rest[:i]
	} else if i := strings.IndexByte(rest, '-'); i >= 0 {
		rest = rest[:i]
	}
	if _, err := time.Parse(snapshotStamp, rest); err != nil {
		return "", false
	}
	return rest, true
}

// listSnapshots returns this store's snapshot files in dir, oldest first.
func (s *Store) listSnapshots(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := s.snapshotStampOf(e.Name()); !ok {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	// The timestamp in the name is fixed width and zero padded, so a plain sort is
	// oldest-first.
	sort.Strings(out)
	return out, nil
}

// pruneSnapshots keeps the newest `keep` snapshots and removes the rest, never removing protect
// (the snapshot this call just wrote).
//
// Names are wall-clock stamps, so name order and content order agree only while the clock moves
// forwards. After a backward step -- an NTP correction, a VM resumed from a snapshot, a backup
// directory restored from a host whose clock was ahead -- the file just written has the newest
// CONTENT and the OLDEST name, and "delete from the front" removed exactly that file: the caller
// logged a fresh snapshot at a path that no longer existed and the recovery point silently stopped
// advancing. Protecting the name and taking one extra victim from the rest keeps retention at
// `keep` while guaranteeing the newest content survives.
func (s *Store) pruneSnapshots(dir string, keep int, protect string) error {
	names, err := s.listSnapshots(dir)
	if err != nil {
		return err
	}
	if len(names) <= keep {
		return nil
	}
	// names is oldest-first, so filling the victim set in order preserves "oldest goes first".
	victims := make([]string, 0, len(names)-keep)
	for _, name := range names {
		if len(victims) == len(names)-keep {
			break
		}
		if name == protect {
			continue
		}
		victims = append(victims, name)
	}
	for _, name := range victims {
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove old snapshot %s: %w", name, err)
		}
	}
	return nil
}

// Snapshots lists the snapshots this store would prune, oldest first. For diagnostics.
func (s *Store) Snapshots(dir string) ([]string, error) {
	return s.listSnapshots(dir)
}

// HasRecoverableState reports whether this database holds anything a snapshot could recover.
//
// The question is not idle when retention is in play. A snapshot of a freshly created database is
// not a recovery point, but retention counts it as one: after the documented state.db loss -- the
// case snapshots exist for -- every restart wrote one of these and evicted a real backup, so three
// restarts with keep=3 destroyed all three genuine snapshots and the operator's last good copy was
// gone before anyone looked. The answer is "is there an account key, a certificate, an order, a
// revocation decision or retired material in here"; rate buckets and identifier-failure counters
// are deliberately not counted, because losing them costs rate-limit knowledge, not a certificate.
func (s *Store) HasRecoverableState() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, table := range []string{"accounts", "certificates", "orders", "revoke_requests", "retired_certificates"} {
		var exists int
		err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM ` + table + `)`).Scan(&exists)
		if err != nil {
			return false, fmt.Errorf("check %s for recoverable state: %w", table, err)
		}
		if exists == 1 {
			return true, nil
		}
	}
	return false, nil
}
