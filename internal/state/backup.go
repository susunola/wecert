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
	final := filepath.Join(dir, s.snapshotName(stamp))

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

	// Two snapshots can still collide at millisecond precision. The fallback keeps the sort order
	// intact: a numeric suffix appended after the stamp sorts LATER, so the newer file stays
	// "newest" for retention. (The pid-based version this replaces did the opposite.)
	for n := 1; ; n++ {
		if _, err := os.Stat(final); os.IsNotExist(err) {
			break
		}
		final = filepath.Join(dir, s.snapshotName(fmt.Sprintf("%s-%d", stamp, n)))
	}

	if _, err := s.db.Exec(`VACUUM INTO ?`, tmpName); err != nil {
		return "", fmt.Errorf("snapshot state database: %w", err)
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

	if err := s.pruneSnapshots(dir, keep); err != nil {
		// The snapshot itself succeeded; failing to prune is worth reporting but must not
		// be reported as a failed snapshot.
		return final, fmt.Errorf("snapshot written to %s, but pruning old snapshots failed: %w", final, err)
	}
	return final, nil
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
	// A collision suffix ("<stamp>-2") is not part of the timestamp.
	if i := strings.IndexByte(rest, '-'); i >= 0 {
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

// pruneSnapshots keeps the newest `keep` snapshots and removes the rest.
func (s *Store) pruneSnapshots(dir string, keep int) error {
	names, err := s.listSnapshots(dir)
	if err != nil {
		return err
	}
	if len(names) <= keep {
		return nil
	}
	for _, name := range names[:len(names)-keep] {
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
