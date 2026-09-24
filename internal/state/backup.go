package state

import (
	"errors"
	"fmt"
	"github.com/susunola/wecert/internal/atomicfile"
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

// removeSnapshotFile is os.Remove, as a seam.
//
// Pruning has to attempt every victim even when one cannot be removed, and the only portable way to
// prove that is to make one removal fail on purpose: "undeletable" normally means an immutable flag
// or an ACL, neither of which a test can rely on across platforms.
var removeSnapshotFile = os.Remove

// snapshotCopied runs after the copy lands and before its permissions are tightened. Tests use it
// to observe the mode the copy was CREATED with: the chmod that follows makes the window invisible
// to any assertion made after Snapshot returns, so without this hook the umask above could be
// dropped without a test noticing.
var snapshotCopied = func(string) {}

// repairDirSynced runs after a repaired snapshot's rename has been made durable with a directory
// fsync. Tests use it to observe that the fsync actually happens: a rename without one is
// invisible to any assertion made on the directory afterwards.
var repairDirSynced = func(string) {}

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

	// VACUUM INTO refuses to overwrite, and the file it creates must already be private: the
	// driver creates it with the process umask (0644 by default) and this file holds the ACME
	// account key and every certificate private key. So the copy is made under a restrictive umask
	// (below) into a name that does not exist yet, and renamed into place afterwards.
	//
	// The name is picked by trial rather than by CreateTemp-then-Remove. Creating the file and
	// deleting it again made the whole snapshot impossible in a directory that allows creating but
	// not deleting (an ACL, a chattr'd directory): every interval failed on the Remove, and each
	// attempt left a 0-byte .snapshot-*.tmp that nothing revisits. Picking a free name needs only
	// stat, and a crash mid-VACUUM now leaves a file the sweep below recognises.
	s.sweepStaleSnapshotTemps(dir)
	s.repairFutureDatedSnapshots(dir)
	tmpName, err := s.freeTempName(dir)
	if err != nil {
		return "", err
	}

	defer func() {
		// Every failure path must clean up, or a broken snapshot accumulates on disk
		// looking like a usable backup. The `-journal` goes with it: SQLite creates it beside the
		// VACUUM INTO target and leaves it behind if the process dies mid-copy.
		for _, name := range []string{tmpName, tmpName + "-journal"} {
			if _, statErr := os.Stat(name); statErr == nil {
				_ = os.Remove(name)
			}
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
	//
	// restore is deferred, matching openFiles: umask is process-wide and the umask mutex is held
	// until restore runs, so a panic between the two calls would leave every later file in the
	// process at 077 and deadlock Open on the same mutex. The cost of defer here is nil.
	restoreUmask := restrictiveUmask()
	defer restoreUmask()
	_, execErr := s.db.Exec(`VACUUM INTO ?`, tmpName)
	snapshotCopied(tmpName)
	if execErr != nil {
		return "", fmt.Errorf("snapshot state database: %w", execErr)
	}
	// The permissions are set on the temporary file and the rename is made durable by
	// internal/atomicfile, which is where the protocol lives.
	if err := atomicfile.Install(tmpName, final, 0o600, dir); err != nil {
		// The rename and the directory sync are two steps, and only the first one changes what is
		// on disk: if the file is there, the caller has a usable snapshot and must be told so --
		// reporting "no snapshot" while one exists is the same false all-clear this caller's
		// "a snapshot was written despite the error" branch exists to prevent.
		if _, statErr := os.Stat(final); statErr == nil {
			tmpName = ""
			return final, fmt.Errorf("snapshot written to %s, but making the name durable failed: %w", final, err)
		}
		return "", fmt.Errorf("install snapshot %s: %w", final, err)
	}
	tmpName = ""
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

// freeTempName returns a path under dir for a snapshot being written, that does not exist yet.
//
// VACUUM INTO insists on a path that does not exist, so the name has to be chosen rather than
// created: CreateTemp's O_EXCL is exactly the guarantee that cannot be used here. The stamp plus a
// counter is enough -- one process writes snapshots for a given store (the store lock makes that
// true), and a collision is detected by the stat instead of assumed away.
//
// The name carries s.base for the same reason the final snapshot name does (see Store.base):
// nothing refuses a shared backup directory, and an unprefixed name let one deployment's trial
// names collide with another's in-progress write -- and made sweepStaleSnapshotTemps unable to
// tell which temp files were its own to remove.
func (s *Store) freeTempName(dir string) (string, error) {
	stamp := time.Now().UTC().Format("20060102T150405.000")
	for n := 0; ; n++ {
		candidate := filepath.Join(dir, fmt.Sprintf(".snapshot-%s-%s-%d.tmp", s.base, stamp, n))
		_, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			return candidate, nil
		}
		if err != nil {
			// Unknown state (an unreachable mount, a lost search permission): every candidate
			// fails the same way, so retrying would spin.
			return "", fmt.Errorf("cannot tell whether snapshot temp file %s is free: %w", candidate, err)
		}
	}
}

// snapshotTempMaxAge is how long a `.snapshot-*.tmp` file may sit in the backup directory before
// the next snapshot removes it.
//
// A crash between VACUUM INTO and the rename leaves a partial copy behind, and nothing else ever
// looks at those names. An hour is far longer than any snapshot takes (the pass that writes one is
// bounded by the store's own work, seconds at most) and far shorter than the shortest retention
// interval, so a live write can never be swept.
const snapshotTempMaxAge = time.Hour

// repairFutureDatedSnapshots renames snapshots whose stamp is in the future.
//
// The stamp is wall-clock, so a forward excursion (an NTP correction, a VM resumed from a snapshot
// taken on a machine whose clock was ahead) writes names that sort AFTER every later, honest stamp.
// Retention keeps the newest names, so such a file is never pruned again: it holds a slot forever
// and the deployment keeps one fewer genuine recovery point -- measured with keep=3, which retained
// only two real snapshots and deleted the oldest fresh one every round. The content is fine, so the
// file is renamed rather than deleted, to the time it was actually written (its mtime) or to now
// when the mtime is in the future too.
func (s *Store) repairFutureDatedSnapshots(dir string) {
	names, err := s.listSnapshots(dir)
	if err != nil {
		return
	}
	now := time.Now()
	for _, name := range names {
		stamp, ok := s.snapshotStampOf(filepath.Base(name))
		if !ok {
			continue
		}
		at, err := time.Parse(snapshotStamp, stamp)
		if err != nil || !at.After(now) {
			continue
		}
		info, err := os.Stat(name)
		if err != nil {
			continue
		}
		target := info.ModTime().UTC()
		if target.After(now) {
			target = now
		}
		fixed, err := s.freeSnapshotName(dir, target.Format(snapshotStamp))
		if err != nil || fixed == name {
			continue
		}
		if err := os.Rename(name, fixed); err != nil {
			continue
		}
		// A rename is only durable once the directory itself is synced (the same reasoning as
		// atomicfile.Install): a power cut here would otherwise resurrect the future-dated name,
		// undoing the repair. Best-effort like the repair itself -- the snapshot pass that called
		// this continues either way.
		_ = atomicfile.SyncDir(dir)
		repairDirSynced(dir)
	}
}

// snapshotTempPrefix is how this store's temporary snapshot names start. A shared backup directory
// means a prefix match on ".snapshot-" alone would also match another deployment's in-progress
// write, which this store has no business removing -- the age check exists so a live write is
// never swept, and widening the match would punch through exactly that guarantee for files this
// store does not own. Temp files written before the prefix carried the base (".snapshot-<stamp>-")
// are deliberately left behind: they cannot be attributed to any store, so nobody may delete them.
func (s *Store) snapshotTempPrefix() string { return ".snapshot-" + s.base + "-" }

// sweepStaleSnapshotTemps removes leftover temporary snapshots from an interrupted write.
//
// Two rules, and the difference is ownership:
//
//   - THIS store's files (`.snapshot-<base>-*`) go at any age. The only caller is Snapshot, which
//     holds the store mutex (so no second snapshot of this database can be in flight in this
//     process) and the cross-process lock on this state path (so no other process can be writing one
//     either): every one of them is a leftover, and an age threshold only leaves a partial copy of
//     the private-key database lying around for an hour. The round-11 crash-fault verification killed
//     the daemon with 8-15 MiB of a 48 MiB copy written and found the temp still there after the next
//     start had taken a clean snapshot.
//   - Anything else matching `.snapshot-*` keeps the age threshold: it belongs to another deployment
//     sharing this directory (see snapshotTempPrefix) or predates the base-name prefix, so its owner
//     cannot be established -- and an hour is far longer than any snapshot takes, which is what makes
//     the age a safe proxy for "nobody is writing this".
//
// The journal SQLite creates beside a VACUUM INTO target goes with the temp file: the verification
// found both stranded (".snapshot-...-0.tmp" and ".snapshot-...-0.tmp-journal"), and the old suffix
// test only matched ".tmp", so the journal was never swept at all.
func (s *Store) sweepStaleSnapshotTemps(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	own := s.snapshotTempPrefix()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, ".snapshot-") {
			continue
		}
		if !strings.HasSuffix(name, ".tmp") && !strings.HasSuffix(name, ".tmp-journal") {
			continue
		}
		if !strings.HasPrefix(name, own) {
			if info, err := e.Info(); err != nil || time.Since(info.ModTime()) < snapshotTempMaxAge {
				continue
			}
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
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

// IsSnapshotName reports whether name looks like a snapshot of the store whose
// database file is named stateBase. The matcher is the same strict one retention
// uses (snapshotStampOf), so a hand-made `state.backup-before-upgrade.db` is
// refused rather than treated as a recovery point.
func IsSnapshotName(name, stateBase string) bool {
	s := &Store{base: stateBase}
	_, ok := s.snapshotStampOf(name)
	return ok
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
	// Every victim is attempted even when one of them cannot be removed.
	//
	// Returning on the first failure meant ONE undeletable snapshot stopped all pruning for the
	// life of the directory: an operator who makes snapshots immutable (chattr +i, or ACLs, as
	// ransomware hardening) then watched the directory grow by one file per interval while every
	// round reported the same error against the same oldest name. The failures are joined instead,
	// so the caller's log line names all of them and the snapshots that CAN be removed are gone.
	var failed []error
	for _, name := range victims {
		if err := removeSnapshotFile(name); err != nil && !os.IsNotExist(err) {
			failed = append(failed, fmt.Errorf("remove old snapshot %s: %w", name, err))
		}
	}
	return errors.Join(failed...)
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
