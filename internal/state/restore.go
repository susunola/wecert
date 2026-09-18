package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/atomicfile"
)

// Restoring a snapshot used to be a sequence from docs/recovery.md: stop the daemon, find the
// newest file, move state.db aside, copy the file, chown it, start again. Every one of those steps
// is a chance to leave the deployment with no state database at all, and the last one -- start
// again -- is where the interesting mistake happens: a restored snapshot carries a rate-limit
// ledger that stops at the moment the snapshot was written, so wecert believes it has spent nothing
// since then. The exact-identifier-set limit is 5 per 7 days with no override, so "believes it has
// spent nothing" is not a bookkeeping detail; it is a few orders away from a locked-out domain.
//
// Restore does the file work as one command, and records what it did, so the process that starts
// afterwards can say the one thing the operator cannot find out anywhere else: how much of the
// rate-limit ledger is missing, and until when that matters.

// restoreStagedSuffix names the fully-copied, fsynced snapshot while it waits beside the database
// it is about to replace.
//
// The copy happens BEFORE the live database is moved, on purpose: copying is the step that fails
// (a full disk, a snapshot on a mount that just went away), and doing it first means a failure
// leaves the deployment exactly as it was.
const restoreStagedSuffix = ".restore-staged"

// replacedSuffix names the database that a restore displaced.
//
// It is kept rather than deleted because that file holds the account key and any order placed after
// the snapshot was written; a restore is a deliberate step backwards and the operator needs a way
// back forward. The suffix deliberately does NOT match the snapshot pattern (`backupSuffix`), so
// retention never prunes it -- "the newest snapshot" must not become a file nobody chose.
const replacedSuffix = ".replaced-"

// RestoreMarkerSuffix names the record a successful restore leaves next to the state database.
//
// It is a file next to the database rather than a row inside it for one reason: the snapshot is
// installed byte-for-byte, and rewriting the restored copy to annotate it would mean the file the
// operator can compare against their snapshot is no longer that snapshot.
const RestoreMarkerSuffix = ".restored"

// RestoreCaveatWindow is how long a restore's warning about the rate-limit ledger stays relevant.
//
// Seven days is the longest window in Let's Encrypt's published limits that we account for (the
// per-exact-identifier-set and per-registered-domain certificate limits are both 7 days). Every
// spend a snapshot cannot know about happened before the restore, so once a full window has passed
// since the restore, every bucket that could have been under-counted has refilled on its own and
// the ledger is whole again.
const RestoreCaveatWindow = 7 * 24 * time.Hour

// RestoreResult describes what Restore did, in the operator's terms.
type RestoreResult struct {
	// Source is the snapshot file that was installed.
	Source string
	// SourceWrittenAt is the snapshot file's modification time: the age of the DATA, which is what
	// the rate-limit caveat is about (a snapshot written five days ago is missing five days of
	// spends, however recently it was copied).
	SourceWrittenAt time.Time
	// RestoredAt is when this restore happened. The caveat runs from here and not from the
	// snapshot's own date: the spends a snapshot cannot know about are the ones placed right up to
	// the moment of the restore, and each of them stops counting against a 7-day window seven days
	// after itself.
	RestoredAt time.Time
	// Replaced is where the previous database was moved, or "" when there was none.
	Replaced string
	// Dest is the file the snapshot was actually installed as. It differs from the requested state
	// path only when that path is a symlink, and then it is the difference between "restored" and
	// "restored somewhere the daemon will never read".
	Dest string
	// ReplacedWrittenAt is the modification time of that previous database (zero when there was
	// none). An operator who restored the wrong snapshot needs to know how much newer the file they
	// displaced was.
	ReplacedWrittenAt time.Time
	// Certificates and Account describe what the restored database holds, so the log line answers
	// "did I restore the right file?" without a second command.
	Certificates int
	Account      bool
}

// RestoreNotice is the record a restore leaves behind, and the input to the warning that a later
// start prints.
type RestoreNotice struct {
	RestoredAt      time.Time `json:"restoredAt"`
	Source          string    `json:"source"`
	SourceWrittenAt time.Time `json:"sourceWrittenAt"`
	Replaced        string    `json:"replaced,omitempty"`
	Version         string    `json:"version,omitempty"`
}

// CaveatApplies reports whether the rate-limit caveat still matters at now.
//
// Before RestoredAt (a clock that stepped backwards between the restore and this start) the answer
// is yes: refusing to warn because the timestamp looks like the future would be exactly wrong, and
// the same "a future instant is due, not impossible" reading is what bindingCheckDue uses.
func (n *RestoreNotice) CaveatApplies(now time.Time) bool {
	if n == nil {
		return false
	}
	return now.Before(n.RestoredAt.Add(RestoreCaveatWindow))
}

// Restore installs a snapshot as the state database at dest.
//
// It refuses rather than guesses in four cases, each of which has an operator action attached:
// another process holds the database open (stop it), the snapshot is not a readable wecert database
// (pick another one), the snapshot IS the state database (nothing to do), or the snapshot is a
// symlink (point at the real file).
//
// The previous database is never overwritten in place. It is renamed to dest+".replaced-<stamp>"
// together with its -wal and -shm sidecars -- moving the database without them would leave a
// write-ahead log belonging to a different file next to the restored one.
func Restore(dest, source string) (RestoreResult, error) {
	var res RestoreResult

	if dest == "" {
		return res, errors.New("restore: no state path to restore into")
	}
	if source == "" {
		return res, errors.New("restore: no snapshot given")
	}

	// Lstat, not Stat: a symlinked snapshot is refused instead of followed. The file is about to be
	// copied over the state database, and "the name I was given resolved to somewhere else" is not
	// a property worth discovering afterwards.
	srcInfo, err := os.Lstat(source)
	if err != nil {
		return res, fmt.Errorf("restore: read the snapshot %s: %w", source, err)
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		return res, fmt.Errorf("restore: %s is a symlink; point at the real snapshot file so it is "+
			"clear which bytes are being restored", source)
	}
	if !srcInfo.Mode().IsRegular() {
		return res, fmt.Errorf("restore: %s is not a regular file (%s)", source, srcInfo.Mode().Type())
	}

	// Follow a symlinked state path instead of replacing the link.
	//
	// A symlinked statePath is a supported arrangement (state.db on another volume, a staging
	// symlink during a migration -- open() warns about the hazard, it does not refuse it). Restoring
	// by renaming a file onto the LINK's name would leave the operator's real database frozen at its
	// old contents and put the restored bytes somewhere the daemon will never read: the restore
	// would report success and change nothing that matters, in the one situation where nobody is
	// going to double-check it. So the bytes go to the link's target, and the marker -- which the
	// next start looks for beside the CONFIGURED path -- stays beside the link.
	realDest, err := resolveStateTarget(dest)
	if err != nil {
		return res, err
	}
	res.Dest = realDest

	if dstInfo, err := os.Stat(realDest); err == nil && os.SameFile(srcInfo, dstInfo) {
		return res, fmt.Errorf("restore: the snapshot %s and the state database %s are the same "+
			"file; nothing to restore", source, realDest)
	}

	// Everything that can be checked about the snapshot is checked before the live database is
	// touched, because the alternative is discovering a bad snapshot halfway through.
	stats, err := inspectSnapshot(source)
	if err != nil {
		return res, err
	}
	res.Source = source
	res.SourceWrittenAt = srcInfo.ModTime()
	res.Certificates = stats.certificates
	res.Account = stats.account

	// The lock is the same one the daemon holds, so this is the check that stops a restore from
	// happening under a running process -- which would leave that process writing to an unlinked
	// inode (state.VerifyOnDisk reports it, but only after the fact).
	lock, err := acquireLock(dest + ".lock")
	if err != nil {
		if errors.Is(err, ErrLocked) {
			return res, fmt.Errorf("restore: refusing to replace the state database while another "+
				"wecert process has it open: %w\n"+
				"       Stop that process (systemctl stop wecert) and run the restore again. Restoring "+
				"underneath a running daemon does not fail loudly: the daemon keeps writing to the file "+
				"it already opened, so its orders and its deployed-certificate records never reach the "+
				"restored database", err)
		}
		return res, err
	}
	defer func() { _ = lock.release() }()

	dir := filepath.Dir(realDest)
	staged := realDest + restoreStagedSuffix
	// A leftover from a crashed restore would make the copy below fail with "file exists" on some
	// filesystems; the name is ours and the previous attempt is not in use, so clear it.
	_ = os.Remove(staged)
	if err := copyFileSync(staged, source, dir); err != nil {
		return res, fmt.Errorf("restore: stage the snapshot: %w", err)
	}
	// The staged copy is verified too, not just the source: a truncated read (a full disk, a device
	// error) produces a file that is only discovered to be unusable by the NEXT start, at which
	// point the good database has already been moved aside.
	if _, err := inspectSnapshot(staged); err != nil {
		_ = os.Remove(staged)
		return res, fmt.Errorf("restore: the staged copy did not survive the copy, so the state "+
			"database was left alone: %w", err)
	}

	replaced, replacedAt, err := setAsideDatabase(realDest)
	if err != nil {
		_ = os.Remove(staged)
		return res, err
	}
	res.Replaced = replaced
	res.ReplacedWrittenAt = replacedAt

	if err := atomicfile.Install(staged, realDest, 0o600, dir); err != nil {
		// Both files are on disk and named: this is recoverable by hand, and the message has to say
		// how, because the state database is now missing and wecert will not start without one.
		back := ""
		if replaced != "" {
			back = fmt.Sprintf(" or go back with `mv %s %s`", replaced, realDest)
		}
		return res, fmt.Errorf("restore: the previous database was moved aside but installing the "+
			"snapshot failed: %w\n"+
			"       Nothing is lost: the verified copy of the snapshot is %s, and the database it was "+
			"to replace is at %s. Finish by hand with `mv %s %s`%s",
			err, staged, replacedDescription(replaced), staged, realDest, back)
	}

	// Best-effort is not good enough here, and the error says why: the caveat below is the only
	// place the rate-limit consequence of this restore is ever stated, and a silent failure would
	// make the next start look like an ordinary one.
	res.RestoredAt = time.Now().UTC()
	notice := RestoreNotice{
		RestoredAt:      res.RestoredAt,
		Source:          source,
		SourceWrittenAt: srcInfo.ModTime().UTC(),
		Replaced:        replaced,
	}
	if err := writeRestoreNotice(dest, notice); err != nil {
		return res, fmt.Errorf("restore: the snapshot is in place, but recording it failed, so the "+
			"next start will not warn about the rate-limit ledger: %w", err)
	}
	return res, nil
}

// snapshotStats is what the validation pass learns about a candidate snapshot.
type snapshotStats struct {
	certificates int
	account      bool
}

// inspectSnapshot proves a file is a wecert state database before it is allowed to replace one.
//
// Three questions, cheapest first, because each rules out a different mistake an operator can
// actually make: restoring a file that is not a database at all (a snapshot that was truncated by a
// full disk), restoring a database that is corrupt, and restoring a well-formed SQLite file that is
// simply not ours (a different deployment's state, a Terraform state file).
func inspectSnapshot(path string) (snapshotStats, error) {
	var stats snapshotStats

	// The 16-byte magic first: it catches "that is not a database" without asking SQLite to open
	// anything, which matters when the file is huge or on a mount that is timing out.
	f, err := os.Open(path)
	if err != nil {
		return stats, fmt.Errorf("restore: open %s: %w", path, err)
	}
	header := make([]byte, 16)
	_, readErr := io.ReadFull(f, header)
	_ = f.Close()
	if readErr != nil {
		return stats, fmt.Errorf("restore: %s is too short to be a SQLite database (%v); a snapshot "+
			"that was copied while it was still being written looks like this", path, readErr)
	}
	if string(header) != "SQLite format 3\x00" {
		return stats, fmt.Errorf("restore: %s is not a SQLite database, so it is not a wecert state "+
			"snapshot (the first bytes are %q)", path, header)
	}

	db, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return stats, fmt.Errorf("restore: open %s: %w", path, err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// integrity_check, not the quick_check an ordinary start uses: this file is about to displace
	// the live database, so the expensive answer is the one worth having, and it is paid once.
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check(1)`).Scan(&integrity); err != nil {
		return stats, fmt.Errorf("restore: %s is not a readable SQLite database: %w", path, err)
	}
	if integrity != "ok" {
		return stats, fmt.Errorf("restore: %s failed its integrity check (%s). Restoring it would "+
			"replace one damaged database with another; use an older snapshot", path, integrity)
	}

	// Table names, not a schema version: migrations are additive and an old snapshot is a legitimate
	// thing to restore -- the next start migrates it. What is not legitimate is a database that has
	// never had wecert's schema.
	for _, table := range []string{"accounts", "certificates"} {
		var n int
		if err := db.QueryRow(
			`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil {
			return stats, fmt.Errorf("restore: read the schema of %s: %w", path, err)
		}
		if n == 0 {
			return stats, fmt.Errorf("restore: %s is a SQLite database but has no %q table, so it is "+
				"not a wecert state snapshot", path, table)
		}
	}

	if err := db.QueryRow(`SELECT count(*) FROM certificates`).Scan(&stats.certificates); err != nil {
		return stats, fmt.Errorf("restore: count the certificates in %s: %w", path, err)
	}
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM accounts)`).Scan(&stats.account); err != nil {
		return stats, fmt.Errorf("restore: look for an account in %s: %w", path, err)
	}
	return stats, nil
}

// freeReplacedName picks a name for the displaced database that nothing occupies.
func freeReplacedName(dest string) (string, error) {
	stamp := time.Now().UTC().Format(snapshotStamp)
	final := dest + replacedSuffix + stamp
	for n := 1; ; n++ {
		_, err := os.Lstat(final)
		if os.IsNotExist(err) {
			return final, nil
		}
		if err != nil {
			// "Unknown" must not be read as "free": every candidate fails the same way, so the loop
			// would spin here forever on a directory that lost its search permission.
			return "", fmt.Errorf("restore: cannot tell whether %s already exists: %w", final, err)
		}
		final = fmt.Sprintf("%s%s%s~%d", dest, replacedSuffix, stamp, n)
	}
}

// resolveStateTarget returns the file a restore should write to when the configured state path is
// dest: dest itself, or -- when dest is a symlink -- the file it points at.
//
// The chain is resolved rather than the first link: a symlink to a symlink is normal in a
// state-directory migration, and restoring onto the middle link would recreate exactly the problem
// this function exists to avoid.
func resolveStateTarget(dest string) (string, error) {
	fi, err := os.Lstat(dest)
	if err != nil {
		// Nothing there yet: a restore onto a lost database is the ordinary disaster case, and the
		// snapshot is about to create the file at exactly this name.
		if os.IsNotExist(err) {
			return dest, nil
		}
		return "", fmt.Errorf("restore: look for the state database %s: %w", dest, err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return dest, nil
	}
	target, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return "", fmt.Errorf("restore: the state path %s is a symlink that cannot be resolved (%w); "+
			"repair the link or point statePath at the real file", dest, err)
	}
	return target, nil
}

// setAsideDatabase moves the state database and its sidecars out of the way.
//
// The three files move together or not at all. A -wal left next to a database it does not belong to
// is the one arrangement SQLite must never be handed on open: the pages in it describe a different
// database, and what a reader gets depends on the header it finds.
func setAsideDatabase(dest string) (string, time.Time, error) {
	if _, err := os.Lstat(dest); os.IsNotExist(err) {
		return "", time.Time{}, nil
	} else if err != nil {
		return "", time.Time{}, fmt.Errorf("restore: look for the existing state database %s: %w", dest, err)
	}

	var writtenAt time.Time
	if fi, err := os.Stat(dest); err == nil {
		writtenAt = fi.ModTime()
	}

	// The same fixed-width UTC layout snapshots use, so the names sort chronologically.
	//
	// A name that is already taken gets the "~N" suffix snapshots use for the same reason: this is
	// the one file in the directory that holds state nobody else has, and os.Rename onto an existing
	// name replaces it silently. Two restores inside the same millisecond are the only way to get
	// here; losing an operator's only copy of a database is not a proportional price for that.
	replaced, err := freeReplacedName(dest)
	if err != nil {
		return "", time.Time{}, err
	}
	var moved []move
	for _, suffix := range []string{"", "-wal", "-shm"} {
		from := dest + suffix
		if _, err := os.Lstat(from); err != nil {
			continue
		}
		if err := os.Rename(from, replaced+suffix); err != nil {
			// Undo what was already moved. The database itself is moved first, so a failure here
			// means dest is missing; putting the earlier files back is the difference between "the
			// restore did nothing" and "the deployment now has no state database".
			var undo []string
			for _, m := range moved {
				if rerr := os.Rename(m.replaced, m.original); rerr != nil {
					undo = append(undo, fmt.Sprintf("%s -> %s (%v)", m.replaced, m.original, rerr))
				}
			}
			msg := fmt.Sprintf("restore: move %s aside: %v", from, err)
			if len(undo) > 0 {
				msg += "; putting the already-moved files back failed too, so they are at " +
					strings.Join(undo, ", ")
			}
			return "", time.Time{}, errors.New(msg)
		}
		moved = append(moved, move{original: from, replaced: replaced + suffix})
	}
	return replaced, writtenAt, nil
}

// move remembers one renamed file so a partial failure can be undone.
type move struct {
	original string
	replaced string
}

// replacedDescription names the moved-aside database in an error message, accounting for the case
// where there was none.
func replacedDescription(replaced string) string {
	if replaced == "" {
		return "(there was no state database to move)"
	}
	return replaced
}

// copyFileSync writes src to dst (which must be a fresh temporary name in dir) and makes the bytes
// durable before the caller renames it.
//
// The fsync is not optional even though the rename that follows is atomic: without it a power loss
// can leave the new NAME pointing at a file whose blocks never reached the disk, and for the state
// database that is the account key and every certificate's private key.
func copyFileSync(dst, src, dir string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.CreateTemp(dir, atomicfile.TempPrefix+"*.tmp")
	if err != nil {
		return err
	}
	tmpName := out.Name()
	// The caller staged to a fixed name (`restoreStagedSuffix`); CreateTemp gives a random one, so
	// the file is moved onto the staged name only after it is complete.
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	tmpName = ""
	return atomicfile.SyncDir(dir)
}

// readOnlyDSN opens a database without allowing a single write.
//
// journal_mode(WAL) is deliberately absent: it is a WRITE (it rewrites the header), and this
// connection exists to inspect a file we have not decided to trust yet. mode=ro also makes SQLite
// refuse to create the file if the path is wrong, which is the difference between "that snapshot
// does not exist" and a brand-new empty database being inspected and rejected as "not a wecert
// snapshot".
func readOnlyDSN(path string) string {
	u := url.URL{Path: path}
	return "file:" + u.EscapedPath() + "?mode=ro&_pragma=busy_timeout(5000)"
}

// writeRestoreNotice records a completed restore next to the state database.
func writeRestoreNotice(dest string, notice RestoreNotice) error {
	data, err := json.MarshalIndent(notice, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicfile.Write(dest+RestoreMarkerSuffix, data, 0o600)
}

// LoadRestoreNotice reads the record of the last restore of this state database.
//
// It returns (nil, nil) when there is none, which is the ordinary case. A marker that exists but
// cannot be read is an error rather than an absence: the caller's next question is "has this
// database's rate-limit ledger been restored from something older", and answering "no" to that on
// the strength of an unreadable file is the shape of mistake this project has already made once
// with an unreadable quota bucket.
func LoadRestoreNotice(statePath string) (*RestoreNotice, error) {
	data, err := os.ReadFile(statePath + RestoreMarkerSuffix)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read the restore record %s: %w", statePath+RestoreMarkerSuffix, err)
	}
	var notice RestoreNotice
	if err := json.Unmarshal(data, &notice); err != nil {
		return nil, fmt.Errorf("the restore record %s is not readable JSON (%w); it was written by "+
			"`wecert -restore` and can be deleted once you have read it", statePath+RestoreMarkerSuffix, err)
	}
	if notice.RestoredAt.IsZero() {
		return nil, fmt.Errorf("the restore record %s has no timestamp, so how old the restored "+
			"rate-limit ledger is cannot be told", statePath+RestoreMarkerSuffix)
	}
	return &notice, nil
}

// SnapshotsIn lists the snapshots of the state database at statePath that live in dir, oldest
// first.
//
// It exists for the restore path, which has to pick a snapshot without a store: the ordinary reason
// to restore is that there is no usable state database to open.
func SnapshotsIn(dir, statePath string) ([]string, error) {
	s := &Store{base: filepath.Base(statePath)}
	return s.listSnapshots(dir)
}
