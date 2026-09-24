// Package state is wecert's persistence layer.
//
// The existence of this layer is itself a requirement: Let's Encrypt explicitly
// names the most common way people hit rate limits -- "deleting the ACME client's
// configuration data on every deploy". Losing the order URL makes a restarted
// process place a fresh order, walking straight into
// "5 certificates per exact set of identifiers / 7 days".
//
// So: account key, order URL, ARI window, and Tencent Cloud CertId all hit disk.
package state

import (
	"database/sql"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Split out so one concern lives in one file. Same package.

func Open(path string) (*Store, error) { return open(path, true) }

// OpenUnlocked opens the state database but does **not** take the exclusive lock.
//
// For the tools that have to work while the daemon holds it -- `-dry-run`, `-revoke`,
// wecert-preflight, wecert-clbverify. "You cannot even validate the config because the daemon is
// running" pushes people into editing it blindly, and a revocation that has to wait for a restart
// is worse than one that lands now.
//
// These callers are NOT read-only, and the earlier claim here that they were was simply wrong:
// `-revoke` records a revocation request (cmd/wecert/revoke.go) and `-dry-run` registers the ACME
// account on a first run (acme.EnsureAccount). What makes the unlocked path safe is not the absence
// of writes -- it is that none of them need serialising against a pass.
//
// What it must not do is migrate. `migrate` is a CREATE TABLE batch plus a check-then-act
// `ALTER TABLE ... ADD COLUMN`, so without the lock two processes can pass the "does this column
// exist?" check together and the loser aborts the entire open with `duplicate column name` -- the
// "two processes initialising at once, hardest to diagnose" case the locking comment below is
// about. An unlocked open therefore VERIFIES the schema and refuses with an instruction, rather
// than changing it.
func OpenUnlocked(path string) (*Store, error) { return open(path, false) }

// OpenForTool opens the store for a one-shot command: `-dry-run`, `-revoke`, the diagnostic tools.
//
// It asks for the exclusive lock first and falls back to the unlocked path only when another
// process holds it. That order matters, and getting it wrong broke a documented flow: always
// opening unlocked made `wecert -dry-run` fail on a fresh installation, because a brand-new state
// directory needs a schema and the unlocked path refuses to create one. The quick start is
// "install, edit the config, dry-run" -- and the whole point of the dry run is to check the config
// before the daemon is ever started.
//
// With this order:
//
//   - no daemon running (a fresh install, or validation before the first start): the tool takes the
//     lock, migrates if the schema is behind, and works -- the migration is serialised, so the race
//     the unlocked path exists to avoid cannot happen;
//   - a daemon running: the lock is refused, the tool reads without one, and it does NOT migrate --
//     which is correct, because the running daemon migrated at startup and holds the truth.
func OpenForTool(path string) (*Store, error) {
	s, err := Open(path)
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, ErrLocked) {
		return nil, err
	}
	return OpenUnlocked(path)
}

// LockFile takes the cross-process exclusive lock described in Store.lock on an
// arbitrary file and returns the function that releases it.
//
// The store locks "<db>.lock" itself inside Open; this is for sibling state files
// that need the same "at most one process" gate -- wecert-onboard's state file,
// where two overlapping cron runs would each load the same baseline and then
// last-writer-wins the save, losing Changes entries and regressing AbsentSince.
// Like the store's lock it fails fast rather than queueing: a second run that
// waited would apply its stale baseline the moment the first one exits, which is
// worse than an outright error.
func LockFile(path string) (unlock func() error, err error) {
	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	return lock.release, nil
}

func open(path string, exclusive bool) (*Store, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create state dir %s: %w", dir, err)
		}
	}
	// The database itself commonly does not exist on a first start, so inspect
	// its containing directory rather than the eventual file.
	filesystemPath := dir
	if filesystemPath == "" || filesystemPath == "." {
		filesystemPath = "."
	}
	if filesystem, err := unsafeFilesystem(filesystemPath); err != nil {
		return nil, err
	} else if filesystem != "" {
		return nil, fmt.Errorf(
			"refusing state database %s on %s: SQLite and flock cannot guarantee one writer on a network filesystem; move statePath to local storage and restore a snapshot there",
			path, filesystem)
	}

	// Both of these are warnings, not refusals, and the difference is deliberate.
	//
	// A symlinked statePath is a legitimate, common arrangement -- state.db on a different volume,
	// or a staging symlink during a migration -- and refusing it would break a working deployment
	// to prevent a hazard that needs a hostile local user. The hazard is real, though: the file is
	// opened through the link (no O_NOFOLLOW), so whoever can write the target's directory can have
	// this process create the schema and the ACME account key inside a file of their choosing. A
	// shared-writable state directory has the same shape for a different reason: 0600 on state.db
	// stops another user from READING it, not from unlinking it and creating their own in its place.
	// Both are stated plainly and left to the operator, because this program cannot tell "my
	// operator symlinked it on purpose" from "someone is redirecting my writes".
	for _, w := range statePathWarnings(path, dir) {
		fmt.Fprintf(os.Stderr, "wecert: WARNING: %s\n", w)
	}

	// Sample both facts BEFORE the lock is taken, not after.
	//
	// openFiles uses them for one purpose: "the database was here and now it is gone". A
	// lock file beside a missing database is what that looks like, because some earlier run
	// must have created one. acquireLock CREATES the lock file, so sampling it afterwards
	// made lockExisted true on every single call -- including a brand-new deployment on an
	// empty directory, which then printed the "a state database was probably deleted or
	// lost ... stop and restore it" warning on its very first run. A warning that fires
	// when nothing is wrong is worse than no warning, because it teaches the reader to
	// ignore the one case that matters.
	//
	// Did the database itself exist before this call? Also asked before the pre-create
	// below, because afterwards the answer is always yes.
	_, statErr := os.Stat(path)
	existedBefore := statErr == nil
	_, lockStatErr := os.Stat(path + ".lock")
	lockExisted := lockStatErr == nil

	// The lock has to be taken before the database file is created: two processes
	// initializing an empty database at once is harder to diagnose than two writing
	// an existing one, because they each end up with a different table schema.
	var lock *fileLock
	if exclusive {
		var err error
		if lock, err = acquireLock(path + ".lock"); err != nil {
			return nil, err
		}
	}

	s, err := openFiles(path, lock, existedBefore, lockExisted, exclusive)
	if err != nil {
		_ = lock.release()
		return nil, err
	}
	return s, nil
}

// statOpenedFile is os.Stat, as a seam.
//
// The file it stats was pre-created by openFiles itself, so "the stat of a file we know exists
// fails" cannot be provoked from a test any other way: every real arrangement that makes stat
// fail (a lost search permission, an unreachable mount) makes the earlier create fail first.
var statOpenedFile = os.Stat

// openStateDB opens the SQLite handle.
//
// It is a variable rather than a direct sql.Open call so a build with `-tags verifycount` can
// substitute a counting driver.Connector and measure how many statements a pass costs the database
// (see zz_stmtcount_verifycount.go, and internal/reconcile's orphan-cost instrument). Production
// builds carry the line below and nothing else.
var openStateDB = func(dsn string) (*sql.DB, error) { return sql.Open("sqlite", dsn) }

// openFiles creates/opens the database files and runs the schema migration.
//
// Everything file-creating in here runs under a restrictive umask (see
// restrictiveUmask): SQLite creates -wal/-shm during migrate() with permissions
// derived from the process umask, and those files are copies of the private keys.
// The post-hoc chmod at the end stays as a backstop -- and as the fix-up for
// databases created before the umask was tightened.
//
// existedBefore/lockExisted are the two facts open() has to sample before the
// pre-create below makes them unanswerable; see missingDatabaseWarning.
func openFiles(path string, lock *fileLock, existedBefore, lockExisted, mayMigrate bool) (*Store, error) {
	restore := restrictiveUmask()
	defer restore()

	// The 0600 pre-create (see Open) is part of the security contract, so a failure
	// here is fatal. Swallowing it lets the sql.Open below fail instead -- with a
	// message that points at SQLite rather than at the real permission problem.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("pre-create state file %s: %w", path, err)
	}
	_ = f.Close()

	if walMissing(path) {
		fmt.Fprintf(os.Stderr, "wecert: WARNING: %s\n", missingWALWarning(path))
	}

	// A lock file with no database is what "someone deleted state.db" looks like. A lock file with a
	// ZERO-LENGTH database is the same shape one step later: the file was truncated to nothing (a
	// crash during creation, a filesystem that lost the write, an rsync that was interrupted), and
	// verifyDatabaseIntact deliberately accepts an empty file as a fresh database -- so without this
	// the next start would come up "new" in silence. The round-11 crash-fault verification reproduced
	// exactly that: an fsync EIO aborted the creation and left a 0-byte state.db next to its lock
	// file, and the following healthy start printed only the ordinary first-run account message.
	//
	// Warn rather than refuse -- a first run after restoring a backup, or an operator deliberately
	// starting clean, are both legitimate -- but it must be loud, because the account key and every
	// in-flight order are gone and the next issuance re-places orders.
	if lockExisted {
		empty := false
		if !existedBefore {
			empty = true
		} else if fi, statErr := os.Stat(path); statErr == nil && fi.Size() == 0 {
			empty = true
		}
		if empty {
			fmt.Fprintf(os.Stderr, "wecert: WARNING: %s\n", missingDatabaseWarning(path))
		}
	}

	dsn := sqliteDSN(path)
	db, err := openStateDB(dsn)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	// modernc sqlite is a single-writer model, so cap connections to avoid SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	// Ask the driver which file it actually opened instead of trusting that the
	// path survived the DSN round trip.
	//
	// Every metacharacter of the URI form ('?', '#', '%XX') is also a legal
	// character in a filename, so a statePath containing one used to make SQLite
	// open a *truncated* path -- a different file, created by SQLite with the
	// process umask (0644 on a default machine) rather than by the 0600
	// pre-create above. The chmod loop below then tightened the configured path,
	// which stayed a zero-byte decoy, while the account key and every certificate
	// private key sat in a world-readable -wal. sqliteDSN now escapes the path, but
	// the driver is the authority on what it opened, so the permission contract is
	// enforced against that answer and not against our own arithmetic.
	realPath, diverged, err := databaseFilePath(db, path)
	if err != nil {
		db.Close()
		return nil, err
	}
	if diverged {
		// The escaping above is supposed to keep these equal. A driver that still
		// normalises (symlinks, a doubled separator) is acceptable -- we chmod the
		// real file -- but a mismatch is also the exact signature of the bug this
		// check replaced, so it must not pass silently.
		fmt.Fprintf(os.Stderr,
			"wecert: state database opened as %s (configured statePath %q); permissions are being enforced on %s\n",
			realPath, path, realPath)
	}

	s := &Store{db: db, lock: lock, base: filepath.Base(path), path: path}
	// The identity of the file at that path right now. os.SameFile against a later stat is what
	// catches "unlinked" and "replaced by a restore" alike, without needing the driver's own fd.
	//
	// A failure here refuses the open rather than continuing with openedAs=nil: the file was
	// pre-created by this very function, so it exists, and a stat that fails anyway means the
	// filesystem is in a state nothing downstream can reason about. Continuing silently would
	// disable VerifyOnDisk's identity check for the life of the process -- its "is this still
	// the same inode" comparison has nothing to compare against -- and that check is the only
	// tripwire for "the database was unlinked or replaced under a running daemon".
	fi, statErr := statOpenedFile(path)
	if statErr != nil {
		db.Close()
		return nil, fmt.Errorf("stat the state file %s after opening it: %w", path, statErr)
	}
	s.openedAs = fi

	// Verify the file is a usable database before anything writes to it.
	//
	// Without this, a truncated or overwritten state.db fails later and deeper: the first
	// query returns "database disk image is malformed (11)" or "file is not a database
	// (26)" from inside a migration or a read, with no hint that the file itself is the
	// problem or what to do about it. quick_check is the cheap form (it skips the
	// index-vs-table comparison integrity_check does) and it is the difference between
	// "see docs/recovery.md" and a SQLite error code.
	if err := verifyDatabaseIntact(db); err != nil {
		db.Close()
		return nil, err
	}

	if mayMigrate {
		if err := s.migrate(); err != nil {
			db.Close()
			return nil, err
		}
		if err := s.advanceGeneration(); err != nil {
			db.Close()
			return nil, err
		}
	} else if pending, err := s.pendingMigrations(); err != nil {
		db.Close()
		return nil, err
	} else if len(pending) > 0 {
		db.Close()
		//lint:ignore ST1005 the second paragraph of a multi-line operator instruction is a
		// sentence; capitalising it is the point, and the first paragraph still starts lowercase.
		return nil, fmt.Errorf(
			"the state database %s needs a schema update (%s), and another process is holding the "+
				"lock on it:\n"+
				"       this command asked for the exclusive lock first and could not get it, so it "+
				"fell back to reading without one -- and an unlocked open must not migrate, because "+
				"two processes passing the same 'does this column exist?' check is how a database "+
				"ends up with an opaque 'duplicate column name' error and a half-applied schema.\n"+
				"       Stop that process, run `wecert -once` (which takes the lock and migrates), "+
				"then start it again. See docs/recovery.md.",
			path, strings.Join(pending, ", "))
	}

	// -wal / -shm only really appear after migrate, so tighten all permissions once.
	// The WAL file is a copy of the private keys, so its permissions must be managed
	// along with the rest. databaseFilePath has already made the main file 0600, and
	// SQLite derives the sidecar modes from the main file, so this is the belt to
	// that pair of braces.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(realPath+suffix, 0o600); err != nil && !os.IsNotExist(err) {
			db.Close()
			// chmod names the file it actually touched (realPath), not the configured
			// path: they differ exactly when the operator needs to know which file the
			// driver opened.
			return nil, fmt.Errorf("chmod state file %s: %w", realPath+suffix, err)
		}
	}
	return s, nil
}

// walMissing reports the "-shm present, -wal absent" signature.
func walMissing(path string) bool {
	if _, err := os.Stat(path + "-shm"); err != nil {
		return false
	}
	_, err := os.Stat(path + "-wal")
	return os.IsNotExist(err)
}

// statePathWarnings words the two local-filesystem hazards around the state database.
//
// Split out so the wording and the decision are testable without capturing stderr from open(),
// exactly like missingDatabaseWarning. Empty means "nothing to say".
func statePathWarnings(path, dir string) []string {
	var out []string

	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		target := "(target does not exist)"
		if resolved, rerr := filepath.EvalSymlinks(path); rerr == nil {
			target = resolved
		}
		out = append(out, fmt.Sprintf(
			"the state database %s is a symlink (to %s). That is allowed, but this process writes "+
				"through it: anyone who can write the target's directory can have wecert create the "+
				"schema and the ACME account key in a file they choose. If the symlink is not yours, "+
				"point statePath at the real file", path, target))
	}

	if dir != "" && dir != "." {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			if perm := fi.Mode().Perm(); perm&0o022 != 0 {
				out = append(out, fmt.Sprintf(
					"the state directory %s is group- or world-writable (%04o). state.db itself is "+
						"0600, which stops another user reading it, but not unlinking it and putting "+
						"their own file in its place. 0700 is what the shipped systemd unit sets "+
						"(StateDirectoryMode)", dir, perm))
			}
		}
	}
	return out
}

// VerifyOnDisk reports whether the database this store is writing to is still the file at the path
// it was opened from, and whether the cross-process lock is still the one this process holds.
//
// Both checks exist because SQLite (and flock) bind to the INODE, not to the name. `rm -rf` of the
// state directory while the daemon runs leaves every later write succeeding against an unlinked
// file: reads answer, no error is raised, and the next start comes up with no certificates at all
// -- the "someone deleted state.db" warning does not fire either, because that needs the lock file,
// which the same rm took with it. Restoring a snapshot under a running daemon has the same shape
// from the other side. Neither can be prevented from inside the process; both can be reported.
//
// It returns the problems, in the operator's words. An empty slice means "still the same file".
func (s *Store) VerifyOnDisk() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var problems []string
	if s.path != "" && s.openedAs != nil {
		fi, err := os.Stat(s.path)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf(
				"the state database %s is no longer at that path (%v), but this process is still "+
					"writing to the file it opened -- SQLite writes to an unlinked inode happily. Every "+
					"write since then is invisible to the next start, which will find no account and no "+
					"certificates. Restore the directory or the newest snapshot and restart",
				s.path, err))
		case !os.SameFile(s.openedAs, fi):
			problems = append(problems, fmt.Sprintf(
				"the state database %s has been replaced since this process opened it (a restore, or "+
					"a second deployment on the same path); this process is still writing to the old "+
					"file, so the two are now different databases and this process's writes are lost",
				s.path))
		}
	}
	if err := s.lock.VerifyHeld(); err != nil {
		problems = append(problems, err.Error())
	}
	return problems
}

// missingWALWarning words the "-shm without -wal" signature.
//
// SQLite's WAL mode keeps committed transactions in state.db-wal until a checkpoint folds them into
// the database, and a clean close removes both sidecars. A -shm file with no -wal is therefore the
// signature of a wal that was deleted (a cleanup script matching -*wal, an operator "cleaning up",
// a hostile rm) or of a checkpoint that never completed: everything committed since the last
// checkpoint is GONE, and the database opens fine, reports no error, and holds fewer rows than the
// last pass wrote. The row that matters most is the in-flight order URL -- losing it means the next
// pass places a new order and spends the exact-identifier-set budget again.
func missingWALWarning(path string) string {
	return fmt.Sprintf("the write-ahead log %s-wal is missing while its shared-memory file "+
		"%s-shm remains. Everything committed since the last checkpoint was in that file and is now "+
		"gone (in-flight order URLs included), so check whether something removes state.db-wal, and "+
		"compare this database against the newest snapshot in docs/recovery.md", path, path)
}

// missingDatabaseWarning words the "there was a database here and now there is not" case.
//
// Split out so the decision and the message are testable without capturing stderr from
// open(), which needs a real file layout.
func missingDatabaseWarning(path string) string {
	return fmt.Sprintf(
		"%s did not exist but its lock file did -- a state database was probably deleted or lost. "+
			"Starting from an empty one: the ACME account key and every in-flight order URL are gone, "+
			"so a new account will be registered and orders will be re-placed (which counts against "+
			"the exact-set rate limit). If you have a backup, stop and restore it before continuing "+
			"(see docs/recovery.md).", path)
}

// isCorruptDatabaseError reports whether a driver error means "this file is not a usable
// database", as opposed to any other I/O or permission problem.
//
// modernc.org/sqlite returns these as plain errors carrying SQLite's own message; matching
// the message is unpleasant but it is what the driver exposes, and the alternative --
// treating every failure the same -- is what produced the unhelpful error this replaces.
func isCorruptDatabaseError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"file is not a database",
		"database disk image is malformed",
		"database disk image is corrupt",
		"malformed database schema",
		"file is encrypted or is not a database",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// corruptDatabaseError words the corrupted-file case so the operator knows what to do.
//
// There is no in-place repair for a malformed SQLite file, and the data at stake (the ACME
// account key, every in-flight order URL, the ARI certID of every live certificate) is not
// reproducible: a fresh database means a new account and re-placed orders, which count
// against the exact-set rate limit. So the message refuses clearly and points at the
// recovery procedure rather than pretending to recover.
func corruptDatabaseError(path string, cause error) error {

	//lint:ignore ST1005 the second paragraph of a multi-line operator instruction is a sentence;
	// capitalising it is the point, and the first paragraph still starts lowercase.
	// "the newest snapshot", not "state.db together with its -wal": snapshots are VACUUM INTO copies
	// and have no sidecars at all, and wecert -restore installs one as a single command. Pointing at a
	// file copy plus a -wal sent the reader looking for two files where recovery.md now says "stop the
	// daemon, run wecert -restore latest".
	return fmt.Errorf(
		"the state database %s is corrupt: %v\n"+
			"       wecert will not start against a database it cannot read. Restore the newest snapshot "+
			"(`wecert -restore latest`, which keeps this file aside), or move the damaged file aside to "+
			"start from an empty database -- which registers a new ACME account and re-places orders, so "+
			"prefer the snapshot. See docs/recovery.md.",
		path, cause)
}

// verifyDatabaseIntact runs SQLite's cheap consistency check and turns a failure into an
// actionable error.
//
// It runs before migrate so the operator is told the file is corrupt, not that some
// migration statement failed. An empty (newly created) file passes: quick_check reports
// "ok" for a database with no pages yet.
func verifyDatabaseIntact(db *sql.DB) error {
	var result string
	if err := db.QueryRow(`PRAGMA quick_check(1)`).Scan(&result); err != nil {
		//lint:ignore ST1005 the second paragraph of a multi-line operator instruction is a sentence;
		// capitalising it is the point, and the first paragraph still starts lowercase.
		return fmt.Errorf(
			"the state database is unreadable: %w\n"+
				"       wecert will not start against a database it cannot trust. Restore the newest "+
				"snapshot (`wecert -restore latest`), or move the damaged file aside to start from an "+
				"empty one -- losing it means a new ACME account and re-placed orders. See docs/recovery.md.",
			err)
	}
	if result != "ok" {
		//lint:ignore ST1005 the second paragraph of a multi-line operator instruction is a sentence;
		// capitalising it is the point, and the first paragraph still starts lowercase.
		return fmt.Errorf(
			"the state database failed its consistency check: %s\n"+
				"       Restore the newest snapshot (`wecert -restore latest`), or move the damaged file "+
				"aside to start from an empty one -- losing it means a new ACME account and re-placed "+
				"orders. See docs/recovery.md.",
			result)
	}
	return nil
}

// The path is escaped rather than pasted in: a statePath is operator-supplied and
// may legally contain any of the URI's own metacharacters.
func sqliteDSN(path string) string {
	// url.URL.EscapedPath escapes '?', '#', '%' and friends while leaving '/' as a
	// separator, which is exactly the set the URI form treats specially. An empty
	// Host is what keeps the result in the "file:/abs/path" form SQLite expects
	// (url.String() would otherwise emit "//" before an absolute path).
	u := url.URL{Path: path}
	// _txlock=immediate makes every transaction this connection opens take the write lock at BEGIN
	// rather than at its first write. In WAL a deferred transaction that reads before it writes can
	// fail at COMMIT with SQLITE_BUSY -- after all its work, and at the point where the failure
	// looks like a commit bug rather than a lock conflict. See tx.go.
	return "file:" + u.EscapedPath() +
		"?_txlock=immediate" +
		"&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
}

// databaseFilePath reports the filesystem path the connection actually opened, and
// enforces the 0600 contract on it.
//
// It returns the configured path as a second value so the caller can tell the
// operator when the two disagree -- which is the signature of a DSN that was
// misparsed (or of a driver that normalised the path).
//
// A driver that answers with nothing (or with an in-memory database) is a hard
// error: the alternative is to keep going without knowing whether the private keys
// are readable by every local user, which is the failure this function exists to
// make impossible.
func databaseFilePath(db *sql.DB, configured string) (actual string, diverged bool, err error) {
	rows, err := db.Query(`PRAGMA database_list`)
	if err != nil {
		// This is where a corrupt state file surfaces first: the pragma has to read the
		// header, so it fails with "file is not a database" or "database disk image is
		// malformed" before any of the checks below -- including the quick_check in open --
		// ever run. Reporting the raw driver error here sends the operator looking at the
		// DSN instead of at their state file.
		if isCorruptDatabaseError(err) {
			return "", false, corruptDatabaseError(configured, err)
		}
		return "", false, fmt.Errorf("query the opened database file: %w", err)
	}
	defer rows.Close()

	var path string
	for rows.Next() {
		var (
			seq  int
			name string
			file string
		)
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", false, fmt.Errorf("scan database_list: %w", err)
		}
		if name == "main" {
			path = file
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("read database_list: %w", err)
	}
	if path == "" {
		return "", false, fmt.Errorf(
			"cannot determine which file the state database was opened as (configured statePath %q); "+
				"refusing to continue without being able to guarantee its permissions", configured)
	}

	// Tighten before anyone can read it, and verify: a failure here is not cosmetic.
	// Note this runs on the path the driver reported, not on the configured string,
	// which is the whole point: the two differ exactly when the DSN was misparsed.
	if err := os.Chmod(path, 0o600); err != nil {
		return "", false, fmt.Errorf("chmod state file %s: %w", path, err)
	}

	// A plain symlink (macOS's /var -> /private/var, say) makes the reported path
	// differ from the configured one without anything being wrong: the two names
	// reach the same file. Only a difference that survives that resolution is
	// evidence that the DSN named a different file -- the failure this check exists
	// to make impossible.
	if path != configured {
		if real, rerr := filepath.EvalSymlinks(configured); rerr != nil || real != path {
			return path, true, nil
		}
	}
	return path, false, nil
}

// Close closes the state database and releases the cross-process lock.
func (s *Store) Close() error {
	// Wait for an in-flight operation before closing.
	//
	// Every statement goes through s.mu (WithTx holds it for the whole transaction), so closing
	// without it let a transaction that was already running COMMIT after Close returned -- and after
	// the flock was released, so a second process could be writing at the same time. The direction
	// was favourable for the data (the promotion landed), but the shutdown warning in cmd/wecert
	// describes the opposite mechanism, and "the store is closed" has to mean no writer is still
	// inside it.
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.db.Close()
	if relErr := s.lock.release(); err == nil {
		err = relErr
	}
	return err
}

func toUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

// ---------- Account ----------

// GetAccount reads the account; returns (nil, nil) when it does not exist.
