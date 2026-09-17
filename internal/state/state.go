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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure Go driver: no CGO, which keeps static builds easy
)

// maxLastErrorBytes bounds the upstream error text persisted per row.
//
// last_error carries remote text verbatim: lego embeds the entire non-JSON ACME
// error body in its errors, and the CVM metadata path echoes response bodies. Left
// unbounded it is both a growth vector and a channel for remote-controlled text
// that /hook/status serves to callers and notifyURL posts off-host.
const maxLastErrorBytes = 512

// Store is the state store layered on top of SQLite.
// execer is the subset of *sql.DB and *sql.Tx the write helpers below use, so one body of SQL can
// run either on its own or inside a caller's transaction (see tx.go). Without it, every
// transactional variant would be a copy of the statement, and the copy is what drifts.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

type Store struct {
	db *sql.DB

	// mu serialises whole operations, not individual statements.
	//
	// The pool is capped at one connection, which serialises statements but NOT a
	// read-modify-write sequence: two goroutines can both read a row, both modify their
	// copy, and both write it back, losing an update. It is not hypothetical -- a scratch
	// run of 50 concurrent GetCert/++/PutCert cycles landed as 3.
	//
	// Fixing the sequence is not something the store can do to a caller that hand-rolls it,
	// so UpdateCert exists for exactly this: it holds mu across read, mutate and write. The
	// mutex here additionally guarantees that nothing in this package can interleave with a
	// multi-statement operation, and that adding a second writer later cannot corrupt state
	// silently -- a guarantee that belongs with the data rather than with one caller's
	// discipline.
	mu sync.Mutex

	// lock is the cross-process exclusive lock.
	//
	// The "at most one in-flight order per certificate" invariant used to hold only
	// **within a single process**. With daemon and timer modes both enabled, each
	// process keeps its own local view, so the same certificate gets ordered twice --
	// and what you hit is
	// "5 certificates per exact set of identifiers / 7 days",
	// a limit with no override: trip it and you wait the full 7 days.
	lock *fileLock

	// base is the state file's own name, used to prefix snapshot filenames.
	//
	// Snapshot names used to hardcode "state", so two deployments sharing one
	// stateBackup.dir wrote and pruned the SAME files: each one's retention deleted the
	// other's backups, and the survivor was whichever ran last. Nothing refuses a shared
	// directory -- it is a reasonable thing to configure, and the config layer cannot see
	// who else writes there -- so the name has to carry the identity.
	base string
}

// ErrLocked means the state database is already held exclusively by another wecert
// process.
//
// This is not an anomaly, it is a gate that has to exist. See the Store.lock comment.
var ErrLocked = errors.New("the state database is already held by another wecert process")

// ErrBackoff means a certificate is inside the retry window an earlier failure scheduled,
// so the pass deliberately did not run.
//
// It lives here rather than in the acme or reconcile package because BOTH need it and they
// do not import each other -- reconcile drives the manager through an interface on purpose
// (see reconcile.CertManager), so the shared vocabulary for "this certificate is not
// actionable right now" belongs in the layer they have in common. `NextAttemptAt` is
// persisted state, so this is the retry state's natural home.
//
// Why it exists: Reconcile used to return nil when it skipped a pass for backoff, which made
// the caller count the pass as result="ok" and POST a success notification for a certificate
// that was in failure backoff -- the opposite of the truth, on the signal an operator uses to
// decide whether anything is progressing.
//
// It is deliberately not a failure: nothing went wrong, and treating it as an error would
// inflate the error rate and emit a failure every interval for a certificate that is simply
// waiting.
var ErrBackoff = errors.New("inside the retry backoff window; this pass did not run")

// CertState is the runtime state of one certificate (the status of config.Certificate).
type CertState struct {
	Name string

	// The certificate currently in effect.
	NotAfter time.Time
	CertURL  string
	CertPEM  []byte
	KeyPEM   []byte
	IssuedAt time.Time

	// ARI (RFC 9773). CertID = base64url(AKI) + "." + base64url(Serial).
	ARICertID      string
	ARIWindowStart time.Time
	ARIWindowEnd   time.Time
	ARICheckedAt   time.Time
	ARIRetryAfter  time.Duration

	// Failure backoff. After tripping
	// "5 authorization failures per identifier per hour", hammering retries only
	// makes things worse, so there has to be a ceiling here that hands off to a human.
	ConsecutiveFailures int
	NextAttemptAt       time.Time
	LastError           string

	// The certificate ID currently active on the Tencent Cloud side, passed as
	// UpdateCertificateInstance's OldCertificateId.
	// An empty string means it was never bound and a human has to bind it once.
	DeployedCertID string

	// DeployConfirmed means "the certificate is genuinely live on the cloud
	// resource", not merely uploaded successfully.
	// After the first upload returns a CertId, a human still has to bind it on the
	// CLB; until that happens it does not count as deployed -- otherwise the expiry
	// alert sees deployed=1 and assumes everything is fine.
	DeployConfirmed bool

	UpdatedAt time.Time
}

// Order is an in-flight ACME order.
//
// KeyPEM is the private key generated while issuing this order. It must hang off the
// order rather than overwriting CertState.KeyPEM directly -- otherwise a failed
// deploy wipes out the private key of the certificate currently in service. Only
// once the new certificate is successfully live is KeyPEM promoted to the active key.
type Order struct {
	CertName    string
	OrderURL    string
	FinalizeURL string
	CertURL     string
	ExpiresAt   time.Time
	Status      string
	KeyPEM      []byte

	// Identifiers is the identifier set submitted when this order was created
	// (canonical form, see config.DomainKey). An empty string means the order came
	// from an older version and has no such record.
	//
	// Why it must be stored: an order's identifier set is fixed at the moment of
	// newOrder. If domains are later changed in config, the CSR no longer matches the
	// order and the CA keeps rejecting finalize. The "never create a new order"
	// invariant then makes the program keep pushing the same broken order, so it
	// stalls until the order expires 7 days later -- and during that window no domain
	// change for that certificate can take effect.
	Identifiers string

	// DeploymentCertID is an uploaded certificate whose asynchronous rebind has not
	// completed yet. Keeping it with the order makes retry idempotent across restarts:
	// never upload a second copy while the first task may still finish.
	DeploymentCertID string
}

// Authorization is one identifier authorization inside an order.
//
// Note: wildcard and apex authorizations land on the same TXT name
// (`example.com` and `*.example.com` both write `_acme-challenge.example.com`),
// so rows here are stored per authz URL and each holds its own TXT value, with the
// manager guaranteeing "write all -> validate all -> only then clean up together".
type Authorization struct {
	CertName       string
	AuthzURL       string
	Identifier     string
	Status         string
	ChallengeURL   string
	ChallengeToken string
	TxtName        string
	TxtValue       string

	// Presented means the TXT has been written into DNS (propagation is not guaranteed).
	Presented bool
	// ChallengeSent means the CA has been POSTed to go and validate.
	ChallengeSent bool
}

// Account is an ACME account.
type Account struct {
	Directory     string
	KID           string
	PrivateKeyPEM []byte
}

// Open opens (creating it if necessary) the state database and takes the
// cross-process exclusive lock.
//
// This file holds the ACME account private key and the private keys of every active
// certificate, so the directory is created first when missing, the file is
// pre-created with 0600, and the whole create/migrate section runs under a
// restrictive umask: SQLite derives the permissions of its own -wal/-shm files
// (copies of the private keys) from the process umask, so on a umask 022 machine
// they would otherwise be born 0644 and stay readable by any local user until the
// post-hoc chmod ran. The systemd path is covered by StateDirectoryMode=0700, but
// manual runs (the README's -dry-run, e2e scripts that put the database in /tmp)
// have no such protection.
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
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create state dir %s: %w", dir, err)
		}
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

	if !existedBefore && lockExisted {
		// See missingDatabaseWarning: a lock file with no database is what "someone deleted
		// state.db" looks like. Warn rather than refuse -- a first run after restoring a
		// backup, or an operator deliberately starting clean, are both legitimate -- but it
		// must be loud, because the account key and every in-flight order are gone and the
		// next issuance re-places orders.
		fmt.Fprintf(os.Stderr, "wecert: WARNING: %s\n", missingDatabaseWarning(path))
	}

	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
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

	s := &Store{db: db, lock: lock, base: filepath.Base(path)}

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
	return fmt.Errorf(
		"the state database %s is corrupt: %v\n"+
			"       wecert will not start against a database it cannot read. Restore the backup that "+
			"docs/recovery.md describes (state.db together with its -wal), or move the damaged file "+
			"aside to start from an empty database -- which registers a new ACME account and re-places "+
			"orders, so prefer the backup. See docs/recovery.md.",
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
				"       wecert will not start against a database it cannot trust. Restore a backup of "+
				"state.db (and its -wal) if you have one, or move the damaged file aside to start from an "+
				"empty one -- losing it means a new ACME account and re-placed orders. See docs/recovery.md.",
			err)
	}
	if result != "ok" {
		//lint:ignore ST1005 the second paragraph of a multi-line operator instruction is a sentence;
		// capitalising it is the point, and the first paragraph still starts lowercase.
		return fmt.Errorf(
			"the state database failed its consistency check: %s\n"+
				"       Restore a backup of state.db if you have one, or move the damaged file aside to "+
				"start from an empty one -- losing it means a new ACME account and re-placed orders. "+
				"See docs/recovery.md.",
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
	err := s.db.Close()
	if relErr := s.lock.release(); err == nil {
		err = relErr
	}
	return err
}

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS accounts (
    directory       TEXT PRIMARY KEY,
    kid             TEXT NOT NULL,
    private_key_pem BLOB NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
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
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    next_attempt_at        INTEGER NOT NULL DEFAULT 0,
    last_error             TEXT    NOT NULL DEFAULT '',
    deployed_cert_id       TEXT    NOT NULL DEFAULT '',
    -- Upload success != bound to the listener. Only set once the one-click update
    -- has actually swapped it over; otherwise the first upload is treated as
    -- "deployed" and metrics go green before a human has bound anything.
    deploy_confirmed       INTEGER NOT NULL DEFAULT 0,
    updated_at             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
    cert_name    TEXT PRIMARY KEY,
    order_url    TEXT NOT NULL,
    finalize_url TEXT NOT NULL DEFAULT '',
    cert_url     TEXT NOT NULL DEFAULT '',
    expires_at   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT '',
    key_pem      BLOB,
    -- The identifier set submitted at newOrder time (canonical form, see config.DomainKey).
    identifiers  TEXT NOT NULL DEFAULT '',
    deployment_cert_id TEXT NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authorizations (
    cert_name       TEXT NOT NULL,
    authz_url       TEXT NOT NULL,
    identifier      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT '',
    challenge_url   TEXT NOT NULL DEFAULT '',
    challenge_token TEXT NOT NULL DEFAULT '',
    txt_name        TEXT NOT NULL DEFAULT '',
    txt_value       TEXT NOT NULL DEFAULT '',
    presented       INTEGER NOT NULL DEFAULT 0,
    challenge_sent  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cert_name, authz_url)
);

-- Cloud certificates that are retired but not yet deleted. Kept for a while to allow
-- rollback, then they must be reclaimed: Tencent Cloud accounts have a quota on the
-- number of uploaded certificates.
--
-- cert_pem / key_pem are the archived material for the retired certificate, so it can be
-- re-uploaded and re-bound during the retention window.
--
-- This table used to hold only the CertId, and the retired certificate's key was
-- overwritten in the certificates row at the moment of renewal -- so "rollback" meant
-- "whatever the cloud still has", and after the retention period deleted it, wecert had
-- nothing to restore from. The comment here and in the deployer claimed rollback was the
-- point; now the material is actually retained, and pruned with the row.
CREATE TABLE IF NOT EXISTS retired_certificates (
    cert_id    TEXT PRIMARY KEY,
    cert_name  TEXT NOT NULL,
    retired_at INTEGER NOT NULL,
    cert_pem   BLOB,
    key_pem    BLOB
);

-- Per-identifier authorization failure ledger.
--
-- The certificate-level consecutive_failures only tells you "this certificate cannot
-- be issued", whereas pre-expiry fallback has to answer "**which name** cannot be
-- issued" -- without that, the only option is dropping names at random, which
-- sacrifices names that were fine to begin with.
--
-- last_failed_at also provides self-healing: once a failure record ages out, that
-- identifier stops being dropped and the next round naturally retries the full set.
-- No extra retry state is needed.
CREATE TABLE IF NOT EXISTS identifier_failures (
    cert_name      TEXT NOT NULL,
    identifier     TEXT NOT NULL,
    failures       INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT NOT NULL DEFAULT '',
    last_failed_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cert_name, identifier)
);

-- The currently active fallback state: this certificate is serving a certificate that
-- is missing some names.
--
-- A separate table rather than extra columns on certificates: this is not a property
-- of the certificate but an "incident in progress", and its lifecycle is completely
-- different -- it should be cleared once the full set issues successfully, while
-- certificate renewal must not touch it.
CREATE TABLE IF NOT EXISTS cert_fallback (
    cert_name TEXT PRIMARY KEY,
    dropped   TEXT NOT NULL DEFAULT '',
    since     INTEGER NOT NULL DEFAULT 0,
    reason    TEXT NOT NULL DEFAULT ''
);

-- Rate-limit bucket snapshots.
--
-- Let's Encrypt publishes its limits and their token-bucket refill rates but offers no way
-- to query the remaining allowance, so the only way to answer "how much is left" is to
-- account for what this program spent. A bucket needs no event log: the model is the memory,
-- so one row per (limit, scope) holding the last known level and when it was observed can be
-- rolled forward to any later instant.
--
-- scope_id is empty for account-wide limits and holds the registered domain / identifier
-- otherwise. reset_at is an AUTHORITATIVE instant the CA reported ("retry after ..."), which
-- beats the local estimate because the estimate cannot see other accounts spending the same
-- global bucket.
-- Revocation requests that have not succeeded yet.
--
-- A row here means "an operator decided this certificate must be revoked, and the CA has not
-- accepted it yet". Persisted rather than attempted once because revocation can fail for
-- entirely transient reasons (network, CA 5xx) and the decision must not be lost with the
-- process: a leaked private key does not stop being leaked because the request timed out.
--
-- The alternative -- only revoking synchronously from a CLI -- leaves a failed attempt as a
-- message on someone's terminal, with no record that the operator ever asked.
--
-- reason is the RFC 5280 CRLReason code, so the reason the operator chose survives into every
-- retry rather than being lost after the first attempt.
CREATE TABLE IF NOT EXISTS revoke_requests (
    cert_name   TEXT PRIMARY KEY,
    reason      INTEGER NOT NULL DEFAULT 0,
    -- The certificate the operator asked to revoke, as an identity derived from its material
    -- (see acme.certIdentity). Without it the retry revoked "whatever is stored under this name
    -- now" -- and a renewal between the request and the retry replaces exactly that, so the
    -- request could revoke the NEW certificate while the compromised one stayed valid, then
    -- clear itself as a success. Empty means unknown: a request recorded by an older build.
    cert_identity TEXT NOT NULL DEFAULT '',
    requested_at INTEGER NOT NULL DEFAULT 0,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT NOT NULL DEFAULT '',
    last_attempt_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rate_buckets (
    limit_name TEXT NOT NULL,
    scope_id   TEXT NOT NULL DEFAULT '',
    tokens     REAL NOT NULL DEFAULT 0,
    observed_at INTEGER NOT NULL DEFAULT 0,
    reset_at   INTEGER NOT NULL DEFAULT 0,
    reset_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (limit_name, scope_id)
);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// CREATE TABLE IF NOT EXISTS does not add columns to an **existing** table, so
	// patch old databases separately. The package-level warning -- "losing it means
	// hitting the rate limit" -- applies here too: on upgrade, one extra migration
	// step is always better than demanding that users delete and rebuild the database.
	for _, m := range schemaColumns {
		if err := s.ensureColumn(m.table, m.column, m.decl); err != nil {
			return err
		}
	}
	return nil
}

// schemaTables are the tables this binary creates.
//
// Declared as data for the same reason schemaColumns is: an unlocked open has to be able to say
// whether the database in front of it is one this build understands, without applying anything.
var schemaTables = []string{
	"accounts",
	"certificates",
	"orders",
	"authorizations",
	"retired_certificates",
	"identifier_failures",
	"cert_fallback",
	"revoke_requests",
	"rate_buckets",
}

// schemaColumns are the columns added to tables that predate them.
//
// Declared as data, and read by both migrate (which adds them) and pendingMigrations (which only
// reports them), so the unlocked open cannot drift into believing a database is current when it is
// not. A missing column here is a missing migration on both paths at once, which the daemon's own
// migrate call still applies -- the unlocked path simply keeps refusing.
var schemaColumns = []struct{ table, column, decl string }{
	{"certificates", "deploy_confirmed", "INTEGER NOT NULL DEFAULT 0"},
	{"orders", "identifiers", "TEXT NOT NULL DEFAULT ''"},
	{"orders", "deployment_cert_id", "TEXT NOT NULL DEFAULT ''"},
	// Rollback material. Legacy rows keep NULL: there is nothing to recover for a
	// certificate retired before wecert started archiving, and inventing an empty
	// value would look like a usable (empty) certificate.
	{"retired_certificates", "cert_pem", "BLOB"},
	{"retired_certificates", "key_pem", "BLOB"},
	// Certificate identity on a pending revocation. Legacy rows keep the empty default, which
	// reads as "unknown" and makes the retry fall back to the pre-column behaviour (revoke the
	// material stored now); inventing an identity would make the retry refuse to act on the
	// operator's request for a reason that was not true when they made it.
	{"revoke_requests", "cert_identity", "TEXT NOT NULL DEFAULT ''"},
}

// pendingMigrations reports schema changes this binary would apply, without applying them.
//
// It is what an unlocked open uses instead of migrating. Check-then-act ALTER TABLE is not safe
// between processes, and the loser of that race aborts the whole open with `duplicate column name`,
// which names neither the cause nor the fix.
func (s *Store) pendingMigrations() ([]string, error) {
	var out []string
	// Tables first, then columns.
	//
	// Checking only columns let an unlocked open accept a database that was missing one of the
	// tables this build adds (the column check cannot see a table that is not there at all), and the
	// operator then got a raw `no such table: revoke_requests` from whichever operation happened to
	// touch it, instead of the "this binary needs a schema update, stop the process and run wecert
	// -once" instruction that exists for exactly this. Reachable for any database written by a build
	// whose column set is current but which predates a table -- which is every release that adds one.
	for _, t := range schemaTables {
		exists, err := s.tableExists(t)
		if err != nil {
			return nil, err
		}
		if !exists {
			out = append(out, t)
		}
	}
	for _, m := range schemaColumns {
		exists, err := s.columnExists(m.table, m.column)
		if err != nil {
			return nil, err
		}
		if !exists {
			out = append(out, m.table+"."+m.column)
		}
	}
	return out, nil
}

// tableExists reports whether the store's schema contains a table.
func (s *Store) tableExists(table string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check table %s: %w", table, err)
	}
	return n > 0, nil
}

// ensureColumn adds a column to a table (when it does not already exist).
//
// columnExists closing rows itself before returning is deliberate: the pool is capped
// at MaxOpenConns(1), and relying on the implicit close triggered by iterating rows to
// EOF to free the connection is too subtle -- if someone changes the loop below to
// return early, ALTER blocks forever waiting for a connection.
func (s *Store) ensureColumn(table, column, decl string) error {
	exists, err := s.columnExists(table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	// String concatenation instead of placeholders here: SQLite DDL does not accept
	// parameterized column names or types. All three arguments are literals in the
	// code and contain no user input.
	if _, err := s.db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + decl); err != nil {
		return fmt.Errorf("alter %s add %s: %w", table, column, err)
	}
	return nil
}

func (s *Store) columnExists(table, column string) (bool, error) {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, fmt.Errorf("pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return false, fmt.Errorf("scan table_info(%s): %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ---------- Time helpers: SQLite stores unix seconds throughout, 0 means zero value ----------

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
func (s *Store) GetAccount(directory string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(
		`SELECT directory, kid, private_key_pem FROM accounts WHERE directory = ?`, directory)
	a := &Account{}
	err := row.Scan(&a.Directory, &a.KID, &a.PrivateKeyPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	return a, nil
}

// PutAccountWithoutKey writes an account row whose private key is empty.
//
// Only for tests and for reproducing a legacy row. It cannot be written as NULL --
// private_key_pem is declared NOT NULL, which is the point of checking the length rather than
// nil-ness in the loader: a row from a database written before that constraint existed reads
// back as nil, and an empty blob reads back the same way. Both mean "no usable key".
func (s *Store) PutAccountWithoutKey(directory, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO accounts (directory, kid, private_key_pem, updated_at) VALUES (?, ?, x'', ?)`,
		directory, kid, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put account %s without a key: %w", directory, err)
	}
	return nil
}

// PutAccount writes the account.
func (s *Store) PutAccount(a *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO accounts (directory, kid, private_key_pem, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(directory) DO UPDATE SET
			kid = excluded.kid,
			private_key_pem = excluded.private_key_pem,
			updated_at = excluded.updated_at`,
		a.Directory, a.KID, a.PrivateKeyPEM, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put account: %w", err)
	}
	return nil
}

// ---------- CertState ----------

// ListCertNames returns every certificate name in the state database, sorted.
//
// Its purpose is the "orphan check": a certificate present in the state database but
// gone from the desired state will never be renewed again and will quietly expire.
// Making this set visible is the only backstop for that failure path.
func (s *Store) ListCertNames() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT name FROM certificates ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list certificate names: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan certificate name: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// UpdateCert applies fn to one certificate's state and writes the result back, all while
// holding the store lock.
//
// This is the form callers should prefer over GetCert followed by PutCert: the read and
// the write have to be one operation or a concurrent writer's change is silently lost.
// fn must not call back into the Store.
//
// A missing row is an error rather than an upsert: a name typo should surface, not create
// a phantom certificate that then appears in the orphan report.
func (s *Store) UpdateCert(name string, fn func(*CertState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.getCertLocked(name)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("update cert %s: no such certificate in the state store", name)
	}
	if err := fn(st); err != nil {
		return err
	}
	return s.putCertLocked(st)
}

// GetCert reads certificate state; returns (nil, nil) when it does not exist.
func (s *Store) GetCert(name string) (*CertState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getCertLocked(name)
}

func (s *Store) getCertLocked(name string) (*CertState, error) {
	row := s.db.QueryRow(`
		SELECT name, not_after, cert_url, cert_pem, key_pem, issued_at,
		       ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
		       consecutive_failures, next_attempt_at, last_error, deployed_cert_id,
		       deploy_confirmed, updated_at
		FROM certificates WHERE name = ?`, name)

	c := &CertState{}
	var notAfter, issuedAt, ariStart, ariEnd, ariChecked, nextAttempt, updatedAt int64
	var retryAfterNS int64
	var deployConfirmed bool

	err := row.Scan(
		&c.Name, &notAfter, &c.CertURL, &c.CertPEM, &c.KeyPEM, &issuedAt,
		&c.ARICertID, &ariStart, &ariEnd, &ariChecked, &retryAfterNS,
		&c.ConsecutiveFailures, &nextAttempt, &c.LastError, &c.DeployedCertID,
		&deployConfirmed, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cert %s: %w", name, err)
	}

	c.NotAfter = fromUnix(notAfter)
	c.IssuedAt = fromUnix(issuedAt)
	c.ARIWindowStart = fromUnix(ariStart)
	c.ARIWindowEnd = fromUnix(ariEnd)
	c.ARICheckedAt = fromUnix(ariChecked)
	c.ARIRetryAfter = time.Duration(retryAfterNS)
	c.NextAttemptAt = fromUnix(nextAttempt)
	c.DeployConfirmed = deployConfirmed
	c.UpdatedAt = fromUnix(updatedAt)
	return c, nil
}

// PutCert writes certificate state.
func (s *Store) PutCert(c *CertState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putCertLocked(c)
}

func (s *Store) putCertLocked(c *CertState) error { return putCertExec(s.db, c) }

func putCertExec(e execer, c *CertState) error {
	_, err := e.Exec(`
		INSERT INTO certificates (
			name, not_after, cert_url, cert_pem, key_pem, issued_at,
			ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
			consecutive_failures, next_attempt_at, last_error, deployed_cert_id,
			deploy_confirmed, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			not_after            = excluded.not_after,
			cert_url             = excluded.cert_url,
			cert_pem             = excluded.cert_pem,
			key_pem              = excluded.key_pem,
			issued_at            = excluded.issued_at,
			ari_cert_id          = excluded.ari_cert_id,
			ari_window_start     = excluded.ari_window_start,
			ari_window_end       = excluded.ari_window_end,
			ari_checked_at       = excluded.ari_checked_at,
			ari_retry_after_ns   = excluded.ari_retry_after_ns,
			consecutive_failures = excluded.consecutive_failures,
			next_attempt_at      = excluded.next_attempt_at,
			last_error           = excluded.last_error,
			deployed_cert_id     = excluded.deployed_cert_id,
			deploy_confirmed     = excluded.deploy_confirmed,
			updated_at           = excluded.updated_at`,
		c.Name, toUnix(c.NotAfter), c.CertURL, c.CertPEM, c.KeyPEM, toUnix(c.IssuedAt),
		c.ARICertID, toUnix(c.ARIWindowStart), toUnix(c.ARIWindowEnd), toUnix(c.ARICheckedAt),
		int64(c.ARIRetryAfter),
		// Truncated at the one place every caller funnels through, not in each
		// producer. last_error carries upstream text: lego embeds the whole non-JSON
		// ACME error body in its errors, and the CVM metadata path echoes part of a
		// response body. Unbounded, that is both a growth vector and remote-controlled
		// text that /hook/status serves and notifyURL posts off-host. The identifier
		// ledger already bounds its equivalent at 512 (fallback.go); this is the same
		// rule applied where it cannot be forgotten.
		c.ConsecutiveFailures, toUnix(c.NextAttemptAt), truncate(c.LastError, maxLastErrorBytes),
		c.DeployedCertID, c.DeployConfirmed, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put cert %s: %w", c.Name, err)
	}
	return nil
}

// ---------- Order ----------

// GetOrder reads the in-flight order; returns (nil, nil) when it does not exist.
func (s *Store) GetOrder(certName string) (*Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`
		SELECT cert_name, order_url, finalize_url, cert_url, expires_at, status, key_pem, identifiers, deployment_cert_id
		FROM orders WHERE cert_name = ?`, certName)

	o := &Order{}
	var expiresAt int64
	err := row.Scan(&o.CertName, &o.OrderURL, &o.FinalizeURL, &o.CertURL, &expiresAt,
		&o.Status, &o.KeyPEM, &o.Identifiers, &o.DeploymentCertID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get order for %s: %w", certName, err)
	}
	o.ExpiresAt = fromUnix(expiresAt)
	return o, nil
}

// PutOrder writes the in-flight order.
func (s *Store) PutOrder(o *Order) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO orders (
			cert_name, order_url, finalize_url, cert_url, expires_at, status, key_pem, identifiers, deployment_cert_id, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cert_name) DO UPDATE SET
			order_url    = excluded.order_url,
			finalize_url = excluded.finalize_url,
			cert_url     = excluded.cert_url,
			expires_at   = excluded.expires_at,
			status       = excluded.status,
			key_pem      = excluded.key_pem,
			identifiers  = excluded.identifiers,
			deployment_cert_id = excluded.deployment_cert_id,
			updated_at   = excluded.updated_at`,
		o.CertName, o.OrderURL, o.FinalizeURL, o.CertURL, toUnix(o.ExpiresAt), o.Status,
		o.KeyPEM, o.Identifiers, o.DeploymentCertID, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put order for %s: %w", o.CertName, err)
	}
	return nil
}

// DeleteOrder discards the current order (it expired or was abandoned).
func (s *Store) DeleteOrder(certName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return deleteOrderExec(s.db, certName)
}

func deleteOrderExec(e execer, certName string) error {
	if _, err := e.Exec(`DELETE FROM orders WHERE cert_name = ?`, certName); err != nil {
		return fmt.Errorf("delete order for %s: %w", certName, err)
	}
	return nil
}

// ---------- Authorization ----------

// ListAuthorizations lists every authorization under a certificate's order.
func (s *Store) ListAuthorizations(certName string) ([]*Authorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_name, authz_url, identifier, status, challenge_url, challenge_token,
		       txt_name, txt_value, presented, challenge_sent
		FROM authorizations WHERE cert_name = ? ORDER BY authz_url`, certName)
	if err != nil {
		return nil, fmt.Errorf("list authorizations for %s: %w", certName, err)
	}
	defer rows.Close()

	var out []*Authorization
	for rows.Next() {
		a := &Authorization{}
		if err := rows.Scan(&a.CertName, &a.AuthzURL, &a.Identifier, &a.Status,
			&a.ChallengeURL, &a.ChallengeToken, &a.TxtName, &a.TxtValue,
			&a.Presented, &a.ChallengeSent); err != nil {
			return nil, fmt.Errorf("scan authorization: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListPresentedAuthorizations lists every authorization this state store still believes
// has a TXT record in DNS, across all certificates.
//
// It exists for the challenge-lease registry in internal/acme: that registry only knows
// what the current *process* wrote, and lego's cleanup deletes every TXT at the challenge
// name. A row recovered from a previous process is therefore a live value the registry
// cannot see, and a cleanup for a different certificate sharing the name would delete it.
// Re-registering from here before any cleanup closes that window.
func (s *Store) ListPresentedAuthorizations() ([]*Authorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_name, authz_url, identifier, status, challenge_url, challenge_token,
		       txt_name, txt_value, presented, challenge_sent
		FROM authorizations WHERE presented = 1 ORDER BY txt_name, cert_name`)
	if err != nil {
		return nil, fmt.Errorf("list presented authorizations: %w", err)
	}
	defer rows.Close()

	var out []*Authorization
	for rows.Next() {
		a := &Authorization{}
		if err := rows.Scan(&a.CertName, &a.AuthzURL, &a.Identifier, &a.Status,
			&a.ChallengeURL, &a.ChallengeToken, &a.TxtName, &a.TxtValue,
			&a.Presented, &a.ChallengeSent); err != nil {
			return nil, fmt.Errorf("scan presented authorization: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PutAuthorization writes a single authorization.
func (s *Store) PutAuthorization(a *Authorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO authorizations (
			cert_name, authz_url, identifier, status, challenge_url, challenge_token,
			txt_name, txt_value, presented, challenge_sent
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cert_name, authz_url) DO UPDATE SET
			identifier      = excluded.identifier,
			status          = excluded.status,
			challenge_url   = excluded.challenge_url,
			challenge_token = excluded.challenge_token,
			txt_name        = excluded.txt_name,
			txt_value       = excluded.txt_value,
			presented       = excluded.presented,
			challenge_sent  = excluded.challenge_sent`,
		a.CertName, a.AuthzURL, a.Identifier, a.Status, a.ChallengeURL, a.ChallengeToken,
		a.TxtName, a.TxtValue, a.Presented, a.ChallengeSent)
	if err != nil {
		return fmt.Errorf("put authorization %s: %w", a.AuthzURL, err)
	}
	return nil
}

// DeleteAuthorizations clears every authorization record for a certificate.
//
// Note: the manager no longer goes through this -- discarding an order should call
// cleanupOrphanTXT, which first reclaims TXT records still present in DNS and only
// then deletes rows. This method is a backstop for cases that genuinely need the whole
// table cleared (tests or manual intervention, for example).
func (s *Store) DeleteAuthorizations(certName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM authorizations WHERE cert_name = ?`, certName)
	if err != nil {
		return fmt.Errorf("delete authorizations for %s: %w", certName, err)
	}
	return nil
}

// DeleteAuthorization deletes a single authorization record.
// Used to clean up leftover authorization rows whose TXT has already been reclaimed
// and no longer needs tracking.
func (s *Store) DeleteAuthorization(certName, authzURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`DELETE FROM authorizations WHERE cert_name = ? AND authz_url = ?`, certName, authzURL)
	if err != nil {
		return fmt.Errorf("delete authorization %s: %w", authzURL, err)
	}
	return nil
}

// ---------- RetiredCert ----------

// RetiredCert is a cloud certificate taken out of service and kept briefly for rollback.
//
// CertPEM/KeyPEM are the archived material, so the rollback the type's name promises is
// actually possible: without them "rollback" only ever meant "whatever the cloud still
// has", and the cloud copy is deleted at the end of the retention period.
type RetiredCert struct {
	CertID    string
	CertName  string
	RetiredAt time.Time
	CertPEM   []byte
	KeyPEM    []byte
}

// AddRetiredCert records a retired certificate together with its archived key material.
//
// certPEM and keyPEM may be nil when there is nothing to archive (the orphan path records a
// certificate wecert never held a copy of). The row is still useful then: the reaper must
// delete it from the cloud either way.
func (s *Store) AddRetiredCert(certID, certName string, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return addRetiredCertExec(s.db, certID, certName, certPEM, keyPEM)
}

func addRetiredCertExec(e execer, certID, certName string, certPEM, keyPEM []byte) error {
	_, err := e.Exec(`
		INSERT INTO retired_certificates (cert_id, cert_name, retired_at, cert_pem, key_pem)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(cert_id) DO UPDATE SET
		    -- The first writer may have had nothing to archive. The orphan path records a
		    -- certificate it merely uploaded, with NULL material; the retirement path records the
		    -- one that was actually serving, with the fullchain and key. DO NOTHING let whichever
		    -- arrived first win, so a row could keep two NULLs and the documented manual rollback
		    -- (docs/recovery.md) had nothing to restore. COALESCE keeps real material from being
		    -- overwritten by a later empty write, and lets it be filled in when the empty write
		    -- came first.
		    cert_pem = COALESCE(EXCLUDED.cert_pem, retired_certificates.cert_pem),
		    key_pem  = COALESCE(EXCLUDED.key_pem,  retired_certificates.key_pem),
		    -- The clock restarts on the write that actually retires the certificate. Without
		    -- this a row first written by the orphan path (which records a certificate it merely
		    -- uploaded, with no material) kept the ORPHAN's timestamp when the same cert_id was
		    -- later retired with the fullchain and key: ReapRetired, which reaps on retired_at,
		    -- would then delete the cloud copy and the freshly archived rollback material on the
		    -- earlier clock -- and before the rebind it asks to delete a certificate that may
		    -- still be serving, refused only by the cloud-side binding check.
		    retired_at = EXCLUDED.retired_at`,
		certID, certName, time.Now().Unix(), certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("add retired cert %s: %w", certID, err)
	}
	return nil
}

// ListRetiredCertsBefore lists certificates retired before cutoff, for reclamation.
func (s *Store) ListRetiredCertsBefore(cutoff time.Time) ([]*RetiredCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_id, cert_name, retired_at, cert_pem, key_pem
		FROM retired_certificates WHERE retired_at < ?`,
		cutoff.Unix())
	if err != nil {
		return nil, fmt.Errorf("list retired certs: %w", err)
	}
	defer rows.Close()

	var out []*RetiredCert
	for rows.Next() {
		r := &RetiredCert{}
		var retiredAt int64
		if err := rows.Scan(&r.CertID, &r.CertName, &retiredAt, &r.CertPEM, &r.KeyPEM); err != nil {
			return nil, fmt.Errorf("scan retired cert: %w", err)
		}
		r.RetiredAt = fromUnix(retiredAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRetiredCertMaterial returns the archived certificate material of every retired certificate
// recorded under one name, newest first.
//
// Rows without material are skipped: the orphan path records a certificate wecert merely uploaded
// and never held a copy of, and an empty blob would look like a usable (empty) certificate. What
// this answers is "is the certificate the operator asked to revoke still here somewhere", which is
// how a revocation request that outlives its renewal can still be honoured.
func (s *Store) ListRetiredCertMaterial(certName string) ([]*RetiredCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_id, cert_name, retired_at, cert_pem, key_pem
		FROM retired_certificates
		WHERE cert_name = ? AND cert_pem IS NOT NULL
		ORDER BY retired_at DESC`, certName)
	if err != nil {
		return nil, fmt.Errorf("list archived material for %s: %w", certName, err)
	}
	defer rows.Close()

	var out []*RetiredCert
	for rows.Next() {
		r := &RetiredCert{}
		var retiredAt int64
		if err := rows.Scan(&r.CertID, &r.CertName, &retiredAt, &r.CertPEM, &r.KeyPEM); err != nil {
			return nil, fmt.Errorf("scan archived material for %s: %w", certName, err)
		}
		r.RetiredAt = fromUnix(retiredAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRetiredCert removes an entry from the reclamation list (called after the
// cloud-side delete succeeds).
func (s *Store) DeleteRetiredCert(certID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM retired_certificates WHERE cert_id = ?`, certID)
	if err != nil {
		return fmt.Errorf("delete retired cert %s: %w", certID, err)
	}
	return nil
}
