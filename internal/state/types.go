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
	_ "modernc.org/sqlite"
	"os"
	"sync"
	"time"
)

// Split out so one concern lives in one file. Same package.

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

	// path is where this store's database lives, and openedAs is the identity of the file that was
	// opened. VerifyOnDisk compares them later: SQLite keeps writing to an inode that has been
	// unlinked or replaced, so a `rm -rf` of the state directory (or a snapshot restored under a
	// running daemon) produces writes that succeed, reads that succeed, and a next start that holds
	// nothing -- with no error anywhere in between. openedAs is always set: openFiles refuses to
	// open a database it cannot stat, precisely so this check can never be silently disabled.
	path     string
	openedAs os.FileInfo

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

	// OrphanCleanedAt is when this name's orphan teardown finished; zero means never (or that the
	// row came back into the desired state since, which clears it).
	//
	// It is read here so the two paths that need it already have it: the orphan sweep reads it in
	// the same query that lists the names (ListOrphanRows), and a certificate being reconciled
	// reads it in the row it fetches anyway (reconcile.publish), where a non-zero value means the
	// name came back and the mark has to go.
	//
	// PutCert deliberately does NOT write this column, and that is the point rather than an
	// oversight: PutCert is a whole-row upsert, and the failure path already synthesises a
	// CertState from a partial read (see RecordFailure), so a full-column write would silently
	// erase the mark for a name that is still an orphan -- putting the whole fleet's teardown cost
	// back on every pass, for a reason nothing in the journal would explain. The mark is written
	// by MarkOrphanCleaned and cleared by ClearOrphanCleaned, and by nothing else.
	OrphanCleanedAt time.Time

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

	// ChallengePreparedAt is when the challenge currently in this row was chosen. Zero means the
	// row predates the column (or was written by a path that does not pick a challenge), and the
	// reader treats it as "age unknown" rather than as "just now".
	ChallengePreparedAt time.Time
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
