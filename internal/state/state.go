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
	"os"
	"path/filepath"
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
type Store struct {
	db *sql.DB

	// lock is the cross-process exclusive lock.
	//
	// The "at most one in-flight order per certificate" invariant used to hold only
	// **within a single process**. With daemon and timer modes both enabled, each
	// process keeps its own local view, so the same certificate gets ordered twice --
	// and what you hit is
	// "5 certificates per exact set of identifiers / 7 days",
	// a limit with no override: trip it and you wait the full 7 days.
	lock *fileLock
}

// ErrLocked means the state database is already held exclusively by another wecert
// process.
//
// This is not an anomaly, it is a gate that has to exist. See the Store.lock comment.
var ErrLocked = errors.New("the state database is already held by another wecert process")

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
// Only for the one-shot validation path (-dry-run): it almost always runs while the
// daemon is up, and "you cannot even validate the config because the daemon is
// running" pushes people into editing the config blindly. This path only reads the
// existing ACME account and initiates no issuance, so skipping the lock is safe.
func OpenUnlocked(path string) (*Store, error) { return open(path, false) }

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

	s, err := openFiles(path, lock)
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
func openFiles(path string, lock *fileLock) (*Store, error) {
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

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	// modernc sqlite is a single-writer model, so cap connections to avoid SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, lock: lock}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	// -wal / -shm only really appear after migrate, so tighten all permissions once.
	// The WAL file is a copy of the private keys, so its permissions must be managed
	// along with the rest.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0o600); err != nil && !os.IsNotExist(err) {
			db.Close()
			return nil, fmt.Errorf("chmod state file %s: %w", path+suffix, err)
		}
	}
	return s, nil
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
CREATE TABLE IF NOT EXISTS retired_certificates (
    cert_id    TEXT PRIMARY KEY,
    cert_name  TEXT NOT NULL,
    retired_at INTEGER NOT NULL
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
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// CREATE TABLE IF NOT EXISTS does not add columns to an **existing** table, so
	// patch old databases separately. The package-level warning -- "losing it means
	// hitting the rate limit" -- applies here too: on upgrade, one extra migration
	// step is always better than demanding that users delete and rebuild the database.
	for _, m := range []struct{ table, column, decl string }{
		{"certificates", "deploy_confirmed", "INTEGER NOT NULL DEFAULT 0"},
		{"orders", "identifiers", "TEXT NOT NULL DEFAULT ''"},
		{"orders", "deployment_cert_id", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.ensureColumn(m.table, m.column, m.decl); err != nil {
			return err
		}
	}
	return nil
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

// PutAccount writes the account.
func (s *Store) PutAccount(a *Account) error {
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

// GetCert reads certificate state; returns (nil, nil) when it does not exist.
func (s *Store) GetCert(name string) (*CertState, error) {
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
	_, err := s.db.Exec(`
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
	_, err := s.db.Exec(`DELETE FROM orders WHERE cert_name = ?`, certName)
	if err != nil {
		return fmt.Errorf("delete order for %s: %w", certName, err)
	}
	return nil
}

// ---------- Authorization ----------

// ListAuthorizations lists every authorization under a certificate's order.
func (s *Store) ListAuthorizations(certName string) ([]*Authorization, error) {
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
	_, err := s.db.Exec(
		`DELETE FROM authorizations WHERE cert_name = ? AND authz_url = ?`, certName, authzURL)
	if err != nil {
		return fmt.Errorf("delete authorization %s: %w", authzURL, err)
	}
	return nil
}

// ---------- RetiredCert ----------

// RetiredCert is a cloud certificate taken out of service and kept briefly for rollback.
type RetiredCert struct {
	CertID    string
	CertName  string
	RetiredAt time.Time
}

// AddRetiredCert records a retired certificate.
func (s *Store) AddRetiredCert(certID, certName string) error {
	_, err := s.db.Exec(`
		INSERT INTO retired_certificates (cert_id, cert_name, retired_at) VALUES (?, ?, ?)
		ON CONFLICT(cert_id) DO NOTHING`,
		certID, certName, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("add retired cert %s: %w", certID, err)
	}
	return nil
}

// ListRetiredCertsBefore lists certificates retired before cutoff, for reclamation.
func (s *Store) ListRetiredCertsBefore(cutoff time.Time) ([]*RetiredCert, error) {
	rows, err := s.db.Query(`
		SELECT cert_id, cert_name, retired_at FROM retired_certificates WHERE retired_at < ?`,
		cutoff.Unix())
	if err != nil {
		return nil, fmt.Errorf("list retired certs: %w", err)
	}
	defer rows.Close()

	var out []*RetiredCert
	for rows.Next() {
		r := &RetiredCert{}
		var retiredAt int64
		if err := rows.Scan(&r.CertID, &r.CertName, &retiredAt); err != nil {
			return nil, fmt.Errorf("scan retired cert: %w", err)
		}
		r.RetiredAt = fromUnix(retiredAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRetiredCert removes an entry from the reclamation list (called after the
// cloud-side delete succeeds).
func (s *Store) DeleteRetiredCert(certID string) error {
	_, err := s.db.Exec(`DELETE FROM retired_certificates WHERE cert_id = ?`, certID)
	if err != nil {
		return fmt.Errorf("delete retired cert %s: %w", certID, err)
	}
	return nil
}
