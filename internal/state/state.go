// Package state 是 wecert 的持久化层。
package state

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type CertState struct {
	Name string

	NotAfter time.Time
	CertURL  string
	CertPEM  []byte
	KeyPEM   []byte
	IssuedAt time.Time

	ARICertID      string
	ARIWindowStart time.Time
	ARIWindowEnd   time.Time
	ARICheckedAt   time.Time
	ARIRetryAfter  time.Duration

	ConsecutiveFailures int
	NextAttemptAt       time.Time
	LastError           string

	DeployedCertID  string
	DeployConfirmed bool
	UpdatedAt       time.Time
}

type Order struct {
	CertName    string
	OrderURL    string
	FinalizeURL string
	CertURL     string
	ExpiresAt   time.Time
	Status      string
	KeyPEM      []byte
}

type Authorization struct {
	CertName       string
	AuthzURL       string
	Identifier     string
	Status         string
	ChallengeURL   string
	ChallengeToken string
	TxtName        string
	TxtValue       string
	Presented      bool
	ChallengeSent  bool
}

type Account struct {
	Directory     string
	KID           string
	PrivateKeyPEM []byte
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

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
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    next_attempt_at      INTEGER NOT NULL DEFAULT 0,
    last_error           TEXT    NOT NULL DEFAULT '',
    deployed_cert_id     TEXT    NOT NULL DEFAULT '',
    deploy_confirmed     INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
    cert_name    TEXT PRIMARY KEY,
    order_url    TEXT NOT NULL,
    finalize_url TEXT NOT NULL DEFAULT '',
    cert_url     TEXT NOT NULL DEFAULT '',
    expires_at   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT '',
    key_pem      BLOB,
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

CREATE TABLE IF NOT EXISTS retired_certificates (
    cert_id    TEXT PRIMARY KEY,
    cert_name  TEXT NOT NULL,
    retired_at INTEGER NOT NULL
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := s.ensureColumn("certificates", "deploy_confirmed", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureColumn(table, column, decl string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return fmt.Errorf("pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("scan table_info: %w", err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl))
	if err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
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

func toBoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) GetAccount(directory string) (*Account, error) {
	row := s.db.QueryRow(`SELECT directory, kid, private_key_pem FROM accounts WHERE directory = ?`, directory)
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

func (s *Store) GetCert(name string) (*CertState, error) {
	row := s.db.QueryRow(`
		SELECT name, not_after, cert_url, cert_pem, key_pem, issued_at,
		       ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
		       consecutive_failures, next_attempt_at, last_error, deployed_cert_id, deploy_confirmed, updated_at
		FROM certificates WHERE name = ?`, name)

	c := &CertState{}
	var notAfter, issuedAt, ariStart, ariEnd, ariChecked, nextAttempt, updatedAt int64
	var retryAfterNS int64
	var deployConfirmed int

	err := row.Scan(
		&c.Name, &notAfter, &c.CertURL, &c.CertPEM, &c.KeyPEM, &issuedAt,
		&c.ARICertID, &ariStart, &ariEnd, &ariChecked, &retryAfterNS,
		&c.ConsecutiveFailures, &nextAttempt, &c.LastError, &c.DeployedCertID, &deployConfirmed, &updatedAt)
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
	c.DeployConfirmed = deployConfirmed != 0
	c.UpdatedAt = fromUnix(updatedAt)
	return c, nil
}

func (s *Store) PutCert(c *CertState) error {
	_, err := s.db.Exec(`
		INSERT INTO certificates (
			name, not_after, cert_url, cert_pem, key_pem, issued_at,
			ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
			consecutive_failures, next_attempt_at, last_error, deployed_cert_id, deploy_confirmed, updated_at
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
		c.ConsecutiveFailures, toUnix(c.NextAttemptAt), c.LastError, c.DeployedCertID, toBoolInt(c.DeployConfirmed),
		time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put cert %s: %w", c.Name, err)
	}
	return nil
}

func (s *Store) GetOrder(certName string) (*Order, error) {
	row := s.db.QueryRow(`
		SELECT cert_name, order_url, finalize_url, cert_url, expires_at, status, key_pem
		FROM orders WHERE cert_name = ?`, certName)
	o := &Order{}
	var expiresAt int64
	err := row.Scan(&o.CertName, &o.OrderURL, &o.FinalizeURL, &o.CertURL, &expiresAt, &o.Status, &o.KeyPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get order for %s: %w", certName, err)
	}
	o.ExpiresAt = fromUnix(expiresAt)
	return o, nil
}

func (s *Store) PutOrder(o *Order) error {
	_, err := s.db.Exec(`
		INSERT INTO orders (cert_name, order_url, finalize_url, cert_url, expires_at, status, key_pem, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cert_name) DO UPDATE SET
			order_url    = excluded.order_url,
			finalize_url = excluded.finalize_url,
			cert_url     = excluded.cert_url,
			expires_at   = excluded.expires_at,
			status       = excluded.status,
			key_pem      = excluded.key_pem,
			updated_at   = excluded.updated_at`,
		o.CertName, o.OrderURL, o.FinalizeURL, o.CertURL, toUnix(o.ExpiresAt), o.Status, o.KeyPEM,
		time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put order for %s: %w", o.CertName, err)
	}
	return nil
}

func (s *Store) DeleteOrder(certName string) error {
	_, err := s.db.Exec(`DELETE FROM orders WHERE cert_name = ?`, certName)
	if err != nil {
		return fmt.Errorf("delete order for %s: %w", certName, err)
	}
	return nil
}

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

func (s *Store) DeleteAuthorizations(certName string) error {
	_, err := s.db.Exec(`DELETE FROM authorizations WHERE cert_name = ?`, certName)
	if err != nil {
		return fmt.Errorf("delete authorizations for %s: %w", certName, err)
	}
	return nil
}

type RetiredCert struct {
	CertID    string
	CertName  string
	RetiredAt time.Time
}

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

func (s *Store) ListRetiredCertsBefore(cutoff time.Time) ([]*RetiredCert, error) {
	rows, err := s.db.Query(`SELECT cert_id, cert_name, retired_at FROM retired_certificates WHERE retired_at < ?`, cutoff.Unix())
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

func (s *Store) DeleteRetiredCert(certID string) error {
	_, err := s.db.Exec(`DELETE FROM retired_certificates WHERE cert_id = ?`, certID)
	if err != nil {
		return fmt.Errorf("delete retired cert %s: %w", certID, err)
	}
	return nil
}
