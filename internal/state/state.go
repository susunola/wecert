// Package state 是 wecert 的持久化层。
//
// 这一层的存在本身就是需求：Let's Encrypt 官方点名了最常见的撞限方式 ——
// "每次部署都删掉 ACME 客户端的配置数据"。丢失 order URL 会让进程重启后
// 重新下单，直接撞上 "5 certificates per exact set of identifiers / 7 days"。
//
// 所以：account key、order URL、ARI 窗口、腾讯云 CertId 全部落盘。
package state

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // 纯 Go driver，免 CGO，方便静态编译
)

// Store 是 SQLite 之上的状态存储。
type Store struct {
	db *sql.DB
}

// CertState 是一张证书的运行时状态（对应 config.Certificate 的 status）。
type CertState struct {
	Name string

	// 当前生效的证书。
	NotAfter  time.Time
	CertURL   string
	CertPEM   []byte
	KeyPEM    []byte
	IssuedAt  time.Time

	// ARI（RFC 9773）。CertID = base64url(AKI) + "." + base64url(Serial)。
	ARICertID      string
	ARIWindowStart time.Time
	ARIWindowEnd   time.Time
	ARICheckedAt   time.Time
	ARIRetryAfter  time.Duration

	// 失败退避。撞了 "5 authorization failures per identifier per hour" 之后
	// 继续猛重试只会让情况更糟，所以这里必须有上限并转为人工介入。
	ConsecutiveFailures int
	NextAttemptAt       time.Time
	LastError           string

	// 腾讯云侧当前生效的证书 ID，作为 UpdateCertificateInstance 的 OldCertificateId。
	// 空字符串表示还没有绑定过，需要人工绑一次。
	DeployedCertID string

	UpdatedAt time.Time
}

// Order 是一个进行中的 ACME 订单。
//
// KeyPEM 是这张订单签发时生成的私钥。它必须挂在订单上而不是直接覆盖
// CertState.KeyPEM —— 否则一旦部署失败，当前正在服务的证书私钥就被覆盖没了。
// 只有新证书成功上线后，才会把 KeyPEM 提升为生效私钥。
type Order struct {
	CertName    string
	OrderURL    string
	FinalizeURL string
	CertURL     string
	ExpiresAt   time.Time
	Status      string
	KeyPEM      []byte
}

// Authorization 是订单里的一个 identifier 授权。
//
// 注意：wildcard 和 apex 的授权会落在同一个 TXT 名字上
// （`example.com` 和 `*.example.com` 都写 `_acme-challenge.example.com`），
// 所以这里按 authz URL 分行存，每行各自持有自己的 TXT 值，
// 由 manager 保证"全部写入 → 全部验证 → 才统一清理"。
type Authorization struct {
	CertName       string
	AuthzURL       string
	Identifier     string
	Status         string
	ChallengeURL   string
	ChallengeToken string
	TxtName        string
	TxtValue       string

	// Presented 表示 TXT 已经写进 DNS（但不保证传播完成）。
	Presented bool
	// ChallengeSent 表示已经 POST 通知 CA 去验证。
	ChallengeSent bool
}

// Account 是 ACME 账号。
type Account struct {
	Directory     string
	KID           string
	PrivateKeyPEM []byte
}

// Open 打开（必要时创建）状态库。
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	// modernc sqlite 是单写入者模型，限制连接数避免 SQLITE_BUSY。
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close 关闭状态库。
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

-- 已退役但尚未删除的云端证书。保留一段时间用于回滚，
-- 之后必须回收：腾讯云账号下上传证书数量有配额。
CREATE TABLE IF NOT EXISTS retired_certificates (
    cert_id    TEXT PRIMARY KEY,
    cert_name  TEXT NOT NULL,
    retired_at INTEGER NOT NULL
);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// ---------- 时间辅助：SQLite 里统一存 unix 秒，0 表示零值 ----------

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

// GetAccount 读取账号；不存在时返回 (nil, nil)。
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

// PutAccount 写入账号。
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

// GetCert 读取证书状态；不存在时返回 (nil, nil)。
func (s *Store) GetCert(name string) (*CertState, error) {
	row := s.db.QueryRow(`
		SELECT name, not_after, cert_url, cert_pem, key_pem, issued_at,
		       ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
		       consecutive_failures, next_attempt_at, last_error, deployed_cert_id, updated_at
		FROM certificates WHERE name = ?`, name)

	c := &CertState{}
	var notAfter, issuedAt, ariStart, ariEnd, ariChecked, nextAttempt, updatedAt int64
	var retryAfterNS int64

	err := row.Scan(
		&c.Name, &notAfter, &c.CertURL, &c.CertPEM, &c.KeyPEM, &issuedAt,
		&c.ARICertID, &ariStart, &ariEnd, &ariChecked, &retryAfterNS,
		&c.ConsecutiveFailures, &nextAttempt, &c.LastError, &c.DeployedCertID, &updatedAt)
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
	c.UpdatedAt = fromUnix(updatedAt)
	return c, nil
}

// PutCert 写入证书状态。
func (s *Store) PutCert(c *CertState) error {
	_, err := s.db.Exec(`
		INSERT INTO certificates (
			name, not_after, cert_url, cert_pem, key_pem, issued_at,
			ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
			consecutive_failures, next_attempt_at, last_error, deployed_cert_id, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			updated_at           = excluded.updated_at`,
		c.Name, toUnix(c.NotAfter), c.CertURL, c.CertPEM, c.KeyPEM, toUnix(c.IssuedAt),
		c.ARICertID, toUnix(c.ARIWindowStart), toUnix(c.ARIWindowEnd), toUnix(c.ARICheckedAt),
		int64(c.ARIRetryAfter),
		c.ConsecutiveFailures, toUnix(c.NextAttemptAt), c.LastError, c.DeployedCertID,
		time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put cert %s: %w", c.Name, err)
	}
	return nil
}

// ---------- Order ----------

// GetOrder 读取进行中的订单；不存在时返回 (nil, nil)。
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

// PutOrder 写入进行中的订单。
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

// DeleteOrder 丢弃当前订单（订单已失效或被放弃）。
func (s *Store) DeleteOrder(certName string) error {
	_, err := s.db.Exec(`DELETE FROM orders WHERE cert_name = ?`, certName)
	if err != nil {
		return fmt.Errorf("delete order for %s: %w", certName, err)
	}
	return nil
}

// ---------- Authorization ----------

// ListAuthorizations 列出某证书订单下的全部授权。
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

// PutAuthorization 写入单个授权。
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

// DeleteAuthorizations 清空某证书的授权记录（订单结束时调用）。
func (s *Store) DeleteAuthorizations(certName string) error {
	_, err := s.db.Exec(`DELETE FROM authorizations WHERE cert_name = ?`, certName)
	if err != nil {
		return fmt.Errorf("delete authorizations for %s: %w", certName, err)
	}
	return nil
}

// ---------- RetiredCert ----------

// RetiredCert 是一张已从线上换下、暂时保留用于回滚的云端证书。
type RetiredCert struct {
	CertID    string
	CertName  string
	RetiredAt time.Time
}

// AddRetiredCert 记录一张退役证书。
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

// ListRetiredCertsBefore 列出退役时间早于 cutoff 的证书，用于回收。
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

// DeleteRetiredCert 从回收列表里移除（云端删除成功后调用）。
func (s *Store) DeleteRetiredCert(certID string) error {
	_, err := s.db.Exec(`DELETE FROM retired_certificates WHERE cert_id = ?`, certID)
	if err != nil {
		return fmt.Errorf("delete retired cert %s: %w", certID, err)
	}
	return nil
}
