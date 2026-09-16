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
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // 纯 Go driver，免 CGO，方便静态编译
)

// Store 是 SQLite 之上的状态存储。
type Store struct {
	db *sql.DB

	// lock 是跨进程排他锁。
	//
	// "每张证书最多一个在飞订单"这条不变量原本只在**一个进程内**成立。
	// daemon 和 timer 两种模式同时启用时，两个进程各自持有一份局部视图，
	// 于是同一张证书会被下单两次 —— 撞上的是
	// "5 certificates per exact set of identifiers / 7 days"，
	// 而那条限额没有 override，撞了要等满 7 天。
	lock *fileLock
}

// ErrLocked 表示状态库已经被另一个 wecert 进程独占。
//
// 这不是异常，是必须存在的一道闸门。见 Store.lock 的注释。
var ErrLocked = errors.New("the state database is already held by another wecert process")

// CertState 是一张证书的运行时状态（对应 config.Certificate 的 status）。
type CertState struct {
	Name string

	// 当前生效的证书。
	NotAfter time.Time
	CertURL  string
	CertPEM  []byte
	KeyPEM   []byte
	IssuedAt time.Time

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

	// DeployConfirmed 表示"证书确实已经在云资源上生效"，而不只是上传成功。
	// 首次上传拿到 CertId 之后还要人工在 CLB 绑一次，那之前不能算已部署 ——
	// 否则到期告警会因为 deployed=1 而误以为一切正常。
	DeployConfirmed bool

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

	// Identifiers 是创建这张订单时提交的 identifier 集合（规范形式，
	// 见 config.DomainKey）。空字符串表示订单来自旧版本、没有这份记录。
	//
	// 为什么必须存：订单的 identifier 集合是 newOrder 那一刻定下的，
	// 之后配置里改了 domains，CSR 就和订单对不上，CA 会一直拒绝 finalize。
	// 而"绝不新建订单"这条不变量又会让程序不停地推进同一张坏订单，
	// 于是卡到订单 7 天后过期为止 —— 期间该证书的任何域名改动都无法生效。
	Identifiers string
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

// Open 打开（必要时创建）状态库，并取得跨进程排他锁。
//
// 这个文件里存着 ACME 账号私钥和全部生效证书的私钥，所以目录不存在时先建、
// 文件用 0600 预创建。SQLite 自己是按进程 umask 建文件的 —— 在 umask 022 的
// 机器上就是 0644，任何本机用户都能把私钥读走。systemd 那条路有
// StateDirectoryMode=0700 兜着，但手工执行（README 的 -dry-run、e2e 脚本
// 把库放在 /tmp）时没有这层保护。
func Open(path string) (*Store, error) { return open(path, true) }

// OpenUnlocked 打开状态库但**不**取排他锁。
//
// 只给一次性的校验路径用（-dry-run）：它几乎总是在 daemon 正在跑的时候
// 被执行，而"因为 daemon 在跑所以连配置都校验不了"会把人逼去瞎改配置。
// 这条路径只读已有的 ACME 账号、不发起任何签发，所以不取锁是安全的。
func OpenUnlocked(path string) (*Store, error) { return open(path, false) }

func open(path string, exclusive bool) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create state dir %s: %w", dir, err)
		}
	}

	// 锁要在建库文件之前拿：两个进程同时初始化一个空库比同时写一个
	// 已有库更难排查，因为它们会各自建出不同的表结构。
	var lock *fileLock
	if exclusive {
		var err error
		if lock, err = acquireLock(path + ".lock"); err != nil {
			return nil, err
		}
	}

	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		_ = f.Close()
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = lock.release()
		return nil, fmt.Errorf("open state db: %w", err)
	}
	// modernc sqlite 是单写入者模型，限制连接数避免 SQLITE_BUSY。
	db.SetMaxOpenConns(1)

	s := &Store{db: db, lock: lock}
	if err := s.migrate(); err != nil {
		db.Close()
		_ = lock.release()
		return nil, err
	}

	// migrate 之后 -wal / -shm 才真正出现，统一收一次权限。
	// WAL 文件是私钥的副本，权限必须一起管。
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0o600); err != nil && !os.IsNotExist(err) {
			db.Close()
			_ = lock.release()
			return nil, fmt.Errorf("chmod state file %s: %w", path+suffix, err)
		}
	}
	return s, nil
}

// Close 关闭状态库并释放跨进程锁。
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
    -- 上传成功 ≠ 已经绑到监听器上。要等一键更新真正换完才置位，
    -- 否则首次上传就会被当成"deployed"，人手还没绑之前指标就开始报绿。
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
    -- 下单时提交的 identifier 集合（规范形式，见 config.DomainKey）。
    identifiers  TEXT NOT NULL DEFAULT '',
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

	// CREATE TABLE IF NOT EXISTS 不会给**已存在**的表补字段，所以给老库单独补。
	// 状态库里那句"丢了它就等于撞限速"的警告同样适用于这里：
	// 升级时宁可多迁一步，也绝不能要求用户删库重建。
	for _, m := range []struct{ table, column, decl string }{
		{"certificates", "deploy_confirmed", "INTEGER NOT NULL DEFAULT 0"},
		{"orders", "identifiers", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.ensureColumn(m.table, m.column, m.decl); err != nil {
			return err
		}
	}
	return nil
}

// ensureColumn 在表上补一个字段（不存在时）。
//
// columnExists 自己把 rows 关掉再返回，是有意的：连接池被限制成
// MaxOpenConns(1)，靠 rows 迭代到 EOF 触发的隐式关闭来释放连接太隐晦 ——
// 一旦有人把下面这个循环改成提前 return，ALTER 就会永久阻塞在等连接上。
func (s *Store) ensureColumn(table, column, decl string) error {
	exists, err := s.columnExists(table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	// 这里是拼字符串而不是占位符：SQLite 的 DDL 不接受参数化列名/类型。
	// 三个入参都是代码里的字面量，不含用户输入。
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

// ListCertNames 返回状态库里所有证书名，已排序。
//
// 用途是"孤儿检查"：状态库里有、但期望状态里已经没有的证书不会再被续期，
// 最终会安静地过期。让这个集合能被看见，是那条失败路径唯一的兜底。
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

// GetCert 读取证书状态；不存在时返回 (nil, nil)。
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

// PutCert 写入证书状态。
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
		c.ConsecutiveFailures, toUnix(c.NextAttemptAt), c.LastError, c.DeployedCertID,
		c.DeployConfirmed, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put cert %s: %w", c.Name, err)
	}
	return nil
}

// ---------- Order ----------

// GetOrder 读取进行中的订单；不存在时返回 (nil, nil)。
func (s *Store) GetOrder(certName string) (*Order, error) {
	row := s.db.QueryRow(`
		SELECT cert_name, order_url, finalize_url, cert_url, expires_at, status, key_pem, identifiers
		FROM orders WHERE cert_name = ?`, certName)

	o := &Order{}
	var expiresAt int64
	err := row.Scan(&o.CertName, &o.OrderURL, &o.FinalizeURL, &o.CertURL, &expiresAt,
		&o.Status, &o.KeyPEM, &o.Identifiers)
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
		INSERT INTO orders (
			cert_name, order_url, finalize_url, cert_url, expires_at, status, key_pem, identifiers, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cert_name) DO UPDATE SET
			order_url    = excluded.order_url,
			finalize_url = excluded.finalize_url,
			cert_url     = excluded.cert_url,
			expires_at   = excluded.expires_at,
			status       = excluded.status,
			key_pem      = excluded.key_pem,
			identifiers  = excluded.identifiers,
			updated_at   = excluded.updated_at`,
		o.CertName, o.OrderURL, o.FinalizeURL, o.CertURL, toUnix(o.ExpiresAt), o.Status,
		o.KeyPEM, o.Identifiers, time.Now().Unix())
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

// DeleteAuthorizations 清空某证书的全部授权记录。
//
// 注意：manager 现在不走它了 —— 丢弃订单时应该调 cleanupOrphanTXT，
// 它会先把 DNS 上还挂着的 TXT 收掉再删行。这个方法是留给"确实要整表清空"
// 的场景（例如测试或人工干预）的兜底。
func (s *Store) DeleteAuthorizations(certName string) error {
	_, err := s.db.Exec(`DELETE FROM authorizations WHERE cert_name = ?`, certName)
	if err != nil {
		return fmt.Errorf("delete authorizations for %s: %w", certName, err)
	}
	return nil
}

// DeleteAuthorization 删除单条授权记录。
// 用于清理已经回收掉 TXT、不再需要跟踪的残留授权行。
func (s *Store) DeleteAuthorization(certName, authzURL string) error {
	_, err := s.db.Exec(
		`DELETE FROM authorizations WHERE cert_name = ? AND authz_url = ?`, certName, authzURL)
	if err != nil {
		return fmt.Errorf("delete authorization %s: %w", authzURL, err)
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
