package state

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// IdentifierFailure 是某个 identifier 的授权失败账本。
type IdentifierFailure struct {
	CertName     string
	Identifier   string
	Failures     int
	LastError    string
	LastFailedAt time.Time
}

// Fallback 是"这张证书正服务着一张缺了几个名字的证书"这件事的记录。
//
// 它必须能被看见：降级是在"部分可用"和"全挂"之间做的取舍，
// 而取舍的结果不能只留在日志里 —— 日志会被轮转掉。
type Fallback struct {
	CertName string
	Dropped  []string
	Since    time.Time
	Reason   string
}

// RecordIdentifierFailure 给某个 identifier 的失败计数加一。
//
// 这个账本是"到期前降级"唯一的输入：没有它，降级只能随机摘名字，
// 而随机摘会把本来好的名字也一起牺牲掉。
func (s *Store) RecordIdentifierFailure(certName, identifier, errMsg string, now time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO identifier_failures (cert_name, identifier, failures, last_error, last_failed_at)
		VALUES (?, ?, 1, ?, ?)
		ON CONFLICT(cert_name, identifier) DO UPDATE SET
			failures       = failures + 1,
			last_error     = excluded.last_error,
			last_failed_at = excluded.last_failed_at`,
		certName, identifier, truncate(errMsg, 512), now.Unix())
	if err != nil {
		return fmt.Errorf("record identifier failure %s/%s: %w", certName, identifier, err)
	}
	return nil
}

// ListIdentifierFailures 返回一张证书下所有 identifier 的失败记录，
// 按 identifier 排序，保证同样的输入给出同样的输出。
func (s *Store) ListIdentifierFailures(certName string) ([]*IdentifierFailure, error) {
	rows, err := s.db.Query(`
		SELECT cert_name, identifier, failures, last_error, last_failed_at
		FROM identifier_failures WHERE cert_name = ? ORDER BY identifier`, certName)
	if err != nil {
		return nil, fmt.Errorf("list identifier failures for %s: %w", certName, err)
	}
	defer rows.Close()

	var out []*IdentifierFailure
	for rows.Next() {
		f := &IdentifierFailure{}
		var lastFailedAt int64
		if err := rows.Scan(&f.CertName, &f.Identifier, &f.Failures, &f.LastError, &lastFailedAt); err != nil {
			return nil, fmt.Errorf("scan identifier failure: %w", err)
		}
		f.LastFailedAt = fromUnix(lastFailedAt)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ClearIdentifierFailures 清掉一张证书下所有 identifier 的失败记录。
//
// 全集签发成功时调用：失败账本的意义是"最近谁在坏"，
// 而不是"历史上谁坏过"。留着它会让一次早已修好的故障永远把名字摘在外面。
func (s *Store) ClearIdentifierFailures(certName string) error {
	if _, err := s.db.Exec(`DELETE FROM identifier_failures WHERE cert_name = ?`, certName); err != nil {
		return fmt.Errorf("clear identifier failures for %s: %w", certName, err)
	}
	return nil
}

// PruneIdentifierFailures 丢掉超过 age 没再失败过的记录。
//
// 让老账本自动过期，而不必等一次成功的全集签发 —— 那些 identifier
// 已经不在证书里了，它们的授权永远不会再被尝试，也就永远不会有
// 一次"成功"来清掉它们。
func (s *Store) PruneIdentifierFailures(certName string, now time.Time, age time.Duration) error {
	cutoff := now.Add(-age)
	if _, err := s.db.Exec(`
		DELETE FROM identifier_failures WHERE cert_name = ? AND last_failed_at < ?`,
		certName, cutoff.Unix()); err != nil {
		return fmt.Errorf("prune identifier failures for %s: %w", certName, err)
	}
	return nil
}

// PutFallback 记录降级状态。
func (s *Store) PutFallback(f *Fallback) error {
	dropped := append([]string(nil), f.Dropped...)
	sort.Strings(dropped)

	_, err := s.db.Exec(`
		INSERT INTO cert_fallback (cert_name, dropped, since, reason)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(cert_name) DO UPDATE SET
			dropped = excluded.dropped,
			since   = excluded.since,
			reason  = excluded.reason`,
		f.CertName, strings.Join(dropped, ","), f.Since.Unix(), truncate(f.Reason, 512))
	if err != nil {
		return fmt.Errorf("put fallback for %s: %w", f.CertName, err)
	}
	return nil
}

// GetFallback 读降级状态；没有记录时返回 (nil, nil)。
func (s *Store) GetFallback(certName string) (*Fallback, error) {
	row := s.db.QueryRow(`
		SELECT cert_name, dropped, since, reason FROM cert_fallback WHERE cert_name = ?`, certName)

	f := &Fallback{}
	var dropped string
	var since int64
	err := row.Scan(&f.CertName, &dropped, &since, &f.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get fallback for %s: %w", certName, err)
	}

	for _, d := range strings.Split(dropped, ",") {
		if d = strings.TrimSpace(d); d != "" {
			f.Dropped = append(f.Dropped, d)
		}
	}
	f.Since = fromUnix(since)
	return f, nil
}

// ClearFallback 清掉降级状态。全集签发成功时调用。
func (s *Store) ClearFallback(certName string) error {
	if _, err := s.db.Exec(`DELETE FROM cert_fallback WHERE cert_name = ?`, certName); err != nil {
		return fmt.Errorf("clear fallback for %s: %w", certName, err)
	}
	return nil
}

// truncate 把可能很长的错误文本截断。
//
// 这里存的是给人看的诊断信息，不是完整日志 —— 而一个反复失败的
// ACME 错误可能带上整个响应体，不截断会让状态库无谓地膨胀。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
