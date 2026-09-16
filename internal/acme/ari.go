package acme

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
)

// RenewalInfo 是 RFC 9773 的 renewalInfo 响应。
type RenewalInfo struct {
	SuggestedWindow struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"suggestedWindow"`
	ExplanationURL string `json:"explanationURL"`
}

// CertID 按 RFC 9773 构造 ARI 的 certID：
//
//	base64url(AKI keyIdentifier) + "." + base64url(DER 序列号)
//
// 注意 AKI 用的是扩展里的 keyIdentifier 原始字节，不是整个扩展。
func CertID(leaf *x509.Certificate) (string, error) {
	if len(leaf.AuthorityKeyId) == 0 {
		return "", fmt.Errorf("certificate has no Authority Key Identifier; cannot build an ARI certID")
	}
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)
	serial := base64.RawURLEncoding.EncodeToString(leaf.SerialNumber.Bytes())
	return aki + "." + serial, nil
}

// FetchRenewalInfo 查询 ARI，同时返回服务器要求的 Retry-After。
//
// ARI 是这套系统最重要的一环：走 ARI 并带上 replaces 的续期
// 豁免 Let's Encrypt 的全部速率限制。不走 ARI 就只能吃
// "5 certificates per exact set of identifiers / 7 days"。
func FetchRenewalInfo(core *api.Core, certID string) (*RenewalInfo, time.Duration, error) {
	resp, err := core.Certificates.GetRenewalInfo(certID)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	// Retry-After 两种格式（秒数或 HTTP-date）lego 都帮我们处理了。
	var retryAfter time.Duration
	if v := resp.Header.Get("Retry-After"); v != "" {
		if d, err := api.ParseRetryAfter(v); err == nil {
			retryAfter = d
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, retryAfter, fmt.Errorf("renewalInfo returned %d", resp.StatusCode)
	}

	var info RenewalInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return nil, retryAfter, fmt.Errorf("parse renewalInfo: %w", err)
	}
	if info.SuggestedWindow.End.Before(info.SuggestedWindow.Start) {
		return nil, retryAfter, fmt.Errorf("renewalInfo suggestedWindow is invalid: %s - %s",
			info.SuggestedWindow.Start, info.SuggestedWindow.End)
	}
	return &info, retryAfter, nil
}

// RenewalTime 在 ARI 建议窗口内确定性地挑一个续期时刻。
//
// 为什么必须确定性：如果每次 reconcile 都重新随机，进程重启就会把续期时间
// 不停往后推，最终推过有效期。用证书名 + 窗口起点做种子，
// 同一个窗口内永远算出同一个时刻。
func RenewalTime(name string, start, end time.Time) time.Time {
	if !end.After(start) {
		return start
	}
	span := end.Sub(start)

	h := sha256.Sum256([]byte(name + "|" + start.UTC().Format(time.RFC3339)))

	at := start.Add(time.Duration(binary.BigEndian.Uint64(h[:8]) % uint64(span)))

	// 再叠一个确定性的 ±10% 抖动，避免多张证书挤在同一秒醒来。
	if jitterSpan := span / 10; jitterSpan > 0 {
		j := time.Duration(binary.BigEndian.Uint64(h[8:16]) % uint64(jitterSpan*2))
		at = at.Add(j - jitterSpan)
	}

	// 抖动可能把它推出窗口，夹回来。
	if at.Before(start) {
		return start
	}
	if at.After(end) {
		return end
	}
	return at
}

// DeterministicTime 在 ARI 不可用时使用的兜底续期时刻。
//
// 语义是"从 base 开始，在 spread 范围内按证书名确定性地散开"，
// 这样几百张证书不会在同一分钟一起去敲 CA 的门。
func DeterministicTime(name string, base time.Time, spread time.Duration) time.Time {
	if spread <= 0 {
		return base
	}
	h := sha256.Sum256([]byte("fallback|" + name))
	offset := time.Duration(binary.BigEndian.Uint64(h[:8]) % uint64(spread))
	return base.Add(offset)
}
