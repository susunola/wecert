package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// renewalDecision 返回"什么时候续期"和"下单时该带哪个 replaces"。
//
// ARI 优先：走 ARI 并带 replaces 的续期豁免 Let's Encrypt 的全部速率限制。
// ARI 不可用时退化到 notAfter - renewBefore，并叠加确定性抖动。
func (m *Manager) renewalDecision(
	ctx context.Context, c *config.Certificate, st *state.CertState,
) (renewAt time.Time, replaces string, ariErr error) {
	// lego 的 ACME API 不接受 context，所以取消没法传进网络调用本身；
	// 但至少在这里检查一次，避免收到停止信号后还在白跑一轮。
	if err := ctx.Err(); err != nil {
		return time.Time{}, "", err
	}

	now := m.now()

	if st.ARICertID != "" && m.ariCheckDue(st, now) {
		info, retryAfter, err := FetchRenewalInfo(m.core, st.ARICertID)
		switch {
		case err == nil:
			st.ARIWindowStart = info.SuggestedWindow.Start
			st.ARIWindowEnd = info.SuggestedWindow.End
			st.ARICheckedAt = now
			st.ARIRetryAfter = retryAfter
			if perr := m.store.PutCert(st); perr != nil {
				return time.Time{}, "", perr
			}
			m.log.Info("ARI window refreshed",
				"cert", c.Name, "start", st.ARIWindowStart, "end", st.ARIWindowEnd, "retryAfter", retryAfter)
		case errors.Is(err, api.ErrNoARI):
			// CA 不支持 ARI，永久退化。记一次就够了，不必每轮重试。
			st.ARICheckedAt = now
			st.ARIRetryAfter = 0
			if perr := m.store.PutCert(st); perr != nil {
				return time.Time{}, "", perr
			}
			ariErr = err
		default:
			// 失败也必须记账。
			//
			// 节流判据 ariCheckDue 完全基于 ARICheckedAt，如果这里不写，
			// 每一轮 reconcile（默认 1 小时）都会重打一次 ARI；
			// 而且服务端给的 Retry-After 会被丢掉 —— FetchRenewalInfo
			// 明明已经替我们解析好了，连非 200 响应的情况都覆盖了。
			st.ARICheckedAt = now
			st.ARIRetryAfter = retryAfter
			if perr := m.store.PutCert(st); perr != nil {
				return time.Time{}, "", perr
			}
			ariErr = err
		}
	}

	if !st.ARIWindowStart.IsZero() && st.ARIWindowEnd.After(st.ARIWindowStart) {
		return RenewalTime(c.Name, st.ARIWindowStart, st.ARIWindowEnd), st.ARICertID, ariErr
	}

	// 兜底：不用 ARI，但仍把 identifier 集合保持不变，
	// 这样至少还能享受"非 ARI 续期"对订单数与每域名证书数的豁免。
	base := st.NotAfter.Add(-c.RenewBeforeDur)
	return DeterministicTime(c.Name, base, c.RenewBeforeDur/8), st.ARICertID, ariErr
}

func (m *Manager) ariCheckDue(st *state.CertState, now time.Time) bool {
	if st.ARICheckedAt.IsZero() {
		return true
	}
	// Let's Encrypt 建议最多 6 小时查一次 renewalInfo。
	if now.Before(st.ARICheckedAt.Add(m.ariInterval)) {
		return false
	}
	// 并遵守服务端给的 Retry-After。
	if st.ARIRetryAfter > 0 && now.Before(st.ARICheckedAt.Add(st.ARIRetryAfter)) {
		return false
	}
	return true
}

// issue 创建订单。注意顺序：先把订单（含本次生成的私钥）落盘，再推进它。
func (m *Manager) issue(ctx context.Context, c *config.Certificate, st *state.CertState, replaces string) error {
	key, err := GenerateKey(c.KeyType)
	if err != nil {
		return m.recordFailure(st, err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return m.recordFailure(st, err)
	}

	order, err := m.core.Orders.NewWithOptions(c.Domains, &api.OrderOptions{
		Profile:        c.Profile,
		ReplacesCertID: replaces,
	})
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("create order: %w", err))
	}
	if order.Location == "" {
		return m.recordFailure(st, errors.New("create order: the server returned no order URL"))
	}

	expiresAt, expErr := parseOrderExpires(order.Expires, m.now())
	if expErr != nil {
		m.log.Warn("cannot parse the order's expires; using a conservative TTL",
			"cert", c.Name, "raw", order.Expires, "err", expErr, "ttl", defaultOrderTTL)
	}

	o := &state.Order{
		CertName:    c.Name,
		OrderURL:    order.Location,
		FinalizeURL: order.Finalize,
		CertURL:     order.Certificate,
		ExpiresAt:   expiresAt,
		Status:      order.Status,
		KeyPEM:      keyPEM,
		// 记下这张订单的 identifier 集合。之后配置里改了域名，
		// Reconcile 就能立刻发现并丢弃它，而不是推进到过期。
		Identifiers: c.DomainKey(),
	}
	if err := m.store.PutOrder(o); err != nil {
		return err
	}

	m.log.Info("ACME order created",
		"cert", c.Name, "status", order.Status, "expiresAt", expiresAt,
		"names", len(c.Domains), "profile", order.Profile, "replaces", replaces != "")
	return m.advance(ctx, c, st, o)
}
