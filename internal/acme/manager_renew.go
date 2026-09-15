package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/acme/api"

	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/state"
)

func (m *Manager) renewalDecision(
	ctx context.Context, c *config.Certificate, st *state.CertState,
) (renewAt time.Time, replaces string, ariErr error) {
	_ = ctx
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
			m.log.Info("已刷新 ARI 窗口",
				"cert", c.Name, "start", st.ARIWindowStart, "end", st.ARIWindowEnd, "retryAfter", retryAfter)
		case errors.Is(err, api.ErrNoARI):
			st.ARICheckedAt = now
			st.ARIRetryAfter = 0
			if perr := m.store.PutCert(st); perr != nil {
				return time.Time{}, "", perr
			}
			ariErr = err
		default:
			ariErr = err
		}
	}

	if !st.ARIWindowStart.IsZero() && st.ARIWindowEnd.After(st.ARIWindowStart) {
		return RenewalTime(c.Name, st.ARIWindowStart, st.ARIWindowEnd), st.ARICertID, ariErr
	}

	base := st.NotAfter.Add(-c.RenewBeforeDur)
	return DeterministicTime(c.Name, base, c.RenewBeforeDur/8), st.ARICertID, ariErr
}

func (m *Manager) ariCheckDue(st *state.CertState, now time.Time) bool {
	if st.ARICheckedAt.IsZero() {
		return true
	}
	if now.Before(st.ARICheckedAt.Add(m.ariInterval)) {
		return false
	}
	if st.ARIRetryAfter > 0 && now.Before(st.ARICheckedAt.Add(st.ARIRetryAfter)) {
		return false
	}
	return true
}

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
		return m.recordFailure(st, fmt.Errorf("创建订单: %w", err))
	}
	if order.Location == "" {
		return m.recordFailure(st, errors.New("创建订单: 服务器未返回 order URL"))
	}

	expiresAt, expErr := parseOrderExpires(order.Expires, m.now())
	if expErr != nil {
		m.log.Warn("订单 expires 无法解析，使用保守 TTL",
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
	}
	if err := m.store.PutOrder(o); err != nil {
		return err
	}

	m.log.Info("已创建 ACME 订单",
		"cert", c.Name, "status", order.Status, "expiresAt", expiresAt,
		"profile", order.Profile, "replaces", replaces != "")
	return m.advance(ctx, c, st, o)
}
