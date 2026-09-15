package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"

	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/deploy"
	"github.com/atom/wecert/internal/state"
)

const (
	authzWaitTimeout = 3 * time.Minute
	orderWaitTimeout = 2 * time.Minute
	pollInterval     = 3 * time.Second
	defaultOrderTTL  = 7 * 24 * time.Hour
)

type Manager struct {
	store    *state.Store
	core     *api.Core
	dns      *DNSSolver
	deployer deploy.Deployer
	log      *slog.Logger

	ariInterval time.Duration
	retention   time.Duration
	now         func() time.Time
}

func NewManager(
	store *state.Store,
	core *api.Core,
	dns *DNSSolver,
	deployer deploy.Deployer,
	log *slog.Logger,
) *Manager {
	return &Manager{
		store:       store,
		core:        core,
		dns:         dns,
		deployer:    deployer,
		log:         log,
		ariInterval: 6 * time.Hour,
		retention:   7 * 24 * time.Hour,
		now:         time.Now,
	}
}

func (m *Manager) Reconcile(ctx context.Context, c *config.Certificate) error {
	st, err := m.store.GetCert(c.Name)
	if err != nil {
		return err
	}
	if st == nil {
		st = &state.CertState{Name: c.Name}
	}

	if !st.NextAttemptAt.IsZero() && m.now().Before(st.NextAttemptAt) {
		m.log.Debug("处于逆避窗口内，跳过", "cert", c.Name, "nextAttemptAt", st.NextAttemptAt)
		return nil
	}

	if o, err := m.store.GetOrder(c.Name); err != nil {
		return err
	} else if o != nil {
		if o.ExpiresAt.IsZero() || m.now().Before(o.ExpiresAt) {
			m.log.Info("继续推进已有订单", "cert", c.Name, "order", o.OrderURL, "status", o.Status)
			return m.advance(ctx, c, st, o)
		}
		m.log.Warn("订单已过期，丢弃后重新决策",
			"cert", c.Name, "order", o.OrderURL, "expiredAt", o.ExpiresAt)
		if err := m.discardOrder(c.Name); err != nil {
			return err
		}
	}

	if st.NotAfter.IsZero() {
		m.log.Info("首次签发", "cert", c.Name, "domains", c.Domains, "profile", c.Profile)
		return m.issue(ctx, c, st, "")
	}

	renewAt, replaces, ariErr := m.renewalDecision(ctx, c, st)
	if ariErr != nil {
		m.log.Warn("ARI 查询失败，改用时间兜底", "cert", c.Name, "err", ariErr)
	}
	if m.now().Before(renewAt) {
		m.log.Debug("尚未到续期时间", "cert", c.Name, "renewAt", renewAt, "notAfter", st.NotAfter)
		return nil
	}

	m.log.Info("开始续期",
		"cert", c.Name, "notAfter", st.NotAfter, "renewAt", renewAt, "ariReplaces", replaces != "")
	return m.issue(ctx, c, st, replaces)
}
