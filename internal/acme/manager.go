package acme

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v4/acme/api"

	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/deploy"
	"github.com/atom/wecert/internal/state"
)

// 授权轮询与订单等待的上限。超过就退避，下一轮接着推进同一个订单 ——
// 因为订单已经落盘，"下一轮"是廉价的，重新下单才是昂贵的。
const (
	authzWaitTimeout = 3 * time.Minute
	orderWaitTimeout = 2 * time.Minute
	pollInterval     = 3 * time.Second
	// ACME 的 expires 是可选字段。解析失败或未返回时用这个保守上限，
	// 绝不能落成零值 —— 零值会被当成"已经过期"而丢掉未完成的订单。
	defaultOrderTTL = 7 * 24 * time.Hour
)

// Manager 把期望状态（config.Certificate）收敛到实际状态（state.CertState）。
//
// 整个系统的正确性依赖三条不变量，都体现在下面的代码里：
//
//  1. 任何时刻每张证书最多一个进行中的订单，且 order URL 必须落盘。
//     reconcile 进来先看有没有未过期的 pending order，有就推进它，绝不新建。
//  2. ARI 优先，且下单时必须带 replaces —— 不带就拿不到"豁免全部速率限制"的待遇。
//  3. wildcard 与 apex 会写到同一个 _acme-challenge 名字上，
//     必须"全部写入 → 全部验证 → 才统一清理"。
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

// NewManager 构造收敛器。
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

// Reconcile 处理单张证书。返回 error 只表示"这一轮没成功"，
// 失败信息已经落盘并安排了下一次尝试时间。
func (m *Manager) Reconcile(ctx context.Context, c *config.Certificate) error {
	st, err := m.store.GetCert(c.Name)
	if err != nil {
		return err
	}
	if st == nil {
		st = &state.CertState{Name: c.Name}
	}

	// 退避窗口内直接跳过。已经安排了重试时间就别再敲 CA 的门了。
	if !st.NextAttemptAt.IsZero() && m.now().Before(st.NextAttemptAt) {
		m.log.Debug("处于退避窗口内，跳过", "cert", c.Name, "nextAttemptAt", st.NextAttemptAt)
		return nil
	}

	// 不变量 1：有未过期的进行中订单就继续推进，绝不新建。
	if o, err := m.store.GetOrder(c.Name); err != nil {
		return err
	} else if o != nil {
		// ExpiresAt 为零值表示服务端没给过期时间：继续推进，让 CA 自己宣布 invalid。
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

	// 还没有证书 → 首次签发。
	if st.NotAfter.IsZero() {
		m.log.Info("首次签发", "cert", c.Name, "domains", c.Domains, "profile", c.Profile)
		return m.issue(ctx, c, st, "")
	}

	// 已有证书 → 决定是否该续期。
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
