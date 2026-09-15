package acme

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
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

// challengeSolver 是 Manager 需要的 DNS-01 能力。
// 抽成接口是为了让"清理残留 TXT"这条出过泄漏的路径能被测试覆盖。
type challengeSolver interface {
	Present(ctx context.Context, domain, token, keyAuth string) (DNSRecord, error)
	WaitAll(ctx context.Context, records []DNSRecord) error
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
}

// keyAuthProvider 只需要"把 challenge token 换算成 key authorization"。
// *api.Core 天然满足它。
type keyAuthProvider interface {
	GetKeyAuthorization(token string) (string, error)
}

// Manager 把期望状态（config.Certificate）收敛到实际状态（state.CertState）。
//
// 整个系统的正确性依赖四条不变量，都体现在下面的代码里：
//
//  1. 任何时刻每张证书最多一个进行中的订单，且 order URL 必须落盘。
//     reconcile 进来先看有没有未过期的 pending order，有就推进它，绝不新建 ——
//     除非配置里的 domains 变了，那样这张订单已经签不出你要的东西。
//  2. ARI 优先，且下单时必须带 replaces —— 不带就拿不到"豁免全部速率限制"的待遇。
//  3. wildcard 与 apex 会写到同一个 _acme-challenge 名字上，
//     必须"全部写入 → 全部验证 → 才统一清理"。
//  4. 期望状态是 domains，不是时间。生效证书的 SAN 与配置不一致就立刻重签，
//     不等 ARI 窗口；丢弃订单之前必须先把 DNS 里的 TXT 收干净 ——
//     授权行一删，那些记录就永远回收不了了。
type Manager struct {
	store    *state.Store
	core     *api.Core
	dns      challengeSolver
	keyAuth  keyAuthProvider
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
	return newManager(store, core, dns, core, deployer, log)
}

// newManager 允许注入 DNS solver 与 key authorization 来源，供测试使用。
func newManager(
	store *state.Store,
	core *api.Core,
	dns challengeSolver,
	keyAuth keyAuthProvider,
	deployer deploy.Deployer,
	log *slog.Logger,
) *Manager {
	return &Manager{
		store:       store,
		core:        core,
		dns:         dns,
		keyAuth:     keyAuth,
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
		switch {
		// ExpiresAt 为零值表示服务端没给过期时间：继续推进，让 CA 自己宣布 invalid。
		case !o.ExpiresAt.IsZero() && !m.now().Before(o.ExpiresAt):
			m.log.Warn("订单已过期，丢弃后重新决策",
				"cert", c.Name, "order", o.OrderURL, "expiredAt", o.ExpiresAt)
			if err := m.discardOrder(ctx, c.Name); err != nil {
				return err
			}

		case !orderMatchesConfig(o, c):
			// 配置里的域名变了。这张订单的 identifier 集合是下单那一刻定下的，
			// 继续推进它只会在 finalize 时被 CA 反复拒绝，一直卡到订单过期 ——
			// 而"绝不新建订单"这条不变量恰好会让这个卡顿格外持久。
			// 所以必须果断丢弃，让下一轮按新域名重建。
			m.log.Warn("配置里的域名已变更，丢弃旧订单后按新域名重建",
				"cert", c.Name,
				"orderIdentifiers", o.Identifiers,
				"configIdentifiers", c.DomainKey())
			if err := m.discardOrder(ctx, c.Name); err != nil {
				return err
			}

		default:
			m.log.Info("继续推进已有订单", "cert", c.Name, "order", o.OrderURL, "status", o.Status)
			return m.advance(ctx, c, st, o)
		}
	}

	// 走到这里说明当前没有进行中的订单。如果状态库里还留着"已写进 DNS"的
	// 授权记录，那它们已经没有归属了（例如上一次删订单成功、删授权失败，
	// 或者进程被 kill），就地回收，不要让它一直挂在 DNSPod 上。
	if err := m.cleanupOrphanTXT(ctx, c.Name); err != nil {
		m.log.Warn("回收残留 TXT 失败", "cert", c.Name, "err", err)
	}

	// 还没有证书 → 首次签发。
	if st.NotAfter.IsZero() {
		m.log.Info("首次签发",
			"cert", c.Name, "names", len(c.Domains), "profile", c.Profile)
		return m.issue(ctx, c, st, "")
	}

	// 已有证书 → 先看域名集合对不对，再看时间。
	//
	// 顺序不能反：只依赖 ARI 窗口的话，配置里新增的域名要等到下一个续期
	// 窗口才会生效，classic profile 下最长是一整个有效期。"随时会改域名"
	// 正是这个项目的使用场景，这种延迟是不可接受的。
	if leaf, lerr := ParseLeaf(st.CertPEM); lerr != nil {
		m.log.Warn("解析生效证书失败，跳过域名集合比对", "cert", c.Name, "err", lerr)
	} else if drifted, detail := CoverageDrift(leaf, c.Domains); drifted {
		m.log.Warn("生效证书的域名集合与配置不一致，立即重签",
			"cert", c.Name, "detail", detail,
			"note", "域名集合变更后的订单不算'同名续期'，会消耗 "+
				"Certificates per Registered Domain 配额（50 / 7 天，跨账号共享）")
		// 仍然带上 replaces：它表达的语义确实是"替换掉这一张"，
		// 而且 lego 在服务端返回 alreadyReplaced 时会自动去掉它重试一次。
		return m.issue(ctx, c, st, st.ARICertID)
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

// orderMatchesConfig 判断订单的 identifier 集合是否还和配置一致。
//
// 旧版本落盘的订单没有这个字段（空字符串），此时不做判断 ——
// 宁可多推进一轮，也不要因为拿不到信息就贸然丢弃一张订单
// （重新下单要消耗 "5 certs per exact set of identifiers / 7 days"）。
func orderMatchesConfig(o *state.Order, c *config.Certificate) bool {
	if o.Identifiers == "" {
		return true
	}
	return o.Identifiers == c.DomainKey()
}
