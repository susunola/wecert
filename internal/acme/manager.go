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

// 授权轮询与订单等待的上限。超过就退避，下一轮接着推进同一个订单 ——
// 因为订单已经落盘，"下一轮"是廉价的，重新下单才是昂贵的。
const (
	authzWaitTimeout = 3 * time.Minute
	orderWaitTimeout = 2 * time.Minute
	pollInterval     = 3 * time.Second
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
		if m.now().Before(o.ExpiresAt) {
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

// renewalDecision 返回"什么时候续期"和"下单时该带哪个 replaces"。
//
// ARI 优先：走 ARI 并带 replaces 的续期豁免 Let's Encrypt 的全部速率限制。
// ARI 不可用时退化到 notAfter - renewBefore，并叠加确定性抖动。
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
			// CA 不支持 ARI，永久退化。记一次就够了，不必每轮重试。
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
		return m.recordFailure(st, fmt.Errorf("创建订单: %w", err))
	}
	if order.Location == "" {
		return m.recordFailure(st, errors.New("创建订单: 服务器未返回 order URL"))
	}

	var expiresAt time.Time
	if order.Expires != "" {
		if t, perr := time.Parse(time.RFC3339, order.Expires); perr == nil {
			expiresAt = t
		}
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

// advance 推进订单状态机。
func (m *Manager) advance(ctx context.Context, c *config.Certificate, st *state.CertState, o *state.Order) error {
	order, err := m.core.Orders.Get(o.OrderURL)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("查询订单: %w", err))
	}
	m.persistOrder(o, order)

	switch order.Status {
	case "valid":
		return m.download(ctx, c, st, o, order)

	case "invalid":
		// 订单废了。清理掉，让下一轮从头决策（此时会走退避）。
		err := fmt.Errorf("订单已失效: %v", order.Err())
		if derr := m.discardOrder(c.Name); derr != nil {
			return errors.Join(err, derr)
		}
		return m.recordFailure(st, err)

	case "ready":
		return m.finalize(ctx, c, st, o, order)
	}

	// pending / processing：把 DNS-01 挑战推完。
	allValid, err := m.solveChallenges(ctx, c, st, order)
	if err != nil {
		return err
	}
	if !allValid {
		// 还在等 CA 验证，订单保留，下一轮继续。
		return nil
	}

	// 全部授权已 valid，等订单转 ready 再 finalize。
	ready, err := m.awaitOrderStatus(ctx, o.OrderURL, "ready", orderWaitTimeout)
	if err != nil {
		return m.recordFailure(st, err)
	}
	m.persistOrder(o, ready)
	if ready.Status == "valid" {
		return m.download(ctx, c, st, o, ready)
	}
	return m.finalize(ctx, c, st, o, ready)
}

// solveChallenges 返回 allValid=true 表示订单的所有授权都已通过验证。
func (m *Manager) solveChallenges(
	ctx context.Context, c *config.Certificate, st *state.CertState, order legoacme.ExtendedOrder,
) (bool, error) {
	authzs, err := m.loadAuthorizations(c.Name, order.Authorizations)
	if err != nil {
		return false, m.recordFailure(st, err)
	}

	// 阶段 1：把所有待验证的 TXT 一次性写完。
	// 这里绝对不能"写一条 → 验一条 → 删一条"：签 example.com + *.example.com 时，
	// 两个授权的 challenge 值都落在 _acme-challenge.example.com 上，必须同时存在。
	var pending []*state.Authorization
	var records []DNSRecord

	for _, a := range authzs {
		cur, err := m.core.Authorizations.Get(a.AuthzURL)
		if err != nil {
			return false, m.recordFailure(st, fmt.Errorf("查询授权 %s: %w", a.AuthzURL, err))
		}
		a.Status = cur.Status
		a.Identifier = cur.Identifier.Value

		switch cur.Status {
		case "valid":
			if err := m.store.PutAuthorization(a); err != nil {
				return false, err
			}
			continue
		case "invalid":
			_ = m.store.PutAuthorization(a)
			return false, m.recordFailure(st, fmt.Errorf(
				"identifier %s 的授权已失效: %s", a.Identifier, authzError(cur)))
		}

		if !a.Presented {
			chlg, err := pickDNS01(cur)
			if err != nil {
				return false, m.recordFailure(st, err)
			}
			keyAuth, err := m.core.GetKeyAuthorization(chlg.Token)
			if err != nil {
				return false, m.recordFailure(st, fmt.Errorf("计算 key authorization: %w", err))
			}

			// 只写入，不等待传播 —— 等所有 TXT 都写完之后统一等一次。
			// 逐条等待会让 wildcard 和 apex 在同一个 TXT 名字上白等两遍
			// （DNSPod 免费套餐一轮传播要 2 分钟以上，这一下就是几分钟）。
			rec, err := m.dns.Present(ctx, a.Identifier, chlg.Token, keyAuth)
			if err != nil {
				return false, m.recordFailure(st, fmt.Errorf("写入 TXT (%s): %w", a.Identifier, err))
			}

			a.ChallengeURL = chlg.URL
			a.ChallengeToken = chlg.Token
			a.TxtName = rec.FQDN
			a.TxtValue = rec.Value
			a.Presented = true
			m.log.Info("TXT 已写入",
				"cert", c.Name, "identifier", a.Identifier, "name", a.TxtName)
		}

		if err := m.store.PutAuthorization(a); err != nil {
			return false, err
		}
		records = append(records, DNSRecord{FQDN: a.TxtName, Value: a.TxtValue})
		pending = append(pending, a)
	}

	if len(pending) == 0 {
		return true, nil
	}

	// 阶段 2：所有 TXT 都写完之后，统一等一次权威 NS 传播。
	// WaitAll 内部按 zone 去重，同一个 zone 只解析一次 NS 列表。
	if err := m.dns.WaitAll(ctx, records); err != nil {
		return false, m.recordFailure(st, fmt.Errorf("等待 TXT 传播: %w", err))
	}

	// 阶段 3：传播确认之后，才逐个通知 CA 开始验证。
	for _, a := range pending {
		if a.ChallengeSent {
			continue
		}
		if _, err := m.core.Challenges.New(a.ChallengeURL); err != nil {
			return false, m.recordFailure(st, fmt.Errorf("触发验证 (%s): %w", a.Identifier, err))
		}
		a.ChallengeSent = true
		if err := m.store.PutAuthorization(a); err != nil {
			return false, err
		}
	}

	// 阶段 3：轮询直到全部 valid。
	if err := m.awaitAuthorizations(ctx, pending); err != nil {
		return false, m.recordFailure(st, err)
	}

	// 阶段 4：全部验证通过后才统一清理 TXT。
	m.cleanup(c.Name, pending)
	return true, nil
}

func (m *Manager) loadAuthorizations(certName string, urls []string) ([]*state.Authorization, error) {
	existing, err := m.store.ListAuthorizations(certName)
	if err != nil {
		return nil, err
	}
	byURL := make(map[string]*state.Authorization, len(existing))
	for _, a := range existing {
		byURL[a.AuthzURL] = a
	}

	out := make([]*state.Authorization, 0, len(urls))
	for _, u := range urls {
		if a, ok := byURL[u]; ok {
			out = append(out, a)
			continue
		}
		a := &state.Authorization{CertName: certName, AuthzURL: u, Status: "pending"}
		if err := m.store.PutAuthorization(a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (m *Manager) awaitAuthorizations(ctx context.Context, authzs []*state.Authorization) error {
	deadline := m.now().Add(authzWaitTimeout)
	for {
		allValid := true
		for _, a := range authzs {
			cur, err := m.core.Authorizations.Get(a.AuthzURL)
			if err != nil {
				return fmt.Errorf("轮询授权 %s: %w", a.AuthzURL, err)
			}
			a.Status = cur.Status
			if perr := m.store.PutAuthorization(a); perr != nil {
				return perr
			}

			switch cur.Status {
			case "valid":
			case "invalid":
				return fmt.Errorf("identifier %s 验证失败: %s", a.Identifier, authzError(cur))
			default:
				allValid = false
			}
		}
		if allValid {
			return nil
		}
		if m.now().After(deadline) {
			return fmt.Errorf("授权在 %s 内未完成验证，订单保留待下一轮继续", authzWaitTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// cleanup 删除本次写入的所有 TXT。只在全部授权通过后调用。
func (m *Manager) cleanup(certName string, authzs []*state.Authorization) {
	for _, a := range authzs {
		if !a.Presented {
			continue
		}
		keyAuth, err := m.core.GetKeyAuthorization(a.ChallengeToken)
		if err != nil {
			m.log.Warn("计算 key authorization 失败，跳过清理", "identifier", a.Identifier, "err", err)
			continue
		}
		if err := m.dns.CleanUp(a.Identifier, a.ChallengeToken, keyAuth); err != nil {
			m.log.Warn("清理 TXT 失败", "identifier", a.Identifier, "name", a.TxtName, "err", err)
			continue
		}
		a.Presented = false
		if err := m.store.PutAuthorization(a); err != nil {
			m.log.Warn("更新授权状态失败", "identifier", a.Identifier, "err", err)
		}
	}
}

func (m *Manager) finalize(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder,
) error {
	key, err := ParsePrivateKeyPEM(o.KeyPEM)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("加载订单私钥: %w", err))
	}
	csr, err := CreateCSRDER(key, c.Domains)
	if err != nil {
		return m.recordFailure(st, err)
	}

	if o.FinalizeURL == "" {
		return m.recordFailure(st, errors.New("订单缺少 finalize URL，无法提交 CSR"))
	}

	// RFC 8555 §7.4：CSR 必须 POST 到 order 的 finalize URL。
	//
	// lego 那个参数名叫 orderURL 是误导 —— UpdateForCSR 直接往你给的 URL POST。
	// 传 order URL 会被 LE 当成 POST-as-GET 并报
	// "POST-as-GET requests must have an empty payload"。
	if _, err := m.core.Orders.UpdateForCSR(o.FinalizeURL, csr); err != nil {
		return m.recordFailure(st, fmt.Errorf("提交 CSR (finalize): %w", err))
	}

	final, err := m.awaitOrderStatus(ctx, o.OrderURL, "valid", orderWaitTimeout)
	if err != nil {
		return m.recordFailure(st, err)
	}
	m.persistOrder(o, final)
	return m.download(ctx, c, st, o, final)
}

func (m *Manager) awaitOrderStatus(
	ctx context.Context, orderURL, want string, timeout time.Duration,
) (legoacme.ExtendedOrder, error) {
	deadline := m.now().Add(timeout)
	var last legoacme.ExtendedOrder

	for {
		o, err := m.core.Orders.Get(orderURL)
		if err != nil {
			return last, fmt.Errorf("轮询订单: %w", err)
		}
		last = o

		switch o.Status {
		case want, "valid":
			return o, nil
		case "invalid":
			return o, fmt.Errorf("订单已失效: %v", o.Err())
		}

		if m.now().After(deadline) {
			return last, fmt.Errorf("订单在 %s 内未达到 %q（当前 %q）", timeout, want, o.Status)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// download 下载证书、校验，然后部署并推进状态。
//
// 这里的顺序是刻意的：在部署成功之前，绝不覆盖 CertState 里当前生效的
// 证书与私钥。否则部署失败就会连回滚的资本都没有。
func (m *Manager) download(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder,
) error {
	if order.Certificate == "" {
		return m.recordFailure(st, errors.New("订单已 valid 但没有证书 URL"))
	}

	// bundle=true → 返回的是 fullchain（叶子 + 中间证书），正是 CLB 需要的格式。
	fullchain, _, err := m.core.Certificates.Get(order.Certificate, true)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("下载证书: %w", err))
	}

	leaf, err := ParseLeaf(fullchain)
	if err != nil {
		return m.recordFailure(st, err)
	}

	// 最后一道闸门：确认覆盖全部域名、且确实比当前证书新。
	if err := VerifyCoverage(leaf, c.Domains); err != nil {
		return m.recordFailure(st, err)
	}
	if !st.NotAfter.IsZero() && !leaf.NotAfter.After(st.NotAfter) {
		return m.recordFailure(st, fmt.Errorf(
			"新证书 notAfter (%s) 不晚于当前证书 (%s)，拒绝部署", leaf.NotAfter, st.NotAfter))
	}
	if len(o.KeyPEM) == 0 {
		return m.recordFailure(st, errors.New("订单缺少私钥，无法部署"))
	}

	// 部署。首次签发时 DeployedCertID 为空，此时只上传，等人工在 CLB 绑一次。
	deployedID := st.DeployedCertID
	if c.Deploy.Enabled {
		id, derr := m.deployer.Deploy(ctx, c.Name, st.DeployedCertID, fullchain, o.KeyPEM)
		if derr != nil {
			return m.recordFailure(st, fmt.Errorf("部署到腾讯云: %w", derr))
		}
		deployedID = id
	}

	// 部署成功，此时才把新证书提升为生效版本。
	oldDeployedID := st.DeployedCertID

	ariCertID, err := CertID(leaf)
	if err != nil {
		// ARI 不可用不该阻断签发，只是失去了速率豁免。
		m.log.Warn("无法构造 ARI certID，本次续期将不带 replaces", "cert", c.Name, "err", err)
	}

	st.NotAfter = leaf.NotAfter
	st.CertURL = order.Certificate
	st.CertPEM = fullchain
	st.KeyPEM = o.KeyPEM
	st.IssuedAt = m.now()
	st.DeployedCertID = deployedID
	st.ARICertID = ariCertID
	st.ARIWindowStart = time.Time{}
	st.ARIWindowEnd = time.Time{}
	st.ARICheckedAt = time.Time{}
	st.ARIRetryAfter = 0
	st.ConsecutiveFailures = 0
	st.NextAttemptAt = time.Time{}
	st.LastError = ""

	if err := m.store.PutCert(st); err != nil {
		return err
	}

	// 旧证书挂到待回收列表：保留一段时间用于回滚，之后必须回收，
	// 否则腾讯云账号下的上传证书配额迟早被耗光。
	if oldDeployedID != "" && oldDeployedID != deployedID {
		if err := m.store.AddRetiredCert(oldDeployedID, c.Name); err != nil {
			m.log.Warn("记录待回收证书失败", "cert", c.Name, "certId", oldDeployedID, "err", err)
		}
	}

	if err := m.discardOrder(c.Name); err != nil {
		return err
	}

	m.log.Info("证书已续期并生效",
		"cert", c.Name, "notAfter", st.NotAfter,
		"daysLeft", int(time.Until(st.NotAfter).Hours()/24),
		"deployedCertId", deployedID, "ariCertId", ariCertID != "")
	return nil
}

// ReapRetired 回收超过保留期的退役证书。
func (m *Manager) ReapRetired(ctx context.Context) {
	retired, err := m.store.ListRetiredCertsBefore(m.now().Add(-m.retention))
	if err != nil {
		m.log.Warn("查询待回收证书失败", "err", err)
		return
	}
	for _, r := range retired {
		if err := m.deployer.Delete(ctx, r.CertID); err != nil {
			m.log.Warn("回收退役证书失败", "certId", r.CertID, "cert", r.CertName, "err", err)
			continue
		}
		m.log.Info("已回收退役证书",
			"certId", r.CertID, "cert", r.CertName, "retiredAt", r.RetiredAt)
		if err := m.store.DeleteRetiredCert(r.CertID); err != nil {
			m.log.Warn("清理回收记录失败", "certId", r.CertID, "err", err)
		}
	}
}

// recordFailure 记录失败并安排指数退避。
//
// 上限 6 小时不是随手定的：撞上 "5 authorization failures per identifier per hour"
// 之后继续猛重试只会让情况更糟，退到 6 小时意味着每天最多 4 次，
// 远低于限速阈值，同时保证问题修好后能自愈。
func (m *Manager) recordFailure(st *state.CertState, err error) error {
	st.ConsecutiveFailures++
	st.LastError = err.Error()

	shift := st.ConsecutiveFailures - 1
	if shift > 10 {
		shift = 10
	}
	backoff := time.Minute << shift
	if backoff > 6*time.Hour || backoff <= 0 {
		backoff = 6 * time.Hour
	}
	st.NextAttemptAt = m.now().Add(backoff)

	if perr := m.store.PutCert(st); perr != nil {
		return errors.Join(err, perr)
	}

	m.log.Error("处理失败，已安排重试",
		"cert", st.Name, "err", err,
		"consecutiveFailures", st.ConsecutiveFailures, "nextAttemptAt", st.NextAttemptAt)
	return err
}

func (m *Manager) discardOrder(certName string) error {
	if err := m.store.DeleteOrder(certName); err != nil {
		return err
	}
	return m.store.DeleteAuthorizations(certName)
}

func (m *Manager) persistOrder(o *state.Order, order legoacme.ExtendedOrder) {
	o.Status = order.Status
	// 不要用空值覆盖已持久化的 finalize URL —— 丢掉它会让后续无法提交 CSR。
	if order.Finalize != "" {
		o.FinalizeURL = order.Finalize
	}
	o.CertURL = order.Certificate
	if err := m.store.PutOrder(o); err != nil {
		m.log.Warn("更新订单状态失败", "cert", o.CertName, "err", err)
	}
}

func pickDNS01(authz legoacme.Authorization) (legoacme.Challenge, error) {
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			return ch, nil
		}
	}
	return legoacme.Challenge{}, fmt.Errorf(
		"identifier %s 的授权未提供 dns-01 挑战（通配符只能走 DNS-01）", authz.Identifier.Value)
}

func authzError(authz legoacme.Authorization) string {
	for _, ch := range authz.Challenges {
		if ch.Error != nil {
			return ch.Error.Detail
		}
	}
	return "CA 未给出具体原因"
}
