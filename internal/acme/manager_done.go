package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// download 下载证书、校验，然后部署并推进状态。
//
// 这里的顺序是刻意的：在部署成功之前，绝不覆盖 CertState 里当前生效的
// 证书与私钥。否则部署失败就会连回滚的资本都没有。
func (m *Manager) download(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder,
) error {
	if order.Certificate == "" {
		return m.recordFailure(st, errors.New("the order is valid but has no certificate URL"))
	}

	// 幂等兜底：订单对应的证书已经是当前生效的那一张，说明上一轮
	// "下载 + 部署"其实成功了，只是收尾（丢弃订单）没做完。
	//
	// 这种情况下如果继续往下走，会被下面那道 notAfter 闸门挡下来 ——
	// 新证书不可能比它自己更新 —— 于是每轮都报一次错、退避到 6 小时，
	// 把一次成功的续期报成持续故障，consecutive_failures 一路涨到需要人工介入。
	// 既然结果是已达成状态，直接收尾即可。
	if st.CertURL != "" && st.CertURL == order.Certificate && !st.NotAfter.IsZero() {
		m.log.Info("the order's certificate is already the live one; skipping the duplicate deploy",
			"cert", c.Name, "certUrl", order.Certificate)
		if !st.DeployConfirmed && c.Deploy.Enabled {
			m.log.Warn("but this certificate is not confirmed deployed to a cloud resource; check that the CLB listener has it bound",
				"cert", c.Name, "deployedCertId", st.DeployedCertID)
		}
		return m.discardOrder(ctx, c.Name)
	}

	// bundle=true → 返回的是 fullchain（叶子 + 中间证书），正是 CLB 需要的格式。
	fullchain, _, err := m.core.Certificates.Get(order.Certificate, true)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("download certificate: %w", err))
	}

	leaf, err := ParseLeaf(fullchain)
	if err != nil {
		return m.recordFailure(st, err)
	}

	if err := VerifyCoverage(leaf, c.Domains); err != nil {
		return m.recordFailure(st, err)
	}
	if !st.NotAfter.IsZero() && !leaf.NotAfter.After(st.NotAfter) {
		return m.recordFailure(st, fmt.Errorf(
			"the new certificate's notAfter (%s) is not later than the current one (%s); refusing to deploy", leaf.NotAfter, st.NotAfter))
	}
	if len(o.KeyPEM) == 0 {
		return m.recordFailure(st, errors.New("the order has no private key; cannot deploy"))
	}

	// 部署。首次签发时 DeployedCertID 为空，此时只上传，等人工在 CLB 绑一次。
	// 上传成功不等于已经绑到监听器：DeployConfirmed 要等一键更新真正换完才置位。
	oldDeployedID := st.DeployedCertID
	deployedID := oldDeployedID
	rebound := false
	if c.Deploy.Enabled {
		id, derr := m.deployer.Deploy(ctx, c.Name, oldDeployedID, fullchain, o.KeyPEM)
		if derr != nil {
			// Deployer 的约定是：出错时仍然把已经上传成功的证书 ID 返回来
			// （见 internal/deploy/tencent.go 的 Deploy）。那个 ID 必须记进
			// 待回收列表 —— 否则它既不在 certificates 表、也不在 retired 表里，
			// ReapRetired 永远看不到它，一次失败就在腾讯云上漏下一张证书，
			// 最后撞上账号配额，而回收机制的存在意义正是防这个。
			m.recordOrphanCert(id, oldDeployedID, c.Name)
			return m.recordFailure(st, fmt.Errorf("deploy to Tencent Cloud: %w", derr))
		}
		deployedID = id
		rebound = oldDeployedID != ""
	}

	ariCertID, err := CertID(leaf)
	if err != nil {
		// ARI 不可用不该阻断签发，只是失去了速率豁免。
		m.log.Warn("could not build the ARI certID; this renewal will go out without replaces", "cert", c.Name, "err", err)
	}

	// 部署成功，此时才把新证书提升为生效版本。
	st.NotAfter = leaf.NotAfter
	st.CertURL = order.Certificate
	st.CertPEM = fullchain
	st.KeyPEM = o.KeyPEM
	st.IssuedAt = m.now()
	st.DeployedCertID = deployedID
	if rebound {
		st.DeployConfirmed = true
	} else if oldDeployedID == "" {
		// 首次上传：CertId 要记下来给人手绑定，但指标仍应显示未部署。
		st.DeployConfirmed = false
	}
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

	// 只有确认已经从旧证换到新证之后，才把旧证挂到待回收列表。
	// 首次上传还没绑监听器时绝不能退休，否则 7 天后会把人手刚绑上的证删掉。
	if rebound && oldDeployedID != "" && oldDeployedID != deployedID {
		if err := m.store.AddRetiredCert(oldDeployedID, c.Name); err != nil {
			m.log.Warn("failed to record the certificate for reclaim", "cert", c.Name, "certId", oldDeployedID, "err", err)
		}
	}

	if err := m.discardOrder(ctx, c.Name); err != nil {
		return err
	}

	if !c.Deploy.Enabled {
		m.log.Info("certificate issued and recorded locally (cloud deploy is off)",
			"cert", c.Name, "notAfter", st.NotAfter,
			"daysLeft", int(time.Until(st.NotAfter).Hours()/24))
	} else if !st.DeployConfirmed {
		m.log.Info("certificate uploaded; waiting for a one-time manual bind in the CLB console",
			"cert", c.Name, "notAfter", st.NotAfter,
			"uploadedCertId", deployedID,
			"hint", "once bound, later renewals switch it automatically via UpdateCertificateInstance")
	} else {
		m.log.Info("certificate renewed and live",
			"cert", c.Name, "notAfter", st.NotAfter,
			"daysLeft", int(time.Until(st.NotAfter).Hours()/24),
			"deployedCertId", deployedID, "ariCertId", ariCertID != "")
	}
	return nil
}

// ReapRetired 回收超过保留期的退役证书。
func (m *Manager) ReapRetired(ctx context.Context) {
	retired, err := m.store.ListRetiredCertsBefore(m.now().Add(-m.retention))
	if err != nil {
		m.log.Warn("failed to list retired certificates", "err", err)
		return
	}
	for _, r := range retired {
		if err := m.deployer.Delete(ctx, r.CertID); err != nil {
			m.log.Warn("failed to reclaim a retired certificate", "certId", r.CertID, "cert", r.CertName, "err", err)
			continue
		}
		m.log.Info("reclaimed a retired certificate",
			"certId", r.CertID, "cert", r.CertName, "retiredAt", r.RetiredAt)
		if err := m.store.DeleteRetiredCert(r.CertID); err != nil {
			m.log.Warn("failed to remove the reclaim record", "certId", r.CertID, "err", err)
		}
	}
}

// recordFailure 记录失败并安排指数退避。
// recordFailure 记录失败并安排指数退避。
//
// 上限 6 小时不是随手定的：撞上 "5 authorization failures per identifier per hour"
// 之后继续猛重试只会让情况更糟，退到 6 小时意味着每天最多 4 次，
// 远低于限速阈值，同时保证问题修好后能自愈。
func (m *Manager) recordFailure(st *state.CertState, err error) error {
	// 停进程 / 父 context 取消不是业务失败。记进去会拉长退避，
	// 重启后本该立刻续推同一张订单，结果被挡在窗口外。
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		m.log.Warn("pass cancelled; not counted as a failure and no backoff applied", "cert", st.Name, "err", err)
		return err
	}

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

	m.log.Error("pass failed; a retry has been scheduled",
		"cert", st.Name, "err", err,
		"consecutiveFailures", st.ConsecutiveFailures, "nextAttemptAt", st.NextAttemptAt)
	return err
}

// discardOrder 丢弃当前订单，并**在删掉授权行之前先把 TXT 收掉**。
//
// 顺序不能反。授权行（TxtName / ChallengeToken / TxtValue）是清理 DNS 的
// 唯一线索，行一旦删掉，那些 _acme-challenge 记录就永远回收不了了。
//
// 这里以前只删行、不清 DNS，于是每走一次"订单已 ready、直接 finalize"
// 的路径（也就是 solveChallenges 被整个跳过的那条常见路径），
// DNSPod 上就攒下一条僵尸 TXT —— 而"授权验证跨轮次"在免费套餐
// 2 分钟以上的传播时间里恰恰是常态。
//
// 清理交给 cleanupOrphanTXT：它自己负责删掉已经处理完的行，
// 并保留那些定位不到 token 的行留给下一轮重试。
func (m *Manager) discardOrder(ctx context.Context, certName string) error {
	if err := m.cleanupOrphanTXT(ctx, certName); err != nil {
		// 清理失败不能阻止丢弃订单 —— 否则会卡在一张签不出结果的订单上，
		// 那比多留一条 TXT 严重得多。
		m.log.Warn("failed to clean up TXT before discarding the order", "cert", certName, "err", err)
	}
	return m.store.DeleteOrder(certName)
}

// parseOrderExpires 解析 ACME 订单的 expires。空值或无法解析时退回 now+defaultOrderTTL，
// 保证落盘的 ExpiresAt 永远不是零值。
func parseOrderExpires(raw string, now time.Time) (time.Time, error) {
	fallback := now.Add(defaultOrderTTL)
	if raw == "" {
		return fallback, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, nil
	}
	return fallback, fmt.Errorf("cannot parse expires %q", raw)
}

func (m *Manager) persistOrder(o *state.Order, order legoacme.ExtendedOrder) {
	o.Status = order.Status
	// 不要用空值覆盖已持久化的 finalize URL —— 丢掉它会让后续无法提交 CSR。
	if order.Finalize != "" {
		o.FinalizeURL = order.Finalize
	}
	if order.Certificate != "" {
		o.CertURL = order.Certificate
	}
	if err := m.store.PutOrder(o); err != nil {
		m.log.Warn("failed to update the order state", "cert", o.CertName, "err", err)
	}
}

func pickDNS01(authz legoacme.Authorization) (legoacme.Challenge, error) {
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			return ch, nil
		}
	}
	return legoacme.Challenge{}, fmt.Errorf(
		"the authorization for identifier %s offers no dns-01 challenge (wildcards can only use DNS-01)", authz.Identifier.Value)
}

func authzError(authz legoacme.Authorization) string {
	for _, ch := range authz.Challenges {
		if ch.Error != nil {
			return ch.Error.Detail
		}
	}
	return "the CA gave no specific reason"
}

// recordOrphanCert 把一个"云上已经存在、但本地没有归属"的证书记进待回收列表。
//
// 场景是 Deploy 上传成功、重绑定失败。不记下来的话，这张证书既不在
// certificates 表也不在 retired 表里，回收器永远看不到 ——
// 而腾讯云账号下上传证书是有配额的，漏几张之后就无法续期了。
func (m *Manager) recordOrphanCert(newID, liveID, certName string) {
	if newID == "" || newID == liveID {
		return
	}
	if err := m.store.AddRetiredCert(newID, certName); err != nil {
		m.log.Warn("failed to record the orphaned certificate (it will occupy Tencent Cloud certificate quota indefinitely)",
			"cert", certName, "certId", newID, "err", err)
		return
	}
	m.log.Info("the certificate uploaded during the failed deploy has been recorded for reclaim and will be deleted later",
		"cert", certName, "certId", newID)
}
