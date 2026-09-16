package acme

import (
	"fmt"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/state"
)

// 各字段未配置时用的默认值。它们在 config 里也各有一份，这里是兜底 ——
// 策略是通过 SetFallbackPolicy 传进来的，不保证经过 config.normalize。
const (
	defaultFallbackAfterFailures = 5
	defaultFallbackBeforeExpiry  = 7 * 24 * time.Hour
	defaultFallbackMinIdentFail  = 3
	defaultFallbackFailureWindow = 24 * time.Hour
	defaultFallbackMinNames      = 1
)

// SetFallbackPolicy 挂上"到期前拆分子集先签"的策略。
//
// 不调用它就等于完全关闭 —— 这是默认状态。它会改变证书覆盖什么，
// 那是安全决策，不该由程序替人做。
func (m *Manager) SetFallbackPolicy(p config.FailureFallback) { m.fallback = &p }

// applyFallback 决定这一轮该为什么样的域名集合下单。
//
// 绝大多数时候它原样返回。只有在一张证书已经"快到期了而且一直签不出来"
// 的时候才摘掉其中反复失败的那几个名字 —— 那 24 个本来好的名字不该
// 陪着 1 个配错 DNS 的名字一起过期。
func (m *Manager) applyFallback(c *config.Certificate, st *state.CertState) *config.Certificate {
	kept, dropped, reason := m.fallbackDomains(c, st)

	if len(dropped) == 0 {
		metrics.CertificateFallbackActive.WithLabelValues(c.Name).Set(0)
		metrics.CertificateFallbackDropped.WithLabelValues(c.Name).Set(0)

		// 这一轮用的是全集。如果之前处于降级，说明已经恢复 ——
		// 那条记录的全部意义就是"现在有一张缺名字的证书在服务"。
		if fb, err := m.store.GetFallback(c.Name); err == nil && fb != nil {
			m.log.Info("back on the full name set; clearing the fallback record",
				"cert", c.Name, "wasDropping", fb.Dropped, "since", fb.Since)
			if cerr := m.store.ClearFallback(c.Name); cerr != nil {
				m.log.Warn("cannot clear the fallback record", "cert", c.Name, "err", cerr)
			}
		}
		// 顺手把老账本丢掉：那些 identifier 已经不在证书里了，
		// 它们的授权永远不会再被尝试，也就永远等不到一次"成功"来清掉它们。
		if perr := m.store.PruneIdentifierFailures(c.Name, m.now(),
			m.fallbackWindow()); perr != nil {
			m.log.Warn("cannot prune the identifier failure ledger", "cert", c.Name, "err", perr)
		}
		return c
	}

	cp := *c
	cp.Domains = kept

	// ERROR 而不是 WARN：这是一次"我们主动把某些名字从证书里拿掉了"的决定，
	// 必须吵闹到没人能错过。
	m.log.Error("FALLING BACK to a subset of names so the rest stay available",
		"cert", c.Name,
		"keeping", kept, "dropping", dropped,
		"consecutiveFailures", st.ConsecutiveFailures,
		"notAfter", st.NotAfter,
		"reason", reason)

	metrics.CertificateFallbackActive.WithLabelValues(c.Name).Set(1)
	metrics.CertificateFallbackDropped.WithLabelValues(c.Name).Set(float64(len(dropped)))

	if err := m.store.PutFallback(&state.Fallback{
		CertName: c.Name, Dropped: dropped, Since: m.now(), Reason: reason,
	}); err != nil {
		m.log.Warn("cannot record the fallback state", "cert", c.Name, "err", err)
	}
	return &cp
}

// fallbackDomains 判断该不该降级，以及该摘掉哪些名字。
//
// 返回的 dropped 非空才表示要降级。所有条件必须同时满足：
//
//   - 策略显式开启
//   - 已经有一张生效的证书（没有它就没有"保住现有的"这个立论）
//   - 这张证书连续失败足够多次
//   - 已经进入到期前的危险窗口
//   - 有**具体某个** identifier 反复失败
//   - 摘完之后剩下的名字不少于下限
//
// 最后两条是关键。不知道是哪个名字坏的时候绝不能摘 —— 随机摘会把
// 本来好的名字也一起牺牲掉，那比不降级更糟。
func (m *Manager) fallbackDomains(c *config.Certificate, st *state.CertState) (kept, dropped []string, reason string) {
	p := m.fallback
	if p == nil || !p.EnabledOr(false) {
		return c.Domains, nil, ""
	}

	// 没有生效证书就没有"部分可用"可言：那不是保住什么，而是只签一部分。
	if st.NotAfter.IsZero() {
		return c.Domains, nil, ""
	}

	afterFailures := p.AfterFailuresOr(defaultFallbackAfterFailures)
	if st.ConsecutiveFailures < afterFailures {
		return c.Domains, nil, ""
	}

	beforeExpiry := p.BeforeExpiryDur
	if beforeExpiry <= 0 {
		beforeExpiry = defaultFallbackBeforeExpiry
	}
	left := st.NotAfter.Sub(m.now())
	if left > beforeExpiry {
		return c.Domains, nil, ""
	}

	failures, err := m.store.ListIdentifierFailures(c.Name)
	if err != nil {
		m.log.Warn("cannot read the identifier failure ledger; not falling back",
			"cert", c.Name, "err", err)
		return c.Domains, nil, ""
	}

	// 只摘"最近还在失败"的那些。老记录不参与 —— 那正是自愈的入口：
	// 问题修好之后记录老化，下一轮自然就去试全集了。
	minFailures := p.MinIdentifierFailuresOr(defaultFallbackMinIdentFail)
	cutoff := m.now().Add(-m.fallbackWindow())

	bad := make(map[string]*state.IdentifierFailure)
	for _, f := range failures {
		if f.Failures >= minFailures && f.LastFailedAt.After(cutoff) {
			bad[f.Identifier] = f
		}
	}
	if len(bad) == 0 {
		return c.Domains, nil, ""
	}

	kept = make([]string, 0, len(c.Domains))
	for _, d := range c.Domains {
		if _, isBad := bad[d]; isBad {
			dropped = append(dropped, d)
			continue
		}
		kept = append(kept, d)
	}

	minNames := p.MinNamesOr(defaultFallbackMinNames)
	if len(kept) < minNames {
		// 这已经是"全挂"换了个样子，却会让人以为还有部分可用。
		m.log.Error("the failure fallback would leave too few names; refusing to fall back",
			"cert", c.Name, "wouldKeep", len(kept), "minNames", minNames, "wouldDrop", dropped)
		return c.Domains, nil, ""
	}

	return kept, dropped, fmt.Sprintf(
		"issuance has failed %d times in a row and the certificate expires in %s; "+
			"dropping the names whose authorizations keep failing so the rest stay available "+
			"(and so this stops consuming the exact-set quota every hour)",
		st.ConsecutiveFailures, left.Round(time.Hour))
}

func (m *Manager) fallbackWindow() time.Duration {
	if m.fallback != nil && m.fallback.FailureWindowDur > 0 {
		return m.fallback.FailureWindowDur
	}
	return defaultFallbackFailureWindow
}
