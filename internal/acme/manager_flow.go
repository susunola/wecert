package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/state"
)

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
		// 授权已全部 valid（例如上次等到 valid 后、cleanup 前崩溃）。
		// 仍然尝试清掉可能残留的 TXT，避免 DNSPod 记录配额被慢慢占满。
		m.cleanup(c.Name, authzs)
		return true, nil
	}

	if err := m.dns.WaitAll(ctx, records); err != nil {
		return false, m.recordFailure(st, fmt.Errorf("等待 TXT 传播: %w", err))
	}

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

	if err := m.awaitAuthorizations(ctx, pending); err != nil {
		return false, m.recordFailure(st, err)
	}

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

// cleanup 删除本次写入的所有 TXT。
func (m *Manager) cleanup(_ string, authzs []*state.Authorization) {
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
	// lego 那个参数名叫 orderURL 是误导 —— UpdateForCSR 直接往你给的 URL POST。
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
