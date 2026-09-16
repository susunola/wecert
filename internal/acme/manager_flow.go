package acme

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// authzFetchConcurrency 限制同时在飞的授权查询数量。
//
// SAN 多的证书上这一步必须并发：100 个授权串行拉一遍就是 100 次往返，
// 3 分钟的等待预算撑不了几轮。上限取 8 是为了不给 CA 造成突发压力。
//
// 并发的安全性来自 lego 的实现：api.Core 在构造完成后只有 nonce 管理器
// 这类可变状态，而它是带 mutex 的；JWS 与 Doer 都是只读。
const authzFetchConcurrency = 8

// advance 推进订单状态机。
func (m *Manager) advance(ctx context.Context, c *config.Certificate, st *state.CertState, o *state.Order) error {
	order, err := m.core.GetOrder(o.OrderURL)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("get order: %w", err))
	}
	m.persistOrder(o, order)

	switch order.Status {
	case "valid":
		return m.download(ctx, c, st, o, order)

	case "invalid":
		// 订单废了。清理掉，让下一轮从头决策（此时会走退避）。
		err := fmt.Errorf("order became invalid: %v", order.Err())
		if derr := m.discardOrder(ctx, c.Name); derr != nil {
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

// fetchAuthzs 并发拉取多个授权的当前状态，结果顺序与入参一致。
//
// 串行拉取在 SAN 很多的证书上是真的会超时的：100 个授权、每个一次往返，
// 一轮就要十几秒到几十秒，3 分钟的等待预算撑不了几轮，
// 而且每次都白等在那儿。并发是这里唯一可行的做法。
//
// goroutine 里只写自己那一格、不碰 store，所以不需要额外加锁；
// 对 api.Core 的并发调用是安全的（nonce 管理器带 mutex）。
func (m *Manager) fetchAuthzs(ctx context.Context, authzs []*state.Authorization) ([]legoacme.Authorization, error) {
	out := make([]legoacme.Authorization, len(authzs))
	errs := make([]error, len(authzs))
	if len(authzs) == 0 {
		return out, nil
	}

	limit := authzFetchConcurrency
	if len(authzs) < limit {
		limit = len(authzs)
	}

	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, a := range authzs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, authzURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := ctx.Err(); err != nil {
				errs[i] = err
				return
			}
			cur, err := m.core.GetAuthorization(authzURL)
			if err != nil {
				errs[i] = err
				return
			}
			out[i] = cur
		}(i, a.AuthzURL)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("get authorization %s: %w", authzs[i].AuthzURL, err)
		}
	}
	return out, nil
}

// solveChallenges 返回 allValid=true 表示订单的所有授权都已通过验证。
func (m *Manager) solveChallenges(
	ctx context.Context, c *config.Certificate, st *state.CertState, order legoacme.ExtendedOrder,
) (bool, error) {
	authzs, err := m.loadAuthorizations(c.Name, order.Authorizations)
	if err != nil {
		return false, m.recordFailure(st, err)
	}

	current, err := m.fetchAuthzs(ctx, authzs)
	if err != nil {
		return false, m.recordFailure(st, err)
	}

	// 阶段 1：把所有待验证的 TXT 一次性写完。
	// 这里绝对不能"写一条 → 验一条 → 删一条"：签 example.com + *.example.com 时，
	// 两个授权的 challenge 值都落在 _acme-challenge.example.com 上，必须同时存在。
	var pending []*state.Authorization
	var records []DNSRecord

	for i, a := range authzs {
		cur := current[i]
		a.Status = cur.Status
		a.Identifier = cur.Identifier.Value

		switch cur.Status {
		case "valid":
			if err := m.store.PutAuthorization(a); err != nil {
				return false, err
			}
			continue
		case "invalid":
			// 先把失效状态落盘再报错。
			// 写失败不掩盖主因（授权失效才是要报的），但必须留痕 ——
			// 静默吞掉 DB 错误会让后续排障失去线索。
			if perr := m.store.PutAuthorization(a); perr != nil {
				m.log.Warn("failed to record the invalidated authorization",
					"cert", c.Name, "identifier", a.Identifier, "err", perr)
			}
			return false, m.recordFailure(st, fmt.Errorf(
				"the authorization for identifier %s is invalid: %s", a.Identifier, authzError(cur)))
		}

		if !a.Presented {
			chlg, err := pickDNS01(cur)
			if err != nil {
				return false, m.recordFailure(st, err)
			}
			keyAuth, err := m.keyAuth.GetKeyAuthorization(chlg.Token)
			if err != nil {
				return false, m.recordFailure(st, fmt.Errorf("compute the key authorization: %w", err))
			}

			// 只写入，不等待传播 —— 等所有 TXT 都写完之后统一等一次。
			// 逐条等待会让 wildcard 和 apex 在同一个 TXT 名字上白等两遍
			// （DNSPod 免费套餐一轮传播要 2 分钟以上，这一下就是几分钟）。
			rec, err := m.dns.Present(ctx, a.Identifier, chlg.Token, keyAuth)
			if err != nil {
				return false, m.recordFailure(st, fmt.Errorf("present TXT (%s): %w", a.Identifier, err))
			}

			a.ChallengeURL = chlg.URL
			a.ChallengeToken = chlg.Token
			a.TxtName = rec.FQDN
			a.TxtValue = rec.Value
			a.Presented = true
			m.log.Info("TXT presented",
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
		m.cleanup(ctx, c.Name, authzs)
		return true, nil
	}

	// 阶段 2：所有 TXT 都写完之后，统一等一次权威 NS 传播。
	// WaitAll 内部按 zone 去重，同一个 zone 只解析一次 NS 列表。
	if err := m.dns.WaitAll(ctx, records); err != nil {
		return false, m.recordFailure(st, fmt.Errorf("wait for TXT propagation: %w", err))
	}

	// 阶段 3：传播确认之后，才逐个通知 CA 开始验证。
	for _, a := range pending {
		if a.ChallengeSent {
			continue
		}
		if err := m.core.AcceptChallenge(a.ChallengeURL); err != nil {
			return false, m.recordFailure(st, fmt.Errorf("trigger validation (%s): %w", a.Identifier, err))
		}
		a.ChallengeSent = true
		if err := m.store.PutAuthorization(a); err != nil {
			return false, err
		}
	}

	// 阶段 4：轮询直到全部 valid。
	if err := m.awaitAuthorizations(ctx, pending); err != nil {
		return false, m.recordFailure(st, err)
	}

	// 阶段 5：全部验证通过后才统一清理 TXT。
	m.cleanup(ctx, c.Name, pending)
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
		current, err := m.fetchAuthzs(ctx, authzs)
		if err != nil {
			return err
		}

		allValid := true
		for i, a := range authzs {
			cur := current[i]
			a.Status = cur.Status
			if perr := m.store.PutAuthorization(a); perr != nil {
				return perr
			}

			switch cur.Status {
			case "valid":
			case "invalid":
				return fmt.Errorf("validation failed for identifier %s: %s", a.Identifier, authzError(cur))
			default:
				allValid = false
			}
		}
		if allValid {
			return nil
		}
		if m.now().After(deadline) {
			return fmt.Errorf("authorizations did not complete within %s; keeping the order for the next pass", authzWaitTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// cleanup 删除本次写入的所有 TXT。只在全部授权通过后调用。
func (m *Manager) cleanup(ctx context.Context, certName string, authzs []*state.Authorization) {
	for _, a := range authzs {
		cleaned, err := m.removeAuthzTXT(ctx, a)
		if err != nil {
			// 保留 Presented=true，下一轮（或收尾时的 cleanupOrphanTXT）还会再试一次。
			m.log.Warn("failed to clean up TXT",
				"cert", certName, "identifier", a.Identifier, "name", a.TxtName, "err", err)
			continue
		}
		if !cleaned {
			// 连记录都定位不到，Presented 必须留着，别把唯一的线索擦掉。
			continue
		}
		a.Presented = false
		if err := m.store.PutAuthorization(a); err != nil {
			m.log.Warn("failed to update the authorization state", "cert", certName, "identifier", a.Identifier, "err", err)
		}
	}
}

// removeAuthzTXT 删掉一条授权写进 DNS 的那条 TXT。
//
// 返回值 cleaned 表示"DNS 上已经没有这条记录了"，可以是本来就没写、
// 也可以是这次删掉了。cleaned=false 且 err=nil 表示这条记录定位不到
// （缺 token），调用方**必须保留授权行** —— 行里的 TxtName 是唯一还能
// 拿来人工排查的线索。
func (m *Manager) removeAuthzTXT(ctx context.Context, a *state.Authorization) (cleaned bool, err error) {
	if a == nil || !a.Presented {
		return true, nil
	}
	if a.ChallengeToken == "" || a.Identifier == "" {
		m.log.Warn("the authorization has no token, so the TXT record cannot be located (keeping the row for manual investigation)",
			"cert", a.CertName, "identifier", a.Identifier, "name", a.TxtName)
		return false, nil
	}
	keyAuth, err := m.keyAuth.GetKeyAuthorization(a.ChallengeToken)
	if err != nil {
		return false, fmt.Errorf("compute the key authorization: %w", err)
	}
	if err := m.dns.CleanUp(ctx, a.Identifier, a.ChallengeToken, keyAuth); err != nil {
		return false, fmt.Errorf("clean up TXT %s: %w", a.TxtName, err)
	}
	return true, nil
}

// cleanupOrphanTXT 回收"已经写进 DNS、但已不属于任何进行中订单"的 TXT 记录。
//
// 两类来源：
//   - 丢弃订单时的正常清理（discardOrder 会先调它）；
//   - 上一次收尾只成功了一半（删订单成功、删授权失败），或进程被 kill。
//
// 第二类正是这个函数存在的意义：幂等、能自愈，不需要人去 DNSPod 后台翻。
func (m *Manager) cleanupOrphanTXT(ctx context.Context, certName string) error {
	authzs, err := m.store.ListAuthorizations(certName)
	if err != nil {
		return err
	}

	var cleaned, stuck int
	for _, a := range authzs {
		if !a.Presented {
			// 没写进 DNS 的行直接清掉，不留垃圾。
			if err := m.store.DeleteAuthorization(certName, a.AuthzURL); err != nil {
				m.log.Warn("failed to delete authorization rows", "cert", certName, "authz", a.AuthzURL, "err", err)
			}
			continue
		}

		ok, err := m.removeAuthzTXT(ctx, a)
		if err != nil {
			m.log.Warn("failed to reclaim a leftover TXT record",
				"cert", certName, "identifier", a.Identifier, "name", a.TxtName, "err", err)
			continue
		}
		if !ok {
			// 定位不到那条记录：保留授权行，别把 TxtName 这条线索也丢了。
			stuck++
			continue
		}
		cleaned++
		if err := m.store.DeleteAuthorization(certName, a.AuthzURL); err != nil {
			m.log.Warn("failed to delete authorization rows", "cert", certName, "authz", a.AuthzURL, "err", err)
		}
	}

	if cleaned > 0 {
		m.log.Info("reclaimed a leftover _acme-challenge TXT record", "cert", certName, "count", cleaned)
	}
	if stuck > 0 {
		m.log.Warn("some TXT records could not be reclaimed automatically; clean them up in the DNS console",
			"cert", certName, "count", stuck,
			"hint", "no challenge token, so the specific record cannot be located")
	}
	return nil
}

func (m *Manager) finalize(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder,
) error {
	key, err := ParsePrivateKeyPEM(o.KeyPEM)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("load the order's private key: %w", err))
	}
	csr, err := CreateCSRDER(key, c.Domains)
	if err != nil {
		return m.recordFailure(st, err)
	}

	if o.FinalizeURL == "" {
		return m.recordFailure(st, errors.New("the order has no finalize URL; cannot submit the CSR"))
	}

	// RFC 8555 §7.4：CSR 必须 POST 到 order 的 finalize URL。
	//
	// lego 那个参数名叫 orderURL 是误导 —— UpdateForCSR 直接往你给的 URL POST。
	// 传 order URL 会被 LE 当成 POST-as-GET 并报
	// "POST-as-GET requests must have an empty payload"。
	if _, err := m.core.UpdateOrderForCSR(o.FinalizeURL, csr); err != nil {
		return m.recordFailure(st, fmt.Errorf("submit CSR (finalize): %w", err))
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
		o, err := m.core.GetOrder(orderURL)
		if err != nil {
			return last, fmt.Errorf("poll order: %w", err)
		}
		last = o

		switch o.Status {
		case want, "valid":
			return o, nil
		case "invalid":
			return o, fmt.Errorf("order became invalid: %v", o.Err())
		}

		if m.now().After(deadline) {
			return last, fmt.Errorf("the order did not reach %q within %s (currently %q)", timeout, want, o.Status)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
