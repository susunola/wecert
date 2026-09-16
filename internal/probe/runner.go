package probe

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/metrics"
)

// 状态取值。用常量而不是随手写的字符串：它是告警去重用的键，
// 拼错一个字母会让同一种状态被当成两种，于是每轮都告警。
const (
	stateOK          = "ok"
	stateMismatch    = "mismatch"
	stateUnreachable = "unreachable"
)

// Runner 负责"探测 + 判定 + 记指标 + 只在状态跳变时告警"。
//
// 为什么只在跳变时告警：这个探测每轮都跑，而网络抖动是常态。
// 每轮都打一条 ERROR 会让人很快学会忽略它，那条告警就等于不存在。
// 反过来也绝不能不打 —— 从 ok 掉到 mismatch 是这个探测存在的全部意义。
type Runner struct {
	opts Options

	// minValidFor 是"至少还要剩多久有效期"，0 表示不检查。
	minValidFor time.Duration

	log *slog.Logger

	mu   sync.Mutex
	last map[string]string
}

// NewRunner 构造探测器。minValidFor 为 0 表示不检查剩余有效期。
func NewRunner(opts Options, minValidFor time.Duration, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	return &Runner{
		opts:        opts,
		minValidFor: minValidFor,
		log:         log,
		last:        make(map[string]string),
	}
}

// Check 探测一个名字，按期望判定，并把结果落到指标与日志。
//
// 返回判定结果供调用方使用，但**是否告警由这里决定** ——
// 它是唯一持有"上次是什么状态"的地方。
func (r *Runner) Check(ctx context.Context, host string, e Expectation) Verdict {
	res, err := Probe(ctx, host, r.opts)
	if err != nil {
		metrics.CertificateProbeErrors.WithLabelValues(host).Inc()

		// 连不上和证书不对必须分开报：从运行 wecert 的这台机器拨不出去
		// 是环境问题，不是证书问题。混成一个结论会让人去查错方向 ——
		// 而"以为证书坏了"比"探测没跑成"严重得多。
		r.transition(host, stateUnreachable,
			"cannot reach this name to check which certificate it serves", "err", err)
		return Verdict{Problems: []string{err.Error()}}
	}

	metrics.CertificateProbeNotAfter.WithLabelValues(host).Set(float64(res.NotAfter.Unix()))
	if res.Trusted {
		metrics.CertificateProbeTrusted.WithLabelValues(host).Set(1)
	} else {
		metrics.CertificateProbeTrusted.WithLabelValues(host).Set(0)
	}

	if e.Now.IsZero() {
		e.Now = time.Now()
	}
	if e.MinValidFor == 0 {
		e.MinValidFor = r.minValidFor
	}

	v := res.Verify(e)
	if v.OK {
		metrics.CertificateProbeMatch.WithLabelValues(host).Set(1)
		r.transition(host, stateOK, "the certificate being served is the one that was deployed",
			"notAfter", res.NotAfter, "daysLeft", res.DaysLeft(e.Now), "issuer", res.Issuer,
			"trusted", res.Trusted, "handshakeMs", res.HandshakeMS)
		return v
	}

	metrics.CertificateProbeMatch.WithLabelValues(host).Set(0)
	// 一次把所有问题列全。让人拨第二遍才知道还有别的问题，
	// 等于把排障成本乘以问题个数。
	r.transition(host, stateMismatch, "the certificate being served is not the one that was deployed",
		"problems", v.Problems, "servedNotAfter", res.NotAfter,
		"sans", res.SANs, "issuer", res.Issuer, "remoteAddr", res.RemoteAddr)
	return v
}

// LastState 返回某个名字上一次的状态，主要用于诊断。
// 空字符串表示还没探测过。
func (r *Runner) LastState(host string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last[host]
}

func (r *Runner) transition(host, state, msg string, attrs ...any) {
	r.mu.Lock()
	prev, seen := r.last[host]
	r.last[host] = state
	r.mu.Unlock()

	if seen && prev == state {
		return
	}

	args := append([]any{"host", host, "state", state, "previous", prev}, attrs...)
	if state == stateOK {
		r.log.Info(msg, args...)
		return
	}
	r.log.Error(msg, args...)
}
