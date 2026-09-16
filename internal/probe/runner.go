package probe

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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

	// Keep probeAll injectable so multi-address aggregation can be tested without
	// relying on real DNS; production instances always use ProbeAll.
	probeAll func(context.Context, string, Options) ([]Attempt, error)

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
		probeAll:    ProbeAll,
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
	attempts, err := r.probeAll(ctx, host, r.opts)
	if err != nil {
		metrics.CertificateProbeErrors.WithLabelValues(host).Inc()

		// 连不上和证书不对必须分开报：从运行 wecert 的这台机器拨不出去
		// 是环境问题，不是证书问题。混成一个结论会让人去查错方向 ——
		// 而"以为证书坏了"比"探测没跑成"严重得多。
		r.transition(host, stateUnreachable,
			"cannot reach this name to check which certificate it serves", "err", err)
		return Verdict{Problems: []string{err.Error()}}
	}

	if e.Now.IsZero() {
		e.Now = time.Now()
	}
	if e.MinValidFor == 0 {
		e.MinValidFor = r.minValidFor
	}

	var (
		first       *Result
		problems    []string
		attemptErrs []string
	)
	for _, attempt := range attempts {
		if attempt.Err != nil {
			metrics.CertificateProbeErrors.WithLabelValues(host).Inc()
			attemptErrs = append(attemptErrs, fmt.Sprintf("%s: %v", attempt.Address, attempt.Err))
			continue
		}
		if attempt.Result == nil {
			continue
		}
		if first == nil {
			first = attempt.Result
		}
		if v := attempt.Result.Verify(e); !v.OK {
			for _, p := range v.Problems {
				problems = append(problems, fmt.Sprintf("%s: %s", attempt.Address, p))
			}
		}
	}

	if first == nil {
		msg := "no resolved address completed a TLS handshake"
		if len(attemptErrs) > 0 {
			msg += ": " + strings.Join(attemptErrs, " | ")
		}
		r.transition(host, stateUnreachable,
			"cannot reach this name to check which certificate it serves", "err", msg)
		return Verdict{Problems: []string{msg}}
	}

	// Metrics are labelled by host rather than address, so retain the first
	// successful result here. A differing later address sets probe_match to 0
	// and is named in the log below.
	metrics.CertificateProbeNotAfter.WithLabelValues(host).Set(float64(first.NotAfter.Unix()))
	if first.Trusted {
		metrics.CertificateProbeTrusted.WithLabelValues(host).Set(1)
	} else {
		metrics.CertificateProbeTrusted.WithLabelValues(host).Set(0)
	}

	if len(problems) > 0 {
		metrics.CertificateProbeMatch.WithLabelValues(host).Set(0)
		r.transition(host, stateMismatch, "the certificate being served is not the one that was deployed",
			"problems", problems, "servedNotAfter", first.NotAfter,
			"sans", first.SANs, "issuer", first.Issuer, "remoteAddr", first.RemoteAddr)
		return Verdict{Problems: problems}
	}

	if len(attemptErrs) > 0 {
		msg := "some resolved addresses could not be probed: " + strings.Join(attemptErrs, " | ")
		r.transition(host, stateUnreachable,
			"some addresses could not be reached to check which certificate they serve", "err", msg)
		return Verdict{Problems: []string{msg}}
	}

	metrics.CertificateProbeMatch.WithLabelValues(host).Set(1)
	r.transition(host, stateOK, "the certificate being served is the one that was deployed",
		"notAfter", first.NotAfter, "daysLeft", first.DaysLeft(e.Now), "issuer", first.Issuer,
		"trusted", first.Trusted, "handshakeMs", first.HandshakeMS)
	return Verdict{OK: true}
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
