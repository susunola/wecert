// Package spec 定义期望状态的契约。
//
// 契约的核心是一条纪律：**这一层永不推断**。
// wecert 只读一份已经写下来的、可 diff 的期望状态，然后做收敛。
// 推断属于 onboarding 组件 —— 它随时可以换、可以试错、可以丢，
// 而证书生命周期必须稳。
//
// 这么切分的理由是失败模式：来源故障只会让期望状态**不更新**（安全，
// 保持现状），而如果 wecert 自己去枚举来源，一次接口抖动就可能被读成
// "这些域名都没了"，接着把域名从证书里摘掉，线上立刻握手失败。
package spec

import (
	"context"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// Decision 记录单个 hostname 的去留理由。
//
// 必须能回答"我加了域名怎么没签" —— 这是这类系统上线后的头号问题。
// 没有它，排障只能靠翻日志，而日志会被轮转掉。
type Decision struct {
	Hostname string `json:"hostname" yaml:"hostname"`

	// Included 表示这个名字最终进了某张证书的 SAN。
	Included bool `json:"included" yaml:"included"`

	// Reason 是一句人话的解释，比如
	// "covered by declared wildcard *.example.com" / "no CLB rule" /
	// "source unknown, freezing".
	Reason string `json:"reason" yaml:"reason"`

	// Certificate 是它最终归入的证书名（如果进了）。
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`

	Details map[string]any `json:"details,omitempty" yaml:"details,omitempty"`
}

// Result 是一次期望状态求值的完整结果。
type Result struct {
	Certificates []config.Certificate `json:"certificates" yaml:"certificates"`
	Decisions    []Decision           `json:"decisions,omitempty" yaml:"decisions,omitempty"`

	// Revision 是期望状态内容的指纹，用来回答"这轮和上轮是不是同一份"。
	// 它只覆盖 certificates，不含时间戳 —— 否则每跑一次都会变。
	Revision string `json:"revision,omitempty" yaml:"revision,omitempty"`

	// GeneratedAt 是文档被写下的时刻，仅文档来源有。零值表示来源不适用。
	GeneratedAt time.Time `json:"generatedAt,omitempty" yaml:"generatedAt,omitempty"`

	// Frozen 表示这次读来源失败过，返回的是上一版可用状态。
	//
	// 这不是错误，而是刻意设计的行为：来源读不到时，正确答案是**保持现状**，
	// 绝不是"期望为空"。后者会让 wecert 把域名从证书里摘掉。
	// 冻结比执行安全。
	Frozen bool `json:"frozen,omitempty" yaml:"frozen,omitempty"`

	// FreezeReason 说明为什么冻结。
	FreezeReason string `json:"freezeReason,omitempty" yaml:"freezeReason,omitempty"`

	// Shadow 只在 observe 模式下有值：它是"如果按影子来源来会怎样"的对比。
	// 为 nil 表示没有影子来源（static / enforce 模式）。
	Shadow *ShadowReport `json:"shadow,omitempty" yaml:"shadow,omitempty"`
}

// Provider 是期望状态来源。
//
// 实现必须满足两条性质：
//  1. 幂等：同样的输入永远给出同样的输出，顺序也一致
//  2. Name 稳定：证书名只由分组键派生，绝不随域名集合变化
type Provider interface {
	Desired(ctx context.Context) ([]config.Certificate, error)
}

// ReportingProvider 是推荐实现：除了期望状态本身，还给出每个 hostname 的理由。
type ReportingProvider interface {
	Provider

	// DesiredWithReasons 是推荐的入口；Desired 只是它的简化形式。
	DesiredWithReasons(ctx context.Context) (*Result, error)
}

// Named 让来源能报出自己是谁，用于日志和诊断端点。
type Named interface {
	Kind() string
}

// Desired 求值一个 provider，优先走带理由的路径。
func Desired(ctx context.Context, p Provider) (*Result, error) {
	if rp, ok := p.(ReportingProvider); ok {
		return rp.DesiredWithReasons(ctx)
	}

	certs, err := p.Desired(ctx)
	if err != nil {
		return nil, err
	}
	return &Result{Certificates: certs, Revision: Revision(certs)}, nil
}

// KindOf 返回来源名字，未实现 Named 时返回 "unknown"。
func KindOf(p Provider) string {
	if n, ok := p.(Named); ok {
		return n.Kind()
	}
	return "unknown"
}

// CertNames 返回结果里所有证书的名字，顺序与结果一致。
func (r *Result) CertNames() []string {
	names := make([]string, 0, len(r.Certificates))
	for i := range r.Certificates {
		names = append(names, r.Certificates[i].Name)
	}
	return names
}

// Find 按名字找一张证书。
func (r *Result) Find(name string) *config.Certificate {
	for i := range r.Certificates {
		if r.Certificates[i].Name == name {
			return &r.Certificates[i]
		}
	}
	return nil
}

// decisionsFor 给一份静态期望状态补上"为什么它在这里"。
func decisionsFor(certs []config.Certificate, reason string) []Decision {
	var out []Decision
	for i := range certs {
		c := &certs[i]
		for _, d := range c.Domains {
			out = append(out, Decision{
				Hostname:    d,
				Included:    true,
				Reason:      reason,
				Certificate: c.Name,
			})
		}
	}
	return out
}
