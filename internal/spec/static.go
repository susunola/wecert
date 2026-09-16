package spec

import (
	"context"

	"github.com/susunola/wecert/internal/config"
)

// Static 是配置里的 certificates 区块。
//
// 它同样实现 Provider，好让收敛循环完全不关心期望状态从哪来 ——
// 这正是从 static 切到 enforce 不需要动收敛代码的原因。
type Static struct {
	certs []config.Certificate
}

// NewStatic 包装一份静态证书列表。
func NewStatic(certs []config.Certificate) *Static {
	cp := make([]config.Certificate, len(certs))
	copy(cp, certs)
	return &Static{certs: cp}
}

// Kind 实现 Named。
func (s *Static) Kind() string { return config.ModeStatic }

// Desired 实现 Provider。
func (s *Static) Desired(context.Context) ([]config.Certificate, error) {
	return s.certs, nil
}

// DesiredWithReasons 实现 ReportingProvider。
func (s *Static) DesiredWithReasons(context.Context) (*Result, error) {
	return &Result{
		Certificates: s.certs,
		Revision:     Revision(s.certs),
		Decisions: decisionsFor(s.certs,
			"declared in the configuration file (desiredState.mode=static)"),
	}, nil
}
