package spec

import (
	"context"

	"github.com/susunola/wecert/internal/config"
)

// Static is the certificates block from the configuration file.
//
// It implements Provider too, so the convergence loop does not care where the
// desired state comes from -- which is exactly why switching from static to
// enforce needs no change to convergence code.
type Static struct {
	certs []config.Certificate
}

// NewStatic wraps a static certificate list.
func NewStatic(certs []config.Certificate) *Static {
	cp := make([]config.Certificate, len(certs))
	copy(cp, certs)
	return &Static{certs: cp}
}

// Kind implements Named.
func (s *Static) Kind() string { return config.ModeStatic }

// Desired implements Provider.
func (s *Static) Desired(context.Context) ([]config.Certificate, error) {
	return s.certs, nil
}

// DesiredWithReasons implements ReportingProvider.
func (s *Static) DesiredWithReasons(context.Context) (*Result, error) {
	return &Result{
		Certificates: s.certs,
		Revision:     Revision(s.certs),
		Decisions: decisionsFor(s.certs,
			"declared in the configuration file (desiredState.mode=static)"),
	}, nil
}
