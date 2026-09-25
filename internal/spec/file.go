package spec

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/susunola/wecert/internal/config"
)

// File reads the desired-state document written by the onboarding component.
type File struct {
	path string
	log  *slog.Logger

	mu   sync.Mutex
	last *Document
}

// NewFile constructs the document source.
//
// **The first read must succeed**; otherwise it returns an error and the process
// refuses to start. Allowing "starts up but has no desired state" would let
// wecert quietly renew nothing until every certificate expires -- the worst kind
// of failure: silent, with all the consequences in production.
func NewFile(path string, log *slog.Logger) (*File, error) {
	if log == nil {
		log = slog.Default()
	}
	f := &File{path: path, log: log}
	doc, err := LoadDocument(path)
	if err != nil {
		return nil, err
	}
	f.last = doc
	return f, nil
}

// Kind implements Named.
func (f *File) Kind() string { return "document" }

// Desired implements Provider.
func (f *File) Desired(ctx context.Context) ([]config.Certificate, error) {
	res, err := f.DesiredWithReasons(ctx)
	if err != nil {
		return nil, err
	}
	return res.Certificates, nil
}

// DesiredWithReasons reads the document; if it cannot, it freezes on the last
// usable revision.
func (f *File) DesiredWithReasons(context.Context) (*Result, error) {
	doc, err := LoadDocument(f.path)
	if err == nil {
		f.mu.Lock()
		f.last = doc
		f.mu.Unlock()
		return documentResult(doc, false, ""), nil
	}

	f.mu.Lock()
	last := f.last
	f.mu.Unlock()

	if last == nil {
		return nil, fmt.Errorf("no usable desired state: %w", err)
	}

	// A source read failure is not an empty desired state.
	//
	// onboarding already has the same three-state semantics, but the contract
	// boundary cannot assume upstream got it right: a truncated, deleted or
	// chmod-ed document reaches this branch too, and acting on it strips SANs in
	// bulk, so TLS handshakes in production fail immediately.
	f.log.Warn("desired-state document is unreadable; freezing on the last good revision",
		"path", f.path, "revision", last.Revision, "generatedAt", last.GeneratedAt, "err", err)
	return documentResult(last, true, err.Error()), nil
}

func documentResult(doc *Document, frozen bool, reason string) *Result {
	return &Result{
		Certificates: doc.Certificates,
		Revision:     doc.Revision,
		GeneratedAt:  doc.GeneratedAt,
		Frozen:       frozen,
		FreezeReason: reason,
		Decisions: decisionsFor(doc.Certificates,
			"declared in the desired-state document ("+doc.Revision+")"),
	}
}
