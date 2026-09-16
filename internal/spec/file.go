package spec

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/susunola/wecert/internal/config"
)

// File 读取 onboarding 组件写下的期望状态文档。
type File struct {
	path string
	log  *slog.Logger

	mu   sync.Mutex
	last *Document
}

// NewFile 构造文档来源。
//
// **首次读取必须成功**，否则直接返回错误让进程起不来。
// 如果允许"起得来但没有期望状态"，wecert 会安静地什么都不续期，
// 直到所有证书过期才被发现 —— 那是最糟的一种失败：无声，且后果全在线上。
func NewFile(path string, log *slog.Logger) (*File, error) {
	f := &File{path: path, log: log}
	doc, err := LoadDocument(path)
	if err != nil {
		return nil, err
	}
	f.last = doc
	return f, nil
}

// Kind 实现 Named。
func (f *File) Kind() string { return "document" }

// Desired 实现 Provider。
func (f *File) Desired(ctx context.Context) ([]config.Certificate, error) {
	res, err := f.DesiredWithReasons(ctx)
	if err != nil {
		return nil, err
	}
	return res.Certificates, nil
}

// DesiredWithReasons 读文档；读不到就冻结在最后一版可用状态上。
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

	// 读来源失败 ≠ 期望为空。
	//
	// onboarding 那边已经有同样的三态语义，但契约边界不能假设上游一定做对了：
	// 一份被截断、被误删、或权限被改掉的文档同样会走到这个分支，
	// 而"照它执行"的后果是批量摘除 SAN，线上立刻握手失败。
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
