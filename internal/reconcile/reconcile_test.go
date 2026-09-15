package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/metrics"
	"github.com/atom/wecert/internal/state"
)

// fakeManager 用来把收敛循环的编排逻辑单独测出来。
type fakeManager struct {
	calls    []string
	failWith map[string]error

	reaped int

	// onReconcile 在每次 Reconcile 时回调，便于在测试里做取消等操作。
	onReconcile func(name string)

	reapBefore chan struct{}
}

func (f *fakeManager) Reconcile(_ context.Context, c *config.Certificate) error {
	f.calls = append(f.calls, c.Name)
	if f.onReconcile != nil {
		f.onReconcile(c.Name)
	}
	return f.failWith[c.Name]
}

func (f *fakeManager) ReapRetired(_ context.Context) {
	if f.reapBefore != nil {
		<-f.reapBefore
	}
	f.reaped++
}

func newTestReconciler(t *testing.T, names []string, mgr CertManager) (*Reconciler, *state.Store) {
	t.Helper()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开状态库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	for _, n := range names {
		cfg.Certificates = append(cfg.Certificates, config.Certificate{Name: n})
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, store, mgr, log), store
}

// 这是 RunOnce 存在的全部理由：一张证书炸了不能把其它证书的续期一起拖住。
// 自动化里最危险的就是这种耦合 —— 一个配错的域名能让全站证书都不续。
func TestRunOnceContinuesAfterOneCertFails(t *testing.T) {
	mgr := &fakeManager{failWith: map[string]error{
		"b": errors.New("boom"),
	}}
	r, _ := newTestReconciler(t, []string{"a", "b", "c"}, mgr)

	r.RunOnce(context.Background())

	if len(mgr.calls) != 3 {
		t.Fatalf("三张证书都应被处理，实际只处理了 %v", mgr.calls)
	}
	want := []string{"a", "b", "c"}
	for i := range want {
		if mgr.calls[i] != want[i] {
			t.Errorf("处理顺序应为 %v，实际 %v", want, mgr.calls)
			break
		}
	}
}

func TestRunOnceReapsRetiredCerts(t *testing.T) {
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"only"}, mgr)

	r.RunOnce(context.Background())

	if mgr.reaped != 1 {
		t.Errorf("每轮都应回收一次退役证书，实际 %d 次", mgr.reaped)
	}
}

// 收到停止信号后不该再往下处理后续证书。
func TestRunOnceStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := &fakeManager{onReconcile: func(string) { cancel() }}
	r, _ := newTestReconciler(t, []string{"a", "b", "c"}, mgr)

	r.RunOnce(ctx)

	if len(mgr.calls) != 1 {
		t.Errorf("取消后应停在第一张，实际处理了 %v", mgr.calls)
	}
}

func TestPublishExportsNotAfter(t *testing.T) {
	mgr := &fakeManager{}
	r, store := newTestReconciler(t, []string{"pub-notafter"}, mgr)

	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutCert(&state.CertState{Name: "pub-notafter", NotAfter: notAfter}); err != nil {
		t.Fatal(err)
	}

	r.RunOnce(context.Background())

	got := testutil.ToFloat64(metrics.CertNotAfter.WithLabelValues("pub-notafter"))
	if int64(got) != notAfter.Unix() {
		t.Errorf("CertNotAfter = %d，期望 %d", int64(got), notAfter.Unix())
	}
}

// 首次上传后还要人工绑一次，在那之前"已部署"不能亮绿灯 ——
// 否则到期告警会以为一切正常。
func TestPublishDeployedRequiresConfirmation(t *testing.T) {
	const name = "pub-deployed"
	mgr := &fakeManager{}
	r, store := newTestReconciler(t, []string{name}, mgr)

	// 只上传了，还没确认绑定
	if err := store.PutCert(&state.CertState{
		Name: name, NotAfter: time.Now().Add(24 * time.Hour), DeployedCertID: "ap-uploaded",
	}); err != nil {
		t.Fatal(err)
	}
	r.RunOnce(context.Background())
	if got := testutil.ToFloat64(metrics.CertDeployed.WithLabelValues(name)); got != 0 {
		t.Errorf("未确认绑定时 CertDeployed 应为 0，实际 %v", got)
	}

	// 确认之后才该亮绿灯
	if err := store.PutCert(&state.CertState{
		Name: name, NotAfter: time.Now().Add(24 * time.Hour),
		DeployedCertID: "ap-uploaded", DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}
	r.RunOnce(context.Background())
	if got := testutil.ToFloat64(metrics.CertDeployed.WithLabelValues(name)); got != 1 {
		t.Errorf("确认绑定后 CertDeployed 应为 1，实际 %v", got)
	}
}

// 状态库里没有这张证书时不应 panic，也不该写出任何指标。
func TestPublishMissingCertIsNoop(t *testing.T) {
	const name = "pub-missing"
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{name}, mgr)

	r.RunOnce(context.Background())

	// 关键是不能 panic。指标此时应为默认 0。
	if got := testutil.ToFloat64(metrics.CertConsecutiveFailures.WithLabelValues(name)); got != 0 {
		t.Errorf("缺失证书的失败计数应为 0，实际 %v", got)
	}
}

func TestRunOnceCountsFailuresInMetrics(t *testing.T) {
	const name = "pub-failcount"
	mgr := &fakeManager{failWith: map[string]error{name: errors.New("boom")}}
	r, store := newTestReconciler(t, []string{name}, mgr)

	if err := store.PutCert(&state.CertState{Name: name, ConsecutiveFailures: 3}); err != nil {
		t.Fatal(err)
	}

	r.RunOnce(context.Background())

	if got := testutil.ToFloat64(metrics.CertConsecutiveFailures.WithLabelValues(name)); got != 3 {
		t.Errorf("连续失败次数应透出为 3，实际 %v", got)
	}
}
