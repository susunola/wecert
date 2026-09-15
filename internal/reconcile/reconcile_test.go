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

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/state"
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
	return New(cfg, store, mgr, nil, log), store
}

// fakeNotifier 记录收到的通知，用来验证"结果事件确实发出去了"。
type fakeNotifier struct {
	events chan struct {
		cert string
		err  error
	}
}

func newFakeNotifier() *fakeNotifier {
	return &fakeNotifier{events: make(chan struct {
		cert string
		err  error
	}, 16)}
}

func (f *fakeNotifier) Renewal(_ context.Context, certName string, err error) {
	f.events <- struct {
		cert string
		err  error
	}{certName, err}
}

func TestNotifierReceivesRenewalResult(t *testing.T) {
	const name = "notify-ok"
	mgr := &fakeManager{}
	notifier := newFakeNotifier()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	r := New(cfg, store, mgr, notifier, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.RunOnce(context.Background())

	select {
	case ev := <-notifier.events:
		if ev.cert != name || ev.err != nil {
			t.Errorf("通知内容不对: cert=%q err=%v", ev.cert, ev.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("没有收到续期通知")
	}
}

func TestNotifierReceivesFailure(t *testing.T) {
	const name = "notify-fail"
	mgr := &fakeManager{failWith: map[string]error{name: errors.New("boom")}}
	notifier := newFakeNotifier()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	r := New(cfg, store, mgr, notifier, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.RunOnce(context.Background())

	select {
	case ev := <-notifier.events:
		if ev.err == nil {
			t.Error("失败也应当通知，且带上错误")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("没有收到失败通知")
	}
}

// ── 事件触发相关 ────────────────────────────────────────────────────────────

func TestRunCertUnknownName(t *testing.T) {
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"a"}, mgr)

	if err := r.RunCert(context.Background(), "nope"); err == nil {
		t.Fatal("未知证书名应当报错")
	}
	if len(mgr.calls) != 0 {
		t.Errorf("未知名字不该触发任何处理，实际 %v", mgr.calls)
	}
}

func TestRunCertProcessesOnlyThatCert(t *testing.T) {
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"a", "b", "c"}, mgr)

	if err := r.RunCert(context.Background(), "b"); err != nil {
		t.Fatalf("RunCert 失败: %v", err)
	}
	if len(mgr.calls) != 1 || mgr.calls[0] != "b" {
		t.Errorf("只应处理 b，实际 %v", mgr.calls)
	}
}

// 这条是整个并发闸门存在的理由：定时器和事件触发的收敛同时落到同一张证书上，
// 两边各下一单就会撞 "5 certificates per exact set of identifiers / 7 days"。
func TestConcurrentRunCertIsRejected(t *testing.T) {
	const name = "busy"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	mgr := &fakeManager{onReconcile: func(string) {
		entered <- struct{}{}
		<-release
	}}
	r, _ := newTestReconciler(t, []string{name}, mgr)

	go func() { _ = r.RunCert(context.Background(), name) }()
	<-entered // 等第一轮真的进去

	err := r.RunCert(context.Background(), name)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("并发处理同一张证书应返回 ErrAlreadyRunning，实际 %v", err)
	}

	close(release)
}

// StartCert 必须**同步**占位：否则调用方拿到"已受理"之后，
// 同一张证书可能已经被别处又启动了一轮。
func TestStartCertReservesSlotSynchronously(t *testing.T) {
	const name = "async"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	done := make(chan struct{})

	mgr := &fakeManager{onReconcile: func(string) {
		entered <- struct{}{}
		<-release
		close(done)
	}}
	r, _ := newTestReconciler(t, []string{name}, mgr)

	if err := r.StartCert(context.Background(), name); err != nil {
		t.Fatalf("StartCert 失败: %v", err)
	}
	// 立刻再启动一次，必须被拒 —— 此时后台那轮还没跑完。
	if err := r.StartCert(context.Background(), name); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("应立刻报告已在处理中，实际 %v", err)
	}

	<-entered
	close(release)
	<-done
}

func TestStartAllSkipsBusyCerts(t *testing.T) {
	const busy = "busy-one"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	mgr := &fakeManager{onReconcile: func(n string) {
		if n == busy {
			entered <- struct{}{}
			<-release
		}
	}}
	r, _ := newTestReconciler(t, []string{busy, "other"}, mgr)

	if err := r.StartCert(context.Background(), busy); err != nil {
		t.Fatal(err)
	}
	<-entered

	skipped := r.StartAll(context.Background())
	found := false
	for _, n := range skipped {
		if n == busy {
			found = true
		}
	}
	if !found {
		t.Errorf("StartAll 应报告 %q 被跳过，实际 %v", busy, skipped)
	}
	close(release)
}

func TestRunAllSkipsBusyCerts(t *testing.T) {
	const busy = "busy-runall"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	mgr := &fakeManager{onReconcile: func(n string) {
		if n == busy {
			entered <- struct{}{}
			<-release
		}
	}}
	r, _ := newTestReconciler(t, []string{busy, "free"}, mgr)

	go func() { _ = r.RunCert(context.Background(), busy) }()
	<-entered

	skipped := r.RunAll(context.Background())
	if len(skipped) != 1 || skipped[0] != busy {
		t.Errorf("RunAll 应跳过 %q，实际 %v", busy, skipped)
	}
	close(release)
}

func TestCertNamesPreservesConfigOrder(t *testing.T) {
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"z", "a", "m"}, mgr)

	got := r.CertNames()
	want := []string{"z", "a", "m"}
	if len(got) != len(want) {
		t.Fatalf("CertNames = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CertNames 顺序应与配置一致: %v vs %v", got, want)
		}
	}
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
