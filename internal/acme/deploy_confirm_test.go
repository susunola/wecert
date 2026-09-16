package acme

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// fakeDeployer 只实现 Bindings —— 本文件测的是"确认绑定"这一步。
type fakeDeployer struct {
	bindings int
	bindErr  error
	calls    int
}

func (f *fakeDeployer) Deploy(_ context.Context, _, oldID string, _, _ []byte) (string, error) {
	return oldID, nil
}
func (f *fakeDeployer) Delete(_ context.Context, _ string) error { return nil }
func (f *fakeDeployer) Bindings(_ context.Context, _ string) (int, error) {
	f.calls++
	return f.bindings, f.bindErr
}

// newConfirmHarness 造出"证书已签发并上传、但尚未确认绑定"的状态。
//
// 刻意让证书距离续期窗口还很远、且不带 ARI —— 这样 Reconcile 走到
// 确认这一步之后不会再碰 ACME 客户端，用例可以纯单测。
func newConfirmHarness(
	t *testing.T, dep deploy.Deployer, mutate func(*state.CertState, *config.Certificate),
) (*Manager, *state.Store, *config.Certificate) {
	t.Helper()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, dep, log)

	cert := &config.Certificate{
		Name:    "confirm-test",
		Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic,
		Deploy:  config.Deploy{Enabled: true},
	}

	st := &state.CertState{
		Name:     cert.Name,
		NotAfter: time.Now().Add(80 * 24 * time.Hour),
		CertURL:  "https://acme.example/cert/1",
		CertPEM:  []byte("x"),
		KeyPEM:   []byte("x"),
		// 首次签发只上传，所以有 CertId 但 DeployConfirmed 为 false。
		DeployedCertID:  "ap-uploaded",
		DeployConfirmed: false,
	}
	if mutate != nil {
		mutate(st, cert)
	}
	if err := store.PutCert(st); err != nil {
		t.Fatal(err)
	}

	return m, store, cert
}

// 这是本次修复的核心：人工在 CLB 控制台绑好之后，
// 收敛必须能自己发现并置位，而不是干等到下次续期（最长 90 天）。
func TestReconcileConfirmsBindingOnceBound(t *testing.T) {
	dep := &fakeDeployer{bindings: 2}
	m, store, cert := newConfirmHarness(t, dep, nil)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile 不该报错: %v", err)
	}

	if dep.calls != 1 {
		t.Fatalf("应当查询一次绑定关系，实际 %d 次", dep.calls)
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !got.DeployConfirmed {
		t.Error("查到绑定了 2 个资源，DeployConfirmed 应当被置位")
	}
}

// 查不到绑定是"等人去绑"的正常状态，不是错误 ——
// 不能记失败、更不能进指数退避，否则人工绑好之前会被退避挡住。
func TestReconcileUnboundStaysUnconfirmedWithoutFailure(t *testing.T) {
	dep := &fakeDeployer{bindings: 0}
	m, store, cert := newConfirmHarness(t, dep, nil)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("没绑上不该报错: %v", err)
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployConfirmed {
		t.Error("没有任何绑定时不该置位")
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("这不算失败，ConsecutiveFailures 应为 0，实际 %d", got.ConsecutiveFailures)
	}
	if !got.NextAttemptAt.IsZero() {
		t.Errorf("不该进入退避，NextAttemptAt 应为零值，实际 %s", got.NextAttemptAt)
	}
}

// 查询故障不能拖住续期主线：Reconcile 仍然成功返回。
func TestReconcileBindingQueryErrorDoesNotFailThePass(t *testing.T) {
	dep := &fakeDeployer{bindErr: errors.New("API 抖了一下")}
	m, store, cert := newConfirmHarness(t, dep, nil)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("查询失败不该让整轮失败: %v", err)
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployConfirmed {
		t.Error("查询没成功就不该置位")
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("确认动作的故障不该记成续期失败，实际 %d", got.ConsecutiveFailures)
	}
}

// 已经确认过的证书不该每次收敛都去查一遍 —— 那是白花的 API 调用，
// 而这个状态一旦为真就不会再变回假。
func TestReconcileSkipsQueryWhenAlreadyConfirmed(t *testing.T) {
	dep := &fakeDeployer{bindings: 3}
	m, _, cert := newConfirmHarness(t, dep, func(st *state.CertState, _ *config.Certificate) {
		st.DeployConfirmed = true
	})

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile 不该报错: %v", err)
	}
	if dep.calls != 0 {
		t.Errorf("已确认的证书不该再查绑定，实际查了 %d 次", dep.calls)
	}
}

// 没开 deploy 的证书根本不会上传，也就无所谓确认。
func TestReconcileSkipsQueryWhenDeployDisabled(t *testing.T) {
	dep := &fakeDeployer{bindings: 1}
	m, _, cert := newConfirmHarness(t, dep, func(st *state.CertState, c *config.Certificate) {
		c.Deploy.Enabled = false
		st.DeployedCertID = ""
	})

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile 不该报错: %v", err)
	}
	if dep.calls != 0 {
		t.Errorf("未开启部署时不该查绑定，实际查了 %d 次", dep.calls)
	}
}

// 还没有 CertId 说明连上传都还没发生，没有可查的对象。
func TestReconcileSkipsQueryWhenNoCertID(t *testing.T) {
	dep := &fakeDeployer{bindings: 1}
	m, _, cert := newConfirmHarness(t, dep, func(st *state.CertState, _ *config.Certificate) {
		st.DeployedCertID = ""
	})

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile 不该报错: %v", err)
	}
	if dep.calls != 0 {
		t.Errorf("没有 CertId 时不该查绑定，实际查了 %d 次", dep.calls)
	}
}

// 确认之后必须落盘：重启不能让这个结论丢掉，
// 否则每次重启都会退回"未部署"，而指标正是读它。
func TestConfirmedBindingIsPersisted(t *testing.T) {
	dep := &fakeDeployer{bindings: 1}
	m, _, cert := newConfirmHarness(t, dep, nil)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	// 再跑一轮：此时应已确认，不该再查第二次。
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if dep.calls != 1 {
		t.Errorf("置位后应当落盘，第二轮不该再查；实际共查 %d 次", dep.calls)
	}
}

// Noop 部署器（未开启云端部署时用）应恒为 0，且不报错。
func TestNoopDeployerReportsNoBindings(t *testing.T) {
	n, err := deploy.Noop{}.Bindings(context.Background(), "ap-whatever")
	if err != nil {
		t.Fatalf("Noop.Bindings 不该报错: %v", err)
	}
	if n != 0 {
		t.Errorf("Noop.Bindings 应恒为 0，得到 %d", n)
	}
}
