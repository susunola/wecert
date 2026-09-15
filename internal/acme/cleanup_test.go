package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// ---------- 测试替身 ----------

// fakeSolver 记录每一次 TXT 写入与清理，用于断言"清理真的发生了"。
type fakeSolver struct {
	mu        sync.Mutex
	presented []string // "identifier|token"
	cleaned   []string // "identifier|keyAuth"
	cleanErr  error
}

func (f *fakeSolver) Present(_ context.Context, domain, token, keyAuth string) (DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.presented = append(f.presented, domain+"|"+token)
	return DNSRecord{FQDN: "_acme-challenge." + domain + ".", Value: "txt-" + token}, nil
}

func (f *fakeSolver) WaitAll(context.Context, []DNSRecord) error { return nil }

func (f *fakeSolver) CleanUp(_ context.Context, domain, token, keyAuth string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cleanErr != nil {
		return f.cleanErr
	}
	f.cleaned = append(f.cleaned, domain+"|"+keyAuth)
	return nil
}

func (f *fakeSolver) cleanCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cleaned)
}

// fakeKeyAuth 模拟 api.Core 的 key authorization 计算。
type fakeKeyAuth struct{ err error }

func (f fakeKeyAuth) GetKeyAuthorization(token string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "keyauth(" + token + ")", nil
}

// ---------- 脚手架 ----------

func newTestManager(t *testing.T, solver challengeSolver, ka keyAuthProvider) (*Manager, *state.Store) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开状态库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// core 传 nil：这些用例走的路径（清理残留 TXT）不碰 ACME 客户端。
	return newManager(store, nil, solver, ka, deploy.Noop{}, log), store
}

// seedOrderWithAuthzs 造出"订单 + 已写入 DNS 的授权"这个状态。
func seedOrderWithAuthzs(t *testing.T, store *state.Store, certName string, authzs []*state.Authorization) {
	t.Helper()

	if err := store.PutOrder(&state.Order{
		CertName:    certName,
		OrderURL:    "https://acme.example/order/1",
		FinalizeURL: "https://acme.example/finalize/1",
		Status:      "ready",
		Identifiers: "a.example.com,b.example.com",
	}); err != nil {
		t.Fatalf("PutOrder: %v", err)
	}
	for _, a := range authzs {
		if err := store.PutAuthorization(a); err != nil {
			t.Fatalf("PutAuthorization: %v", err)
		}
	}
}

// ---------- 泄漏回归：这是本文件的核心 ----------

// 最要命的泄漏路径：订单已经 ready，advance 直接走 finalize → download，
// solveChallenges（唯一会调用 cleanup 的地方）被整个跳过。
// 收尾时 discardOrder 会删掉授权行 —— 如果它不先清 DNS，
// 那些 _acme-challenge 就永远回收不了了。
func TestDiscardOrderClearsTXTBeforeDeletingRows(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// wildcard 和 apex 共用同一个 TXT 名字，两条授权各自持有自己的值。
	seedOrderWithAuthzs(t, store, "c", []*state.Authorization{
		{CertName: "c", AuthzURL: "authz-apex", Identifier: "example.com",
			ChallengeToken: "tok-apex", TxtName: "_acme-challenge.example.com.",
			TxtValue: "val-apex", Presented: true, ChallengeSent: true},
		{CertName: "c", AuthzURL: "authz-wild", Identifier: "*.example.com",
			ChallengeToken: "tok-wild", TxtName: "_acme-challenge.example.com.",
			TxtValue: "val-wild", Presented: true, ChallengeSent: true},
	})

	if err := m.discardOrder(context.Background(), "c"); err != nil {
		t.Fatalf("discardOrder: %v", err)
	}

	if got := solver.cleanCount(); got != 2 {
		t.Errorf("丢弃订单前应清掉 2 条 TXT，实际清了 %d 条 —— 这就是僵尸记录的来源", got)
	}

	// 清理用的必须是各自的 token 换算出的 keyAuth，不能张冠李戴。
	want := map[string]bool{
		"example.com|keyauth(tok-apex)":   true,
		"*.example.com|keyauth(tok-wild)": true,
	}
	for _, c := range solver.cleaned {
		if !want[c] {
			t.Errorf("意外的一次清理: %q", c)
		}
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("以下清理没有发生: %v", want)
	}

	// 订单与授权行都要清干净，下一轮才能按新域名重建。
	if o, err := store.GetOrder("c"); err != nil || o != nil {
		t.Errorf("订单未被删除: %+v, err=%v", o, err)
	}
	if as, err := store.ListAuthorizations("c"); err != nil || len(as) != 0 {
		t.Errorf("授权行未被删除: %d 条, err=%v", len(as), err)
	}
}

// 自愈：状态库里留着"已写入 DNS"的授权，但没有对应的订单
// （上一次收尾只成功了一半，或进程被 kill）。
// Reconcile 走到这一步时应当把它们回收掉。
func TestCleanupOrphanTXTReclaimsLeftovers(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// 只有授权行，没有订单行 —— 这正是"孤儿"的定义。
	for _, a := range []*state.Authorization{
		{CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
			ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.",
			TxtValue: "v1", Presented: true},
		{CertName: "c", AuthzURL: "authz-2", Identifier: "b.example.com",
			ChallengeToken: "tok-2", TxtName: "_acme-challenge.b.example.com.",
			TxtValue: "v2", Presented: true},
	} {
		if err := store.PutAuthorization(a); err != nil {
			t.Fatal(err)
		}
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}

	if got := solver.cleanCount(); got != 2 {
		t.Errorf("应回收 2 条残留 TXT，实际 %d 条", got)
	}
	if as, err := store.ListAuthorizations("c"); err != nil || len(as) != 0 {
		t.Errorf("回收后授权行应清空，得到 %d 条, err=%v", len(as), err)
	}
}

// 没写进 DNS 的授权行不该触发任何 DNS 调用，直接删掉即可。
func TestCleanupOrphanTXTDoesNotTouchDNSForUnpresented(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
		Status: "pending", Presented: false,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("未写入 DNS 的授权不应触发清理，实际调用 %d 次", got)
	}
	if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
		t.Errorf("未写入 DNS 的授权行应当被删掉，仍有 %d 条", len(as))
	}
}

// 清理失败不能阻止丢弃订单 —— 否则会卡在一张签不出结果的订单上，
// 那比多留一条 TXT 严重得多。行也要删掉，避免无限重试。
func TestDiscardOrderProceedsEvenIfCleanupFails(t *testing.T) {
	solver := &fakeSolver{cleanErr: errors.New("DNSPod 挂了")}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	seedOrderWithAuthzs(t, store, "c", []*state.Authorization{
		{CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
			ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.",
			Presented: true},
	})

	if err := m.discardOrder(context.Background(), "c"); err != nil {
		t.Fatalf("清理失败不应让 discardOrder 报错: %v", err)
	}
	if o, _ := store.GetOrder("c"); o != nil {
		t.Error("订单应当已被丢弃")
	}
}

// key authorization 算不出来时（例如账号状态异常），
// 不能把整轮处理拖挂，但也不能谎称清理成功。
func TestCleanupSkipsWhenKeyAuthFails(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{err: errors.New("无账号私钥")})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
		ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.", Presented: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("不应把错误抛出去: %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("keyAuth 失败时不该调用 CleanUp，实际 %d 次", got)
	}

	// 关键：Presented 必须保持 true，否则这条记录就彻底找不回来了。
	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 {
		t.Fatalf("清理未完成时不应删掉授权行，剩余 %d 条", len(as))
	}
	if !as[0].Presented {
		t.Error("Presented 必须保持 true，否则下次再也定位不到那条 TXT")
	}
}

// 缺 token 时连记录都定位不到。此时必须**保留授权行** ——
// 行里的 TxtName 是人工去 DNS 后台清理的唯一线索，删掉就彻底丢了。
func TestCleanupKeepsRowWhenTokenMissing(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
		ChallengeToken: "", TxtName: "_acme-challenge.a.example.com.", Presented: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupOrphanTXT(context.Background(), "c"); err != nil {
		t.Fatalf("cleanupOrphanTXT: %v", err)
	}
	if got := solver.cleanCount(); got != 0 {
		t.Errorf("缺 token 时不该调用 CleanUp，实际 %d 次", got)
	}

	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 {
		t.Fatalf("定位不到记录时必须保留授权行，剩余 %d 条", len(as))
	}
	if as[0].TxtName == "" {
		t.Error("保留的行必须仍带着 TxtName，否则人工也没法清理")
	}
}

// 成功路径的 cleanup 要把 Presented 落成 false，避免收尾时重复清理。
func TestCleanupMarksUnpresented(t *testing.T) {
	solver := &fakeSolver{}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	a := &state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "a.example.com",
		ChallengeToken: "tok-1", TxtName: "_acme-challenge.a.example.com.", Presented: true,
	}
	if err := store.PutAuthorization(a); err != nil {
		t.Fatal(err)
	}

	m.cleanup(context.Background(), "c", []*state.Authorization{a})

	if got := solver.cleanCount(); got != 1 {
		t.Fatalf("应清理 1 次，实际 %d 次", got)
	}
	as, err := store.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].Presented {
		t.Errorf("Presented 应被落成 false: %+v", as)
	}
}

// ---------- 域名变更：订单失效判定 ----------

// 配置里的域名变了之后，在飞订单的 identifier 集合就对不上了。
// 必须能识别出来，否则会一直推进一张 finalize 必然被拒的坏订单。
func TestOrderMatchesConfig(t *testing.T) {
	order := &state.Order{
		CertName:    "c",
		Identifiers: config.DomainKey([]string{"a.example.com", "b.example.com"}),
	}

	cases := []struct {
		name    string
		domains []string
		want    bool
	}{
		{"完全一致", []string{"a.example.com", "b.example.com"}, true},
		{"顺序不同仍算一致", []string{"b.example.com", "a.example.com"}, true},
		{"大小写不同仍算一致", []string{"A.example.com", "B.example.com"}, true},
		{"新增域名 → 不一致", []string{"a.example.com", "b.example.com", "c.example.com"}, false},
		{"删除域名 → 不一致", []string{"a.example.com"}, false},
		{"替换域名 → 不一致", []string{"a.example.com", "z.example.com"}, false},
	}

	for _, tc := range cases {
		cfg := &config.Certificate{Name: "c", Domains: tc.domains}
		if got := orderMatchesConfig(order, cfg); got != tc.want {
			t.Errorf("%s: orderMatchesConfig = %v，期望 %v（domains=%v）",
				tc.name, got, tc.want, tc.domains)
		}
	}
}

// 旧版本落盘的订单没有 identifiers 字段。此时必须保守处理 ——
// 宁可多推进一轮，也不能因为拿不到信息就贸然丢弃订单
// （重新下单要消耗 "5 certs per exact set of identifiers / 7 days"）。
func TestLegacyOrderWithoutIdentifiersIsNotDiscarded(t *testing.T) {
	order := &state.Order{CertName: "c", Identifiers: ""}
	cfg := &config.Certificate{Name: "c", Domains: []string{"whatever.example.com"}}

	if !orderMatchesConfig(order, cfg) {
		t.Error("identifiers 为空的旧订单不应被判定为需要丢弃")
	}
}

// ---------- 域名漂移检测 ----------

func leafWith(names ...string) *x509.Certificate {
	return &x509.Certificate{DNSNames: names}
}

func TestCoverageDrift(t *testing.T) {
	cases := []struct {
		name    string
		leaf    []string
		want    []string
		drifted bool
	}{
		{"完全一致", []string{"a.com", "b.com"}, []string{"a.com", "b.com"}, false},
		{"顺序无关", []string{"b.com", "a.com"}, []string{"a.com", "b.com"}, false},
		{"大小写无关", []string{"A.COM"}, []string{"a.com"}, false},
		{"配置新增域名 → 漂移", []string{"a.com"}, []string{"a.com", "b.com"}, true},
		{"配置删除域名 → 漂移", []string{"a.com", "b.com"}, []string{"a.com"}, true},
		{"整体替换 → 漂移", []string{"old.com"}, []string{"new.com"}, true},
		{"通配符与 apex 同时存在", []string{"a.com", "*.a.com"}, []string{"a.com", "*.a.com"}, false},
	}

	for _, tc := range cases {
		drifted, detail := CoverageDrift(leafWith(tc.leaf...), tc.want)
		if drifted != tc.drifted {
			t.Errorf("%s: drifted = %v，期望 %v (detail=%q)",
				tc.name, drifted, tc.drifted, detail)
		}
		if drifted && detail == "" {
			t.Errorf("%s: 判定为漂移时必须给出可读的差异说明", tc.name)
		}
	}
}

// 差异说明要能区分"缺"和"多"，排障时才知道该往哪个方向查。
func TestCoverageDriftDetailPointsBothDirections(t *testing.T) {
	_, detail := CoverageDrift(
		leafWith("keep.com", "stale.com"),
		[]string{"keep.com", "fresh.com"},
	)

	for _, want := range []string{"fresh.com", "stale.com"} {
		if !strings.Contains(detail, want) {
			t.Errorf("差异说明应提到 %q，得到: %q", want, detail)
		}
	}
}
