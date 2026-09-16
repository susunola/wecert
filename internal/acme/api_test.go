package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// fakeAPI 记录每一次 ACME 调用，并返回预先编排好的响应。
//
// 它就是把 Manager 对 *api.Core 的依赖抽成窄接口真正换来的东西。
// 订单状态机的正确性完全在于**调用的顺序和参数**：
//
//   - order URL 必须在联系 CA 之前落盘
//   - 续期的订单必须带 replaces，否则拿不到 ARI 的限速豁免
//   - CSR 必须是 DER，而且必须提交到 finalize URL
//
// 这三条都不会报错，只会安静地烧配额或者让重绑定不生效 —— 正是最需要
// 断言、也最需要在一个不需要网络的测试里断言的那类东西。
//
// 之前这些只能靠起一个假的 ACME HTTP 服务器来覆盖：那能跑通全流程，
// 但没法回答"它到底先做了什么"。
type fakeAPI struct {
	mu    sync.Mutex
	calls []string

	// beforeCall 在每次调用**之前**执行，用来断言"此刻的状态库是什么样"。
	//
	// 崩溃安全只能这样验：它断言的是一个**时刻**，而不是某个最终结果。
	// "最后订单落盘了"和"在联系 CA 之前订单就落盘了"是两回事，
	// 而只有后者能挡住"进程在 DNS 传播那几分钟里被杀掉之后重新下单"。
	beforeCall func(call string)

	// orders 是 GetOrder 依次返回的剧本；用完之后一直返回最后一个，
	// 这样轮询循环能收敛而不是空转。
	orders   []legoacme.ExtendedOrder
	orderIdx int

	certPEM []byte
	certErr error

	// 记录下来的参数。
	newOrderDomains []string
	newOrderOpts    *api.OrderOptions
	finalizeURL     string
	finalizeCSR     []byte
	accepted        []string
	certBundle      bool
	renewalInfoHits int
}

func (f *fakeAPI) enter(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	if f.beforeCall != nil {
		f.beforeCall(call)
	}
}

func (f *fakeAPI) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeAPI) NewOrder(domains []string, opts *api.OrderOptions) (legoacme.ExtendedOrder, error) {
	f.enter("NewOrder")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.newOrderDomains = append([]string(nil), domains...)
	f.newOrderOpts = opts
	if len(f.orders) == 0 {
		return legoacme.ExtendedOrder{}, errors.New("fakeAPI: NewOrder 没有编排任何订单")
	}
	return f.orders[0], nil
}

func (f *fakeAPI) GetOrder(string) (legoacme.ExtendedOrder, error) {
	f.enter("GetOrder")
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.orders) == 0 {
		return legoacme.ExtendedOrder{}, errors.New("fakeAPI: GetOrder 没有编排任何订单")
	}
	o := f.orders[f.orderIdx]
	if f.orderIdx < len(f.orders)-1 {
		f.orderIdx++
	}
	return o, nil
}

func (f *fakeAPI) UpdateOrderForCSR(finalizeURL string, csr []byte) (legoacme.ExtendedOrder, error) {
	f.enter("UpdateOrderForCSR")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalizeURL = finalizeURL
	f.finalizeCSR = append([]byte(nil), csr...)
	if len(f.orders) == 0 {
		return legoacme.ExtendedOrder{}, errors.New("fakeAPI: UpdateOrderForCSR 没有编排任何订单")
	}
	return f.orders[len(f.orders)-1], nil
}

func (f *fakeAPI) GetAuthorization(string) (legoacme.Authorization, error) {
	f.enter("GetAuthorization")
	return legoacme.Authorization{Status: "valid", Identifier: legoacme.Identifier{Value: "a.example.com"}}, nil
}

func (f *fakeAPI) AcceptChallenge(challengeURL string) error {
	f.enter("AcceptChallenge")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepted = append(f.accepted, challengeURL)
	return nil
}

func (f *fakeAPI) GetCertificate(string, bool) ([]byte, []byte, error) {
	f.enter("GetCertificate")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certBundle = true
	return f.certPEM, []byte("key"), f.certErr
}

// GetRenewalInfo 默认报错：ARI 是可选路径，而一个没编排过的 ARI 调用
// 通常意味着测试现场的 throttling 没设对。让它显式失败比返回空响应好查。
func (f *fakeAPI) GetRenewalInfo(string) (*http.Response, error) {
	f.enter("GetRenewalInfo")
	f.mu.Lock()
	f.renewalInfoHits++
	f.mu.Unlock()
	return nil, errors.New("fakeAPI: ARI 没有编排")
}

func (f *fakeAPI) GetKeyAuthorization(token string) (string, error) {
	return "keyauth(" + token + ")", nil
}

// ── 脚手架 ──────────────────────────────────────────────────────────────────

// terminalOrder 返回一张"已经签发好"的订单。
//
// 每个测试都编排能收敛的订单序列：假的 GetOrder 如果一直返回 pending，
// 状态机会老老实实轮询到 2 分钟的超时 —— 那让整个包的测试慢到没法用，
// 而且掩盖了真正想断言的东西。
func terminalOrder(location, finalize, certURL string) legoacme.ExtendedOrder {
	return legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "valid", Finalize: finalize, Certificate: certURL},
		Location: location,
	}
}

func newAPITestHarness(t *testing.T, domains []string) (*state.Store, *Manager, *fakeAPI, *config.Certificate) {
	t.Helper()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开状态库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	certs := []config.Certificate{{
		Name:    "site-example-com",
		Domains: domains,
		Profile: config.ProfileClassic,
		KeyType: config.KeyTypeECDSAP256,
		Deploy:  config.Deploy{Enabled: false},
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatalf("规范化证书失败: %v", err)
	}
	return store, m, fake, &certs[0]
}

// ── 不变量 1：order URL 先落盘，再联系 CA ───────────────────────────────────

// 这是崩溃安全的全部依赖。
//
// 如果 order URL 没落盘，进程在 DNS 传播那几分钟里被杀掉之后会重新下单，
// 而那一单的 identifier 集合与前一单完全相同 —— 直接撞上
// "5 certificates per exact set of identifiers / 7 days"，
// 而且没有任何 override 可以申请。
func TestOrderURLIsOnDiskBeforeTheNextACMECall(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	fake.orders = []legoacme.ExtendedOrder{
		{
			Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/1"},
			Location: "https://ca.test/order/1",
		},
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

	var checked bool
	fake.beforeCall = func(call string) {
		// NewOrder 之后的下一次调用就是状态机去查订单；那一刻落盘必须已经发生。
		if call != "GetOrder" || checked {
			return
		}
		checked = true

		o, err := store.GetOrder(cert.Name)
		if err != nil {
			t.Fatalf("读订单失败: %v", err)
		}
		if o == nil {
			t.Fatal("联系 CA 之前 order URL 必须先落盘：进程在这里被 kill，" +
				"重启后会为同一组 identifier 再下一单，撞上 7 天不可恢复的限额")
		}
		if o.OrderURL != "https://ca.test/order/1" {
			t.Fatalf("落盘的 order URL = %q，期望 https://ca.test/order/1", o.OrderURL)
		}
		// finalize URL 也必须一起落盘：它只有这一次能拿到。
		if o.FinalizeURL != "https://ca.test/finalize/1" {
			t.Fatalf("落盘的 finalize URL = %q", o.FinalizeURL)
		}
		// identifier 集合也要记下来，否则之后配置改了也发现不了。
		if o.Identifiers != cert.DomainKey() {
			t.Fatalf("落盘的 identifier 指纹 = %q，期望 %q", o.Identifiers, cert.DomainKey())
		}
	}

	_ = m.Reconcile(context.Background(), cert)

	if !checked {
		t.Fatalf("假 API 的 GetOrder 一次都没被调用，这个测试什么都没验到（调用序列: %v）", fake.callLog())
	}
}

// ── 不变量 2：续期必须带 replaces ───────────────────────────────────────────

// 不带 replaces 的订单拿不到 ARI 的限速豁免 —— 它不会报错，
// 只会让这次签发实打实地消耗"每注册域 50 张 / 7 天"。
// 这类不报错的错误正是需要一个能断言调用参数的假实现的原因。
func TestRenewalCarriesTheReplacesCertID(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	now := m.now()
	const certID = "YWJj.ZGVm"

	// ARI 窗口整个落在过去 → 现在就该续期。
	// ARICheckedAt 设成"刚查过"，把 ARI 拉取那一步节流掉，
	// 这样这个测试只关心下落单时带了什么。
	if err := store.PutCert(&state.CertState{
		Name:           cert.Name,
		NotAfter:       now.Add(20 * 24 * time.Hour),
		ARICertID:      certID,
		ARIWindowStart: now.Add(-2 * time.Hour),
		ARIWindowEnd:   now.Add(-time.Hour),
		ARICheckedAt:   now,
	}); err != nil {
		t.Fatal(err)
	}

	fake.orders = []legoacme.ExtendedOrder{
		{
			Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/2"},
			Location: "https://ca.test/order/2",
		},
		terminalOrder("https://ca.test/order/2", "https://ca.test/finalize/2", "https://ca.test/cert/2"),
	}
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

	_ = m.Reconcile(context.Background(), cert)

	if fake.newOrderOpts == nil {
		t.Fatalf("应当下一张续期订单，实际调用序列: %v", fake.callLog())
	}
	if fake.newOrderOpts.ReplacesCertID != certID {
		t.Errorf("下单必须带 replaces=%q（ARI 豁免的前提），实际 %q",
			certID, fake.newOrderOpts.ReplacesCertID)
	}
	if fake.newOrderOpts.Profile != config.ProfileClassic {
		t.Errorf("profile 应当透传给 CA，实际 %q", fake.newOrderOpts.Profile)
	}
	if fake.renewalInfoHits != 0 {
		t.Errorf("ARICheckedAt 刚更新过，不该再去查 ARI，实际查了 %d 次", fake.renewalInfoHits)
	}
}

// ── 不变量 3：CSR 是 DER，且提交到 finalize URL ─────────────────────────────

// 这两条都踩过：
//
//   - 传 PEM 会得到 asn1 "tags don't match"
//   - 提交到 order URL 会得到 "POST-as-GET requests must have an empty payload"
//
// lego 那个参数名恰好叫 orderURL，所以后者尤其容易踩。
func TestCSRIsDERAndGoesToTheFinalizeURL(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com", "b.example.com"})

	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	const orderURL = "https://ca.test/order/9"
	const finalizeURL = "https://ca.test/finalize/9"
	const certURL = "https://ca.test/cert/9"

	if err := store.PutOrder(&state.Order{
		CertName:    cert.Name,
		OrderURL:    orderURL,
		FinalizeURL: finalizeURL,
		Status:      "ready",
		KeyPEM:      keyPEM,
		Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}

	// 状态为 ready → 直接进 finalize，不必推挑战。
	fake.orders = []legoacme.ExtendedOrder{
		{Order: legoacme.Order{Status: "ready", Finalize: finalizeURL}, Location: orderURL},
		{Order: legoacme.Order{Status: "valid", Finalize: finalizeURL, Certificate: certURL}, Location: orderURL},
	}
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile 失败: %v", err)
	}

	if fake.finalizeURL != finalizeURL {
		t.Errorf("CSR 必须提交到 finalize URL %q，实际提交到 %q（传 order URL 会被 LE 当成 POST-as-GET）",
			finalizeURL, fake.finalizeURL)
	}

	// DER 而不是 PEM：PEM 会在 CA 那边报 asn1 "tags don't match"。
	if len(fake.finalizeCSR) == 0 {
		t.Fatal("没有捕获到提交的 CSR")
	}
	req, err := x509.ParseCertificateRequest(fake.finalizeCSR)
	if err != nil {
		t.Fatalf("提交的不是 DER 编码的 CSR（传 PEM 会得到 asn1 tags don't match）: %v", err)
	}
	if err := req.CheckSignature(); err != nil {
		t.Errorf("CSR 签名校验失败: %v", err)
	}
	if got := len(req.DNSNames); got != len(cert.Domains) {
		t.Errorf("CSR 里的名字数 = %d，期望 %d: %v", got, len(cert.Domains), req.DNSNames)
	}

	if !fake.certBundle {
		t.Error("下载证书时应当要 fullchain（bundle=true），那才是 CLB 需要的格式")
	}

	// 最后证书必须真的落到状态库里，否则这一轮等于白跑。
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st == nil || st.NotAfter.IsZero() {
		t.Fatalf("证书没有落盘: %+v", st)
	}
	if st.ARICertID == "" {
		t.Error("应当从证书里算出 ARI certID —— 那是下一次续期拿限速豁免的前提")
	}
}

// 状态机不应该在已 valid 的授权上重复调 AcceptChallenge。
//
// 重复通知不会报错，但那是每轮一次的无用往返；更重要的是，
// 一个"每轮都重推一遍挑战"的实现会掩盖真正的进度问题。
func TestChallengesAreAcceptedOncePerAuthorization(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.PutOrder(&state.Order{
		CertName:    cert.Name,
		OrderURL:    "https://ca.test/order/3",
		FinalizeURL: "https://ca.test/finalize/3",
		Status:      "pending",
		KeyPEM:      keyPEM,
		Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAuthorization(&state.Authorization{
		CertName:       cert.Name,
		AuthzURL:       "https://ca.test/authz/1",
		Identifier:     "a.example.com",
		Status:         "valid",
		ChallengeURL:   "https://ca.test/chall/1",
		ChallengeToken: "tok-1",
	}); err != nil {
		t.Fatal(err)
	}

	// 订单停在 pending，而授权已经是 valid：不该再有挑战要推。
	fake.orders = []legoacme.ExtendedOrder{
		{
			Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/3"},
			Location: "https://ca.test/order/3",
		},
		terminalOrder("https://ca.test/order/3", "https://ca.test/finalize/3", "https://ca.test/cert/3"),
	}
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile 失败: %v", err)
	}

	if len(fake.accepted) != 0 {
		t.Errorf("授权已经 valid，不该再通知 CA 去验证，实际推了 %v", fake.accepted)
	}

	// 这个测试的价值有一半在于确认调用序列真的是我们以为的那几步。
	t.Logf("调用序列: %v", fake.callLog())
}
