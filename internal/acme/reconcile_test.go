package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	legoapi "github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// fakeACME 起一个最小的 ACME 目录（TLS）。
//
// 只实现到"能构造出 api.Core 并让 NewOrder 失败"为止 ——
// 目的不是模拟一个 CA，而是让 Reconcile 的**决策路径**可以被观察：
// 它到底有没有去下单。
type fakeACME struct {
	srv       *httptest.Server
	newOrders atomic.Int64
}

func newFakeACME(t *testing.T) *fakeACME {
	t.Helper()
	f := &fakeACME{}
	mux := http.NewServeMux()

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		// lego 会强制 https（sender.newHTTPSOnly 检查 req.URL.Scheme），
		// 所以假服务端必须走 TLS；srv.Client() 自带测试 CA。
		base := "https://" + r.Host
		writeJSON(w, map[string]any{
			"newNonce":   base + "/new-nonce",
			"newAccount": base + "/new-account",
			"newOrder":   base + "/new-order",
			"revokeCert": base + "/revoke-cert",
			"keyChange":  base + "/key-change",
			// 故意不提供 renewalInfo：GetRenewalInfo 会返回 ErrNoARI，
			// 于是续期决策退化到时间兜底，不产生额外请求。
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/new-order", func(w http.ResponseWriter, _ *http.Request) {
		f.newOrders.Add(1)
		// 明确的失败，让 recordFailure 走完。
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{
			"type":   "urn:ietf:params:acme:error:malformed",
			"detail": "测试用的假服务端不接受下单",
		})
	})
	mux.HandleFunc("/new-account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+r.Host+"/acct/1")
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"status": "valid"})
	})

	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// selfSignedCertPEM 造一张带指定 SAN 的自签证书，用来填 CertState.CertPEM。
func selfSignedCertPEM(t *testing.T, notAfter time.Time, dnsNames ...string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		AuthorityKeyId:        []byte{0x01, 0x02, 0x03},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newReconcileHarness 搭一个"证书已经签发好、正处于有效期中期"的现场。
func newReconcileHarness(t *testing.T, domains []string, certSANs []string) (*Manager, *state.Store, *fakeACME, *config.Certificate) {
	t.Helper()

	fake := newFakeACME(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开状态库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	httpClient := fake.srv.Client()
	// 账号的 kid 与私钥随便给：这个测试只关心"有没有去下单"。
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core, err := legoapi.New(httpClient, "wecert-test", fake.srv.URL+"/directory", "kid-1", key)
	if err != nil {
		t.Fatalf("构造 api.Core 失败: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	solver := &fakeSolver{}
	m := newManager(store, core, solver, fakeKeyAuth{}, deploy.Noop{}, log)

	// 90 天有效期、刚签不久：距离 classic 的 30 天续期窗口还很远。
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedCertPEM(t, notAfter, certSANs...)

	if err := store.PutCert(&state.CertState{
		Name:      "many-sans",
		NotAfter:  notAfter,
		CertPEM:   certPEM,
		KeyPEM:    []byte("irrelevant"),
		IssuedAt:  time.Now(),
		CertURL:   "https://acme.example/cert/old",
		ARICertID: "", // 关掉 ARI，让决策完全走时间兜底，避免额外请求
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}

	domainsCopy := append([]string(nil), domains...)
	return m, store, fake, &config.Certificate{
		Name:           "many-sans",
		Domains:        domainsCopy,
		Profile:        config.ProfileClassic,
		KeyType:        config.KeyTypeECDSAP256,
		RenewBeforeDur: 30 * 24 * time.Hour,
		Deploy:         config.Deploy{Enabled: false},
	}
}

// 最核心的一条：域名集合一致时**什么都不做**。
//
// 这同时验证了另一个方向 —— 漂移检测不会误报，把正常的证书推去重签。
// 如果这里错了，每轮 reconcile 都会下一次单，几天内撞满
// "5 certs per exact set of identifiers / 7 days"。
func TestReconcileSkipsWhenDomainsMatch(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com", "c.example.com"}
	m, _, fake, cert := newReconcileHarness(t, domains, domains)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("域名一致且未到续期窗口，不该报错: %v", err)
	}
	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("不应创建任何订单，实际创建了 %d 张 —— 这会在几天内撞满限额", n)
	}
}

// 顺序无关、大小写无关的集合相等不应被误判成漂移。
func TestReconcileIgnoresDomainOrderAndCase(t *testing.T) {
	m, _, fake, cert := newReconcileHarness(t,
		[]string{"B.Example.com", "a.example.com"},
		[]string{"a.example.com", "b.example.com"},
	)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("集合等价时不该报错: %v", err)
	}
	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("集合等价却被判定成漂移，创建了 %d 张订单", n)
	}
}

// 关键回归：给已生效的证书**加一个域名**必须立刻触发重签，
// 而不是傻等到 30 天后的续期窗口。
//
// 这里通过"确实去下了单"来证明决策路径走对了 ——
// 真正的签发需要真实 ACME 服务端，不在单测范围内。
func TestReconcileReissuesImmediatelyWhenDomainAdded(t *testing.T) {
	live := []string{"a.example.com", "b.example.com"}
	m, store, fake, cert := newReconcileHarness(t, append(live, "new.example.com"), live)

	err := m.Reconcile(context.Background(), cert)
	if err == nil {
		t.Fatal("配置新增域名后应当立刻去重签（假服务端会拒绝下单，所以必然报错）")
	}
	if !strings.Contains(err.Error(), "创建订单") {
		t.Errorf("报错应当来自下单这一步，说明确实走进了签发流程: %v", err)
	}
	if n := fake.newOrders.Load(); n != 1 {
		t.Errorf("应当恰好尝试下单 1 次，实际 %d 次", n)
	}

	// 失败要落盘并安排退避，否则每轮都会重打 CA。
	st, gerr := store.GetCert("many-sans")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if st.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d，期望 1", st.ConsecutiveFailures)
	}
	if st.NextAttemptAt.IsZero() {
		t.Error("应当安排下一次尝试时间（退避）")
	}
}

// 反向：配置里**删掉**一个域名同样必须触发重签。
// 只查 missing 会漏掉这种情况，证书会继续带着已经不该有的 SAN。
func TestReconcileReissuesImmediatelyWhenDomainRemoved(t *testing.T) {
	m, _, fake, cert := newReconcileHarness(t,
		[]string{"a.example.com"},
		[]string{"a.example.com", "b.example.com"},
	)

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("配置删掉域名后应当立刻去重签")
	}
	if n := fake.newOrders.Load(); n != 1 {
		t.Errorf("应当尝试下单 1 次，实际 %d 次", n)
	}
}

// 已有未过期订单、且它匹配当前配置时，必须继续推进而不是新建 ——
// 这是防止撞限速的核心不变量。
func TestReconcileResumesMatchingOrderInsteadOfCreatingNew(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com"}
	m, store, fake, cert := newReconcileHarness(t, domains, domains)

	if err := store.PutOrder(&state.Order{
		CertName:    "many-sans",
		OrderURL:    fake.srv.URL + "/order/1",
		FinalizeURL: fake.srv.URL + "/finalize/1",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      "pending",
		Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}

	// advance 会去查订单，假服务端没有这个端点 → 报错。
	// 关键是 NewOrder 一次都不能发生。
	_ = m.Reconcile(context.Background(), cert)

	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("已有匹配的在飞订单时不应新建订单，实际新建了 %d 张", n)
	}
}

// 配置变了之后，在飞订单必须被丢弃 ——
// 否则会一直推进一张 finalize 必然被拒的订单，卡到它 7 天后过期。
//
// 现场按最真实的样子搭：生效证书还是**旧**域名集合，
// 配置已经改了，同时在飞的订单也还是按旧集合下的。
// 一轮 reconcile 应当同时完成"丢弃旧订单"和"按新域名重新签发"。
func TestReconcileDiscardsStaleOrderAndReissues(t *testing.T) {
	oldDomains := []string{"a.example.com", "b.example.com"}
	newDomains := []string{"a.example.com", "b.example.com", "c.example.com"}

	// 生效证书是旧的集合，配置是新的集合。
	m, store, fake, cert := newReconcileHarness(t, newDomains, oldDomains)

	// 在飞订单也是按旧集合下的。
	if err := store.PutOrder(&state.Order{
		CertName:    "many-sans",
		OrderURL:    fake.srv.URL + "/order/stale",
		FinalizeURL: fake.srv.URL + "/finalize/stale",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      "ready",
		Identifiers: config.DomainKey(oldDomains),
	}); err != nil {
		t.Fatal(err)
	}

	_ = m.Reconcile(context.Background(), cert)

	o, err := store.GetOrder("many-sans")
	if err != nil {
		t.Fatal(err)
	}
	if o != nil {
		t.Errorf("域名变更后应当丢弃旧订单，但它还在: %+v", o)
	}
	if n := fake.newOrders.Load(); n != 1 {
		t.Errorf("丢弃旧订单后应当按新域名重新下单，实际新建 %d 张", n)
	}
}

// 反过来：订单和配置不一致，但生效证书**已经**符合配置时，
// 丢弃订单就够了，不该顺势再签一张 ——
// 否则每轮 reconcile 都白烧一次订单配额。
func TestReconcileDiscardStaleOrderDoesNotForceReissue(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com"}
	// 生效证书已经就是配置要的集合。
	m, store, fake, cert := newReconcileHarness(t, domains, domains)

	// 在飞订单却按另一个（更早的）集合下的。
	if err := store.PutOrder(&state.Order{
		CertName:    "many-sans",
		OrderURL:    fake.srv.URL + "/order/stale",
		FinalizeURL: fake.srv.URL + "/finalize/stale",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      "ready",
		Identifiers: config.DomainKey([]string{"a.example.com"}),
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile 不该报错: %v", err)
	}

	if o, _ := store.GetOrder("many-sans"); o != nil {
		t.Errorf("过期集合的订单应当被丢弃: %+v", o)
	}
	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("证书已符合配置且未到续期窗口，不该下单，实际新建 %d 张", n)
	}
}
