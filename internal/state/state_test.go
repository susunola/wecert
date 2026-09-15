package state

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开状态库失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// 这是整个系统最重要的不变量：订单连同它的私钥必须能跨进程重启完整恢复。
// 丢了 order URL 就会重新下单，直接撞上
// "5 certificates per exact set of identifiers / 7 days"。
func TestOrderRoundTripPreservesKey(t *testing.T) {
	s := openTestStore(t)

	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n")
	expires := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Second)
	want := &Order{
		CertName:    "example-com",
		OrderURL:    "https://acme-v02.api.letsencrypt.org/acme/order/1/2",
		FinalizeURL: "https://acme-v02.api.letsencrypt.org/acme/finalize/1/2",
		CertURL:     "",
		ExpiresAt:   expires,
		Status:      "pending",
		KeyPEM:      keyPEM,
	}
	if err := s.PutOrder(want); err != nil {
		t.Fatalf("PutOrder 失败: %v", err)
	}

	got, err := s.GetOrder("example-com")
	if err != nil {
		t.Fatalf("GetOrder 失败: %v", err)
	}
	if got == nil {
		t.Fatal("GetOrder 返回 nil，订单丢失")
	}

	if got.OrderURL != want.OrderURL {
		t.Errorf("OrderURL = %q，期望 %q", got.OrderURL, want.OrderURL)
	}
	if got.FinalizeURL != want.FinalizeURL {
		t.Errorf("FinalizeURL = %q，期望 %q", got.FinalizeURL, want.FinalizeURL)
	}
	if got.Status != "pending" {
		t.Errorf("Status = %q，期望 pending", got.Status)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %s，期望 %s", got.ExpiresAt, expires)
	}
	if string(got.KeyPEM) != string(keyPEM) {
		t.Errorf("KeyPEM 未原样恢复: %q", got.KeyPEM)
	}
}

func TestOrderUpsertKeepsSingleRow(t *testing.T) {
	s := openTestStore(t)

	o := &Order{CertName: "c", OrderURL: "url-1", Status: "pending"}
	if err := s.PutOrder(o); err != nil {
		t.Fatal(err)
	}
	// 同一张证书再写一次应当覆盖，而不是留下两个订单。
	o.OrderURL = "url-2"
	o.Status = "ready"
	if err := s.PutOrder(o); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetOrder("c")
	if err != nil {
		t.Fatal(err)
	}
	if got.OrderURL != "url-2" || got.Status != "ready" {
		t.Errorf("订单未被子 upsert 覆盖: %+v", got)
	}
}

func TestGetMissingReturnsNil(t *testing.T) {
	s := openTestStore(t)

	if o, err := s.GetOrder("nope"); err != nil || o != nil {
		t.Errorf("GetOrder 对不存在的证书应返回 (nil, nil)，得到 (%v, %v)", o, err)
	}
	if c, err := s.GetCert("nope"); err != nil || c != nil {
		t.Errorf("GetCert 对不存在的证书应返回 (nil, nil)，得到 (%v, %v)", c, err)
	}
	if a, err := s.GetAccount("nope"); err != nil || a != nil {
		t.Errorf("GetAccount 对不存在的目录应返回 (nil, nil)，得到 (%v, %v)", a, err)
	}
}

func TestCertStateRoundTrip(t *testing.T) {
	s := openTestStore(t)

	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	windowStart := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	windowEnd := windowStart.Add(48 * time.Hour)

	want := &CertState{
		Name:                "example-com",
		NotAfter:            notAfter,
		CertURL:             "https://acme-v02.api.letsencrypt.org/acme/cert/123",
		CertPEM:             []byte("fullchain"),
		KeyPEM:              []byte("privkey"),
		IssuedAt:            time.Now().Truncate(time.Second),
		ARICertID:           "abc.def",
		ARIWindowStart:      windowStart,
		ARIWindowEnd:        windowEnd,
		ARICheckedAt:        time.Now().Truncate(time.Second),
		ARIRetryAfter:       6 * time.Hour,
		ConsecutiveFailures: 3,
		LastError:           "boom",
		DeployedCertID:      "TencentCertId123",
	}
	if err := s.PutCert(want); err != nil {
		t.Fatalf("PutCert 失败: %v", err)
	}

	got, err := s.GetCert("example-com")
	if err != nil {
		t.Fatalf("GetCert 失败: %v", err)
	}

	if !got.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %s，期望 %s", got.NotAfter, notAfter)
	}
	if got.ARICertID != want.ARICertID {
		t.Errorf("ARICertID = %q，期望 %q", got.ARICertID, want.ARICertID)
	}
	if !got.ARIWindowStart.Equal(windowStart) || !got.ARIWindowEnd.Equal(windowEnd) {
		t.Errorf("ARI 窗口未恢复: %s - %s", got.ARIWindowStart, got.ARIWindowEnd)
	}
	if got.ARIRetryAfter != 6*time.Hour {
		t.Errorf("ARIRetryAfter = %v，期望 6h", got.ARIRetryAfter)
	}
	if got.ConsecutiveFailures != 3 {
		t.Errorf("ConsecutiveFailures = %d，期望 3", got.ConsecutiveFailures)
	}
	if got.DeployedCertID != "TencentCertId123" {
		t.Errorf("DeployedCertID = %q", got.DeployedCertID)
	}
	if string(got.CertPEM) != "fullchain" || string(got.KeyPEM) != "privkey" {
		t.Errorf("证书/私钥未恢复: %q / %q", got.CertPEM, got.KeyPEM)
	}
}

// 零值时间必须能原样往返，否则"还没签发"会被误判成"1970 年就签发了"。
func TestZeroTimesRoundTrip(t *testing.T) {
	s := openTestStore(t)

	if err := s.PutCert(&CertState{Name: "fresh"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCert("fresh")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotAfter.IsZero() {
		t.Errorf("NotAfter 应为零值，得到 %s", got.NotAfter)
	}
	if !got.ARIWindowStart.IsZero() || !got.ARICheckedAt.IsZero() {
		t.Error("ARI 时间字段应为零值")
	}
	if !got.NextAttemptAt.IsZero() {
		t.Errorf("NextAttemptAt 应为零值，得到 %s", got.NextAttemptAt)
	}
}

func TestAuthorizationRoundTrip(t *testing.T) {
	s := openTestStore(t)

	// wildcard 和 apex 会落在同一个 TXT 名字上，两条授权必须能各自独立保存。
	for _, a := range []*Authorization{
		{CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
			TxtName: "_acme-challenge.example.com.", TxtValue: "value-1", Presented: true},
		{CertName: "c", AuthzURL: "authz-2", Identifier: "*.example.com",
			TxtName: "_acme-challenge.example.com.", TxtValue: "value-2", Presented: true},
	} {
		if err := s.PutAuthorization(a); err != nil {
			t.Fatalf("PutAuthorization 失败: %v", err)
		}
	}

	got, err := s.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("应有 2 条授权，得到 %d", len(got))
	}

	values := map[string]string{}
	for _, a := range got {
		if a.TxtName != "_acme-challenge.example.com." {
			t.Errorf("TxtName = %q", a.TxtName)
		}
		if !a.Presented {
			t.Errorf("%s 的 Presented 应为 true", a.Identifier)
		}
		values[a.Identifier] = a.TxtValue
	}
	if values["example.com"] != "value-1" || values["*.example.com"] != "value-2" {
		t.Errorf("两条同名 TXT 的值未正确区分: %v", values)
	}

	if err := s.DeleteAuthorizations("c"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListAuthorizations("c"); len(got) != 0 {
		t.Errorf("删除后应为空，得到 %d 条", len(got))
	}
}

func TestRetiredCerts(t *testing.T) {
	s := openTestStore(t)

	if err := s.AddRetiredCert("old-1", "example-com"); err != nil {
		t.Fatal(err)
	}
	// 重复添加应当被忽略而不是报错（幂等）。
	if err := s.AddRetiredCert("old-1", "example-com"); err != nil {
		t.Fatalf("重复添加退役证书应当幂等: %v", err)
	}

	// 保留期之外的才该被回收。
	if got, err := s.ListRetiredCertsBefore(time.Now().Add(-7 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Errorf("刚退役的证书不应出现在回收列表，得到 %d 条", len(got))
	}

	got, err := s.ListRetiredCertsBefore(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CertID != "old-1" {
		t.Fatalf("应回收 1 张退役证书，得到 %+v", got)
	}

	if err := s.DeleteRetiredCert("old-1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListRetiredCertsBefore(time.Now().Add(time.Minute)); len(got) != 0 {
		t.Errorf("回收后列表应为空，得到 %d 条", len(got))
	}
}

// 状态库重开后数据必须还在 —— 这是"重启不重新下单"的物理基础。
func TestStatePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.PutOrder(&Order{CertName: "c", OrderURL: "persisted-url", KeyPEM: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	got, err := s2.GetOrder("c")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.OrderURL != "persisted-url" {
		t.Fatalf("重开后订单丢失: %+v", got)
	}
}
