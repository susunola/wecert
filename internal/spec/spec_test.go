package spec

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testDoc(t *testing.T) *Document {
	t.Helper()
	return &Document{
		APIVersion:  APIVersionV1,
		Kind:        KindDesiredState,
		GeneratedAt: time.Now(),
		Generator:   "wecert-onboard/test",
		Certificates: []config.Certificate{{
			Name:    "example-com",
			Domains: []string{"example.com", "*.example.com"},
		}},
	}
}

// 空文档一律拒绝。
//
// "合法的空"和"生成失败导致的空"在文件里长得一模一样，而后者一旦被接受，
// 后果是每张证书的每个域名都被摘掉。这个风险太不对称。
func TestValidateRejectsEmptyCertificates(t *testing.T) {
	doc := testDoc(t)
	doc.Certificates = nil

	if err := doc.Validate(); err == nil {
		t.Fatal("空 certificates 应当被拒绝")
	}
}

func TestValidateRequiresEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Document)
		want   string
	}{
		{"apiVersion", func(d *Document) { d.APIVersion = "other/v9" }, "apiVersion"},
		{"kind", func(d *Document) { d.Kind = "Something" }, "kind"},
		{"generatedAt", func(d *Document) { d.GeneratedAt = time.Time{} }, "generatedAt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := testDoc(t)
			tc.mutate(doc)
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望提到 %q 的报错，实际 %v", tc.want, err)
			}
		})
	}
}

// 证书名必须由分组键派生。
//
// 这是契约边界上唯一能拦住"名字跟着域名集合跑"的地方 ——
// 等 wecert 读进来的时候，孤儿状态已经产生了。
func TestValidateRejectsNameThatFollowsTheDomainSet(t *testing.T) {
	doc := testDoc(t)
	doc.Certificates = []config.Certificate{{
		// 注册域是 example.com，所以名字必须是 example-com。
		Name:    "example-com-plus-api",
		Domains: []string{"example.com", "api.example.com"},
	}}

	err := doc.Validate()
	if err == nil || !strings.Contains(err.Error(), "not stable") {
		t.Fatalf("期望 Name 稳定性报错，实际 %v", err)
	}
}

func TestValidateRejectsCrossRegisteredDomain(t *testing.T) {
	doc := testDoc(t)
	doc.Certificates = []config.Certificate{{
		Name:    "example-com",
		Domains: []string{"example.com", "example.net"},
	}}

	err := doc.Validate()
	if err == nil || !strings.Contains(err.Error(), "registered domains") {
		t.Fatalf("期望跨注册域报错，实际 %v", err)
	}
}

// 指纹只覆盖证书内容，不吃时间戳和顺序。
// 否则每跑一次 onboarding 指纹都变，"期望状态到底变了没有"就答不了。
func TestRevisionIgnoresOrderAndTimestamps(t *testing.T) {
	a := []config.Certificate{{Name: "example-com", Domains: []string{"example.com", "*.example.com"}}}
	b := []config.Certificate{{Name: "example-com", Domains: []string{"*.example.com", "example.com"}}}

	if Revision(a) != Revision(b) {
		t.Errorf("域名顺序不该影响指纹: %s vs %s", Revision(a), Revision(b))
	}
	if Revision(a) == Revision([]config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}}) {
		t.Error("域名集合变了指纹就该变")
	}
}

func TestRevisionRejectsATamperedDocument(t *testing.T) {
	doc := testDoc(t)
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}

	// 改内容但留着旧指纹 —— 手工编辑最常见的形态。
	doc.Certificates[0].Domains = append(doc.Certificates[0].Domains, "www.example.com")
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Fatalf("期望指纹不匹配的报错，实际 %v", err)
	}
}

func TestWriteAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desired-state.yaml")

	doc := testDoc(t)
	if err := WriteDocument(path, doc); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "# ") {
		t.Error("文档应当以'请勿手工编辑'的提示开头")
	}

	got, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != doc.Revision {
		t.Errorf("指纹丢失: %q vs %q", got.Revision, doc.Revision)
	}
	if len(got.Certificates) != 1 || got.Certificates[0].Name != "example-com" {
		t.Errorf("证书没读回来: %+v", got.Certificates)
	}
	// profile/keyType 应当被规范化填上默认值，而不是留空。
	if got.Certificates[0].Profile != config.ProfileClassic {
		t.Errorf("profile 应填默认值，实际 %q", got.Certificates[0].Profile)
	}
}

// 启动时文档读不到，构造 provider 就该失败。
//
// 允许"起得来但没有期望状态"意味着 wecert 会安静地什么都不续期，
// 直到所有证书过期才被发现 —— 那是最糟的一种失败：无声，且后果全在线上。
func TestNewFileFailsWhenTheDocumentIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.yaml")
	if _, err := NewFile(path, testLogger()); err == nil {
		t.Fatal("文档不存在时 NewFile 应当报错")
	}
}

// 运行期文档读不到 ≠ 期望为空。
//
// 这是整套设计里唯一能造成灾难的地方：如果读失败被当成"期望为空"，
// wecert 会把域名从每张证书里摘掉，线上立刻握手失败。
// 正确反应是冻结在最后一版可用状态上，并继续按它收敛。
func TestFileProviderFreezesOnUnreadableDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desired-state.yaml")
	if err := WriteDocument(path, testDoc(t)); err != nil {
		t.Fatal(err)
	}

	f, err := NewFile(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	good, err := f.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if good.Frozen {
		t.Fatal("第一次读成功时不该是冻结状态")
	}

	// 文档被删掉（或权限被改、或写到一半被截断）。
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	frozen, err := f.DesiredWithReasons(context.Background())
	if err != nil {
		t.Fatalf("冻结时不该返回错误，实际 %v", err)
	}
	if !frozen.Frozen {
		t.Error("读不到文档时必须标记为冻结")
	}
	if frozen.FreezeReason == "" {
		t.Error("冻结时必须说明原因")
	}
	if len(frozen.Certificates) != len(good.Certificates) {
		t.Fatalf("冻结时应保留上一版证书，实际 %d -> %d",
			len(good.Certificates), len(frozen.Certificates))
	}
	if frozen.Revision != good.Revision {
		t.Errorf("冻结时应保留上一版指纹，实际 %q -> %q", good.Revision, frozen.Revision)
	}
}

func TestDiffReportsAddRemoveAndChange(t *testing.T) {
	enforced := &Result{Certificates: []config.Certificate{
		{Name: "example-com", Domains: []string{"example.com", "old.example.com"}},
		{Name: "gone-net", Domains: []string{"gone.net"}},
		{Name: "same-org", Domains: []string{"same.org"}},
	}}
	shadow := &Result{Certificates: []config.Certificate{
		{Name: "example-com", Domains: []string{"example.com", "new.example.com"}},
		{Name: "same-org", Domains: []string{"same.org"}},
		{Name: "fresh-io", Domains: []string{"fresh.io"}},
	}, Revision: "sha256:abc"}

	got := Diff(enforced, shadow)

	if len(got.AddCertificates) != 1 || got.AddCertificates[0] != "fresh-io" {
		t.Errorf("新增证书识别错误: %v", got.AddCertificates)
	}
	if len(got.RemoveCertificates) != 1 || got.RemoveCertificates[0] != "gone-net" {
		t.Errorf("待移除证书识别错误: %v", got.RemoveCertificates)
	}
	if len(got.ChangeCertificates) != 1 {
		t.Fatalf("应当识别出 1 张变化的证书，实际 %v", got.ChangeCertificates)
	}
	ch := got.ChangeCertificates[0]
	if ch.Name != "example-com" {
		t.Errorf("变化的证书名不对: %q", ch.Name)
	}
	if len(ch.Added) != 1 || ch.Added[0] != "new.example.com" {
		t.Errorf("新增域名识别错误: %v", ch.Added)
	}
	if len(ch.Removed) != 1 || ch.Removed[0] != "old.example.com" {
		t.Errorf("移除域名识别错误: %v", ch.Removed)
	}
	if got.Empty() {
		t.Error("有差异时 Empty 必须是 false")
	}
}

func TestDiffIsEmptyWhenNothingChanged(t *testing.T) {
	certs := []config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}}
	got := Diff(&Result{Certificates: certs}, &Result{Certificates: certs})
	if !got.Empty() {
		t.Errorf("没有差异时应当报告为空: %+v", got)
	}
}
