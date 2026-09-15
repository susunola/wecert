package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写临时配置失败: %v", err)
	}
	return path
}

const minimalPrefix = `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: dnspod
  loginToken: token
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
`

func TestLoadMinimal(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
certificates:
  - name: example-com
    domains: ["example.com", "*.example.com"]
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}

	c := cfg.Certificates[0]
	if c.Profile != ProfileClassic {
		t.Errorf("默认 profile 应为 classic，得到 %q", c.Profile)
	}
	if c.KeyType != KeyTypeECDSAP256 {
		t.Errorf("默认 keyType 应为 ecdsa-p256，得到 %q", c.KeyType)
	}
	// classic 默认提前 30 天续期。
	if c.RenewBeforeDur != 30*24*time.Hour {
		t.Errorf("classic 默认 renewBefore 应为 720h，得到 %v", c.RenewBeforeDur)
	}
	if c.MaxNames() != 100 {
		t.Errorf("classic 的 MaxNames 应为 100，得到 %d", c.MaxNames())
	}
	// 时长默认值应当被填上，而不是留零值。
	if cfg.DNS.Propagation != 5*time.Minute {
		t.Errorf("dnspod.propagationTimeout 默认应为 5m，得到 %v", cfg.DNS.Propagation)
	}
	if cfg.Metrics.Listen == "" {
		t.Error("metrics.listen 应当有默认值")
	}
}

// tlsserver profile 的 Max Names 只有 25，本地必须先拦下来，
// 否则会把一个必然被 CA 拒绝的订单打出去，白白消耗 order 配额。
func TestProfileMaxNamesEnforcedLocally(t *testing.T) {
	domains := make([]string, 0, 26)
	for i := 0; i < 26; i++ {
		domains = append(domains, "d"+string(rune('a'+i))+".example.com")
	}

	body := minimalPrefix + `
certificates:
  - name: too-many
    profile: tlsserver
    domains: [` + strings.Join(quoteAll(domains), ", ") + `]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("tlsserver profile 超过 25 个域名时应当报错")
	}
	if !strings.Contains(err.Error(), "25") {
		t.Errorf("错误信息应当提到 25 这个上限，得到: %v", err)
	}
}

// classic 的 100 是上限，101 个必须被拒。
func TestClassicMaxNames(t *testing.T) {
	domains := make([]string, 0, 101)
	for i := 0; i < 101; i++ {
		domains = append(domains, "d"+itoa(i)+".example.com")
	}
	body := minimalPrefix + `
certificates:
  - name: too-many
    profile: classic
    domains: [` + strings.Join(quoteAll(domains), ", ") + `]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("classic profile 超过 100 个域名时应当报错")
	}
}

func TestWildcardValidation(t *testing.T) {
	cases := []struct {
		domain  string
		wantErr bool
		why     string
	}{
		{"example.com", false, "普通域名"},
		{"*.example.com", false, "合法通配符"},
		{"a.b.example.com", false, "多层子域"},
		{"*.*.example.com", true, "LE 不允许 *.*"},
		{"a.*.example.com", true, "通配符必须在最左侧"},
		{"example.com.", true, "尾点"},
		{"", true, "空域名"},
	}

	for _, tc := range cases {
		body := minimalPrefix + `
certificates:
  - name: t
    domains: ["` + tc.domain + `"]
`
		_, err := Load(writeConfig(t, body))
		if tc.wantErr && err == nil {
			t.Errorf("%s (%s): 期望报错但没有", tc.domain, tc.why)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s (%s): 期望通过但报错: %v", tc.domain, tc.why, err)
		}
	}
}

// 配置写错了必须立刻暴露，不能静默忽略。
func TestUnknownFieldRejected(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: t
    domains: ["example.com"]
    renewwBefore: 30d
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("未知字段应当导致报错")
	}
}

func TestDuplicateCertificateNameRejected(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: dup
    domains: ["a.example.com"]
  - name: dup
    domains: ["b.example.com"]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("重复的证书名应当报错")
	}
}

func TestMissingRegionsRejected(t *testing.T) {
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: dnspod
  loginToken: token
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
certificates:
  - name: t
    domains: ["example.com"]
`
	// CLB 是分地域资源，不写 regions 会一个实例都更新不到。
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("缺少 tencent.regions 时应当报错")
	}
}

func TestStagingAndProductionConstants(t *testing.T) {
	if DirectoryStaging == DirectoryProduction {
		t.Fatal("staging 与 production 目录不能相同")
	}
}

// dns.provider=dnspod 用的是 DNSPod 自有 API Token，不是腾讯云 AK/SK。
// 漏填时必须给出能看懂的报错，否则使用者会拿着腾讯云 AK/SK 一头雾水。
func TestDNSPodProviderRequiresLoginToken(t *testing.T) {
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: dnspod
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: t
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("dns.provider=dnspod 缺 loginToken 时应当报错")
	}
	if !strings.Contains(err.Error(), "SecretId") {
		t.Errorf("报错应当点明它和腾讯云 SecretId/SecretKey 不是一回事，得到: %v", err)
	}
}

// 反过来，tencentcloud provider 不应该要求 DNSPod token。
func TestTencentCloudProviderNeedsNoLoginToken(t *testing.T) {
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: tencentcloud
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: t
    domains: ["example.com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("dns.provider=tencentcloud 不应要求 loginToken: %v", err)
	}
	if cfg.DNS.Provider != DNSProviderTencentCloud {
		t.Errorf("provider = %q", cfg.DNS.Provider)
	}
}

func TestUnknownDNSProviderRejected(t *testing.T) {
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: route53
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: t
    domains: ["example.com"]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("未知的 dns.provider 应当报错")
	}
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = `"` + s + `"`
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ── webhook 校验 ────────────────────────────────────────────────────────────

func TestWebhookDisabledByDefault(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
certificates:
  - name: t
    domains: ["example.com"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.Webhook.Listen != "" {
		t.Errorf("默认不该启用 webhook，实际 listen=%q", cfg.Webhook.Listen)
	}
}

// 这个端点会触发真实签发、消耗速率限制配额，所以缺 token 必须直接拒绝。
func TestWebhookRequiresToken(t *testing.T) {
	body := minimalPrefix + `
webhook:
  listen: "127.0.0.1:9801"
certificates:
  - name: t
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("启用 webhook 但没给 token 时应当报错")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("报错应当点明缺 token，得到: %v", err)
	}
}

// 弱 token 在这个端点上等于没有鉴权。
func TestWebhookRejectsShortToken(t *testing.T) {
	body := minimalPrefix + `
webhook:
  listen: "127.0.0.1:9801"
  token: "short"
certificates:
  - name: t
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("过短的 token 应当报错")
	}
	if !strings.Contains(err.Error(), "太短") {
		t.Errorf("报错应当说明太短，得到: %v", err)
	}
}

// 有 token 却没监听地址，是配置写反了 —— 端点根本不存在，token 无从生效。
func TestWebhookTokenWithoutListenIsRejected(t *testing.T) {
	body := minimalPrefix + `
webhook:
  token: "0123456789abcdef0123"
certificates:
  - name: t
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("只给 token 不给 listen 时应当报错")
	}
}

// NotifyURL 是出站通知，不依赖监听端点，可以单独用。
func TestWebhookNotifyURLAloneIsAllowed(t *testing.T) {
	body := minimalPrefix + `
webhook:
  notifyURL: "https://example.com/hook"
certificates:
  - name: t
    domains: ["example.com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("只配 notifyURL 应当允许: %v", err)
	}
	if cfg.Webhook.NotifyURL == "" {
		t.Error("notifyURL 未被保留")
	}
}

func TestWebhookValidConfig(t *testing.T) {
	body := minimalPrefix + `
webhook:
  listen: "127.0.0.1:9801"
  token: "0123456789abcdef0123456789abcdef"
  notifyURL: "https://example.com/hook"
certificates:
  - name: t
    domains: ["example.com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("合法配置不该报错: %v", err)
	}
	if cfg.Webhook.Listen != "127.0.0.1:9801" || cfg.Webhook.Token == "" {
		t.Errorf("webhook 配置未被正确解析: %+v", cfg.Webhook)
	}
}
