package config

import (
	"strings"
	"testing"
)

// SAN 多的证书上，domains 往往是从别处整段复制粘贴来的。
// 去重必须发生在判上限**之前**，否则 100 个域名 + 1 个手误重复
// 会被判成 101 超限而拒掉一个本来合法的配置。
func TestDuplicateDomainsDedupedBeforeMaxNames(t *testing.T) {
	// 100 个唯一域名，外加 5 个重复项 —— classic 上限正好是 100。
	domains := make([]string, 0, 105)
	for i := 0; i < 100; i++ {
		domains = append(domains, "d"+itoa(i)+".example.com")
	}
	for i := 0; i < 5; i++ {
		domains = append(domains, "d"+itoa(i)+".example.com")
	}

	body := minimalPrefix + `
certificates:
  - name: dedup
    profile: classic
    domains: [` + strings.Join(quoteAll(domains), ", ") + `]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("100 个唯一域名 + 5 个重复应当通过（去重后正好 100）: %v", err)
	}
	if got := len(cfg.Certificates[0].Domains); got != 100 {
		t.Errorf("去重后应有 100 个域名，得到 %d", got)
	}
}

// 真正的超限仍然要拦住。
func TestRealOverflowStillRejected(t *testing.T) {
	domains := make([]string, 0, 101)
	for i := 0; i < 101; i++ {
		domains = append(domains, "d"+itoa(i)+".example.com")
	}
	body := minimalPrefix + `
certificates:
  - name: over
    profile: classic
    domains: [` + strings.Join(quoteAll(domains), ", ") + `]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("101 个唯一域名应当被拒绝")
	}
}

// 大小写不应当产生两个不同的 identifier。
func TestDomainsLowercased(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: mixed
    domains: ["Example.COM", "example.com", "API.Example.Com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}

	got := cfg.Certificates[0].Domains
	want := []string{"example.com", "api.example.com"}
	if len(got) != len(want) {
		t.Fatalf("domains = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("domains[%d] = %q，期望 %q", i, got[i], want[i])
		}
	}
}

// 顺序必须保持：classic profile 会把第一个 dNSName 提升为 CN。
func TestDomainOrderPreserved(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: ordered
    domains: ["z.example.com", "a.example.com", "m.example.com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	got := cfg.Certificates[0].Domains
	if got[0] != "z.example.com" || got[1] != "a.example.com" || got[2] != "m.example.com" {
		t.Errorf("顺序被改动了: %v（第一个域名会成为 CN）", got)
	}
}

// DomainKey 必须与顺序、大小写、重复无关 —— 它是拿
// "配置里期望的集合"和"证书实际 SAN"做等价比较的基础。
func TestDomainKeyIsSetSemantics(t *testing.T) {
	base := DomainKey([]string{"a.example.com", "b.example.com"})

	same := [][]string{
		{"b.example.com", "a.example.com"},                  // 顺序不同
		{"A.Example.COM", "B.example.com"},                  // 大小写不同
		{"a.example.com", "b.example.com", "a.example.com"}, // 有重复
		{"a.example.com", " b.example.com "},                // 有空白
	}
	for _, candidate := range same {
		if got := DomainKey(candidate); got != base {
			t.Errorf("DomainKey(%v) = %q，应与 %q 等价", candidate, got, base)
		}
	}

	different := [][]string{
		{"a.example.com"}, // 少一个
		{"a.example.com", "b.example.com", "c.example.com"}, // 多一个
		{"a.example.com", "c.example.com"},                  // 换一个
	}
	for _, candidate := range different {
		if got := DomainKey(candidate); got == base {
			t.Errorf("DomainKey(%v) 不应等于 %q", candidate, base)
		}
	}
}

// DiffDomains 两个方向都要报：只报 missing 会漏掉"配置里删了域名"。
func TestDiffDomainsBothDirections(t *testing.T) {
	missing, extra := DiffDomains(
		[]string{"keep.example.com", "added.example.com"},
		[]string{"keep.example.com", "removed.example.com"},
	)

	if len(missing) != 1 || missing[0] != "added.example.com" {
		t.Errorf("missing = %v，期望 [added.example.com]", missing)
	}
	if len(extra) != 1 || extra[0] != "removed.example.com" {
		t.Errorf("extra = %v，期望 [removed.example.com]", extra)
	}

	// 完全一致时两个都应为空。
	missing, extra = DiffDomains([]string{"a.com", "b.com"}, []string{"b.com", "a.com"})
	if len(missing) != 0 || len(extra) != 0 {
		t.Errorf("集合相同时不应有差异，得到 missing=%v extra=%v", missing, extra)
	}
}

// 坏域名必须在本地被拦下 —— 每打出去一个必然被 CA 拒绝的订单，
// 消耗的都是订单配额，而 SAN 多的证书重来一遍代价很大。
func TestDomainValidation(t *testing.T) {
	cases := []struct {
		domain  string
		wantErr bool
		why     string
	}{
		{"example.com", false, "普通域名"},
		{"a.b.c.example.com", false, "多层子域"},
		{"xn--fiqs8s.example.com", false, "punycode"},
		{"my-host.example.com", false, "连字符"},
		{"*.example.com", false, "合法通配符"},
		{"*.*.example.com", true, "LE 不允许 *.*"},
		{"a.*.example.com", true, "通配符必须在最左侧"},
		{"example.com.", true, "尾点"},
		{"", true, "空域名"},
		{"a..example.com", true, "空标签"},
		{".example.com", true, "以点开头"},
		{"example..com", true, "中间空标签"},
		{"exa mple.com", true, "含空格"},
		{"example.com/path", true, "含斜杠"},
		{"under_score.example.com", true, "下划线不是合法主机名字符"},
		{"-lead.example.com", true, "标签以连字符开头"},
		{"trail-.example.com", true, "标签以连字符结尾"},
		{strings.Repeat("a", 64) + ".example.com", true, "标签超过 63 字符"},
		{strings.Repeat("a", 63) + ".example.com", false, "标签正好 63 字符"},
	}

	for _, tc := range cases {
		err := validateDomain(tc.domain)
		if tc.wantErr && err == nil {
			t.Errorf("%q (%s): 期望报错但没有", tc.domain, tc.why)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%q (%s): 期望通过但报错: %v", tc.domain, tc.why, err)
		}
	}
}

// 通配符域名带非法字符时报错信息应当指向真正的问题。
func TestWildcardPositionErrorIsClear(t *testing.T) {
	err := validateDomain("a.*.example.com")
	if err == nil {
		t.Fatal("期望报错")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("报错应点明通配符位置问题，得到: %v", err)
	}
}
