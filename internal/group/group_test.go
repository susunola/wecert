package group

import (
	"errors"
	"reflect"
	"testing"
)

func TestRegisteredDomainUsesThePublicSuffixList(t *testing.T) {
	cases := map[string]string{
		"example.com":            "example.com",
		"api.example.com":        "example.com",
		"a.b.example.com":        "example.com",
		"*.example.com":          "example.com",
		"api.example.com.":       "example.com",
		"API.Example.COM":        "example.com",
		"example.co.uk":          "example.co.uk",
		"api.example.co.uk":      "example.co.uk",
		"deep.api.example.co.uk": "example.co.uk",
		"localhost":              "localhost",
	}

	for in, want := range cases {
		if got := RegisteredDomain(in); got != want {
			t.Errorf("RegisteredDomain(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// 取最后两段是这里最容易犯的错：a.b.co.uk 会被算成 co.uk，
// 于是一整片互不相干的站点被并进同一张证书 —— 而 LE 恰恰也是按 PSL
// 算配额的，两边必须用同一把尺子。
func TestRegisteredDomainDoesNotJustTakeTwoLabels(t *testing.T) {
	if got := RegisteredDomain("a.b.example.co.uk"); got == "co.uk" {
		t.Fatalf("应当使用 PSL 而不是简单取两段，实际得到 %q", got)
	}
}

// *.example.com 只覆盖一层标签。这是最常见的误解，也是"加了域名却没进证书"
// 这个问题的头号来源，所以钉死在测试里。
func TestWildcardCoversExactlyOneLabel(t *testing.T) {
	cases := []struct {
		wc, host string
		want     bool
	}{
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "example.com", false}, // 通配符不覆盖它自己的父名字
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "foo.example.org", false},
		{"*.a.example.com", "x.a.example.com", true},
		{"example.com", "foo.example.com", false}, // 不是通配符
	}

	for _, c := range cases {
		if got := WildcardCovers(c.wc, c.host); got != c.want {
			t.Errorf("WildcardCovers(%q, %q) = %v, 期望 %v", c.wc, c.host, got, c.want)
		}
	}
}

// 这是整个设计里最值钱的一条：已经声明了 *.example.com 之后，
// 再加一个 foo.example.com 不需要动 SAN 集合，也就是 0 次签发。
// 没有它，批量导入 50 个子域就是 50 次重签 = 撞满配额。
func TestCoveredNamesDoNotEnterTheSANSet(t *testing.T) {
	g := Group{
		Registered: "example.com",
		Name:       "example-com",
		Wildcards:  []string{"*.example.com"},
		Names:      []string{"api.example.com", "example.com", "www.example.com"},
	}

	cov, err := g.Cover(100)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"example.com", "*.example.com"}
	if !reflect.DeepEqual(cov.Domains, want) {
		t.Errorf("SAN 集合 = %v，期望 %v", cov.Domains, want)
	}
	for _, n := range []string{"api.example.com", "www.example.com"} {
		if cov.Covered[n] != "*.example.com" {
			t.Errorf("%s 应记录为被 *.example.com 覆盖，实际 %q", n, cov.Covered[n])
		}
	}
	if _, ok := cov.Covered["example.com"]; ok {
		t.Error("example.com 不该被 *.example.com 覆盖")
	}
}

// 没有通配符时，每个名字都得自己进 SAN。
func TestWithoutWildcardsEveryNameEntersTheSANSet(t *testing.T) {
	g := Group{
		Registered: "example.com",
		Name:       "example-com",
		Names:      []string{"www.example.com", "example.com", "api.example.com"},
	}

	cov, err := g.Cover(100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "api.example.com", "www.example.com"}
	if !reflect.DeepEqual(cov.Domains, want) {
		t.Errorf("SAN 集合 = %v，期望 %v（注册域本体在前，其余按字典序）", cov.Domains, want)
	}
}

// 不能凭空造通配符：那意味着证书能对任意子域完成握手，是权限扩张，
// 必须是显式声明的动作。
func TestCoverNeverInventsAWildcard(t *testing.T) {
	g := Group{
		Registered: "example.com",
		Name:       "example-com",
		Names:      []string{"a.example.com", "b.example.com"},
	}

	cov, err := g.Cover(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range cov.Domains {
		if IsWildcard(d) {
			t.Fatalf("没有声明通配符却出现了 %q", d)
		}
	}
}

// Name 只由注册域派生，绝不随域名集合变化。
//
// 这条一旦破掉，加一个域名就会在状态库里凭空多出一条新记录，
// 旧那条的 order URL、ARI certID、deployed CertID 全部成为孤儿。
func TestCertNameIsStableAsDomainsChange(t *testing.T) {
	before, err := GroupBy([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := GroupBy([]string{"example.com", "api.example.com", "*.example.com", "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("应当只有一个分组，实际 %d / %d", len(before), len(after))
	}
	if before[0].Name != after[0].Name {
		t.Fatalf("证书名随域名集合变了: %q -> %q", before[0].Name, after[0].Name)
	}
	if before[0].Name != "example-com" {
		t.Errorf("证书名 = %q，期望 example-com", before[0].Name)
	}
}

// 同样的输入必须给出逐字节相同的输出，顺序也一致。
// 否则期望状态文档每次生成都会 diff 一片，可 review 性直接归零。
func TestGroupByIsIdempotent(t *testing.T) {
	in := []string{"b.example.com", "a.example.com", "*.example.com", "example.com", "A.EXAMPLE.COM"}
	first, err := GroupBy(in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GroupBy(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("两次分组结果不同:\n%+v\n%+v", first, second)
	}
	if len(first) != 1 {
		t.Fatalf("应当只分出一组，实际 %d", len(first))
	}
	if !reflect.DeepEqual(first[0].Names, []string{"a.example.com", "b.example.com", "example.com"}) {
		t.Errorf("具体名字应当去重、小写并排序，实际 %v", first[0].Names)
	}
}

func TestGroupBySplitsByRegisteredDomain(t *testing.T) {
	got, err := GroupBy([]string{"a.example.com", "b.example.net", "c.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("应当分成两组，实际 %d: %+v", len(got), got)
	}
	// 按证书名排序，保证顺序稳定。
	if got[0].Name != "example-com" || got[1].Name != "example-net" {
		t.Errorf("分组顺序应按证书名排序，实际 %q, %q", got[0].Name, got[1].Name)
	}
}

// 超过 SAN 上限时返回可识别的错误，让调用方保留上一版而不是把整组丢掉。
func TestCoverRejectsOversizedGroups(t *testing.T) {
	var names []string
	for _, p := range []string{"a", "b", "c", "d"} {
		names = append(names, p+".example.com")
	}
	g := Group{Registered: "example.com", Name: "example-com", Names: names}

	if _, err := g.Cover(3); !errors.Is(err, ErrTooManyNames) {
		t.Fatalf("应当返回 ErrTooManyNames，实际 %v", err)
	}
	if _, err := g.Cover(4); err != nil {
		t.Fatalf("刚好等于上限时应当通过，实际 %v", err)
	}
}

func TestNormalizeRejectsInvalidNames(t *testing.T) {
	for _, bad := range []string{"", " ", "a..example.com", "-bad.example.com", "a.*.example.com"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) 应当报错", bad)
		}
	}
	if got, err := Normalize(" API.Example.COM. "); err != nil || got != "api.example.com" {
		t.Errorf("Normalize 应接受并规范化大小写与末尾点，实际 %q, %v", got, err)
	}
}
