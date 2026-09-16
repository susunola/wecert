// Package group 把"声明要证书的名字"整理成证书分组。
//
// 这里的规则不是可选的优化，它直接决定 Let's Encrypt 的配额消耗速度：
// 域名集合变一次就是一张新证书，实打实消耗
// "Certificates per Registered Domain"（50 / 7 天，跨账号共享）。
// 通配符优先能把"加一个子域"从 1 次签发降到 0 次。
//
// 两条必须钉住的性质：
//  1. 幂等：同样的输入永远给出同样的输出，顺序也一致
//  2. Name 稳定：证书名只由分组键派生，绝不随域名集合变化
//
// 第 2 条一旦破掉，加一个域名就会在状态库里凭空多出一条新记录，
// 旧那条的 order URL、ARI certID、deployed CertID 全部成为孤儿 ——
// "每张证书最多一个进行中的订单"这条不变量随之失效，两边的订单会同时飞，
// 直接撞上 exact-set 限速（这条没有 override）。
package group

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/susunola/wecert/internal/config"
)

// Normalize 规范化一个声明的名字：去空白、转小写、去末尾点，并校验。
func Normalize(raw string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if n == "" {
		return "", errors.New("empty name")
	}
	if err := config.ValidateDomain(n); err != nil {
		return "", err
	}
	return n, nil
}

// IsWildcard 报告名字是否为通配符，形如 *.example.com。
func IsWildcard(name string) bool { return strings.HasPrefix(name, "*.") }

// Base 去掉通配符前缀，返回它所依附的父名字。
func Base(name string) string { return strings.TrimPrefix(name, "*.") }

// RegisteredDomain 返回 host 的注册域（eTLD+1）。
//
// 用 Public Suffix List 而不是简单的"取最后两段"：后者会把
// a.b.co.uk 算成 co.uk，于是一整片互不相干的站点被并进同一张证书，
// 而 LE 恰恰也是按 PSL 算配额的 —— 两边必须用同一把尺子。
func RegisteredDomain(host string) string {
	h := Base(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."))
	if h == "" {
		return ""
	}
	if net.ParseIP(h) != nil {
		return h
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		// 单标签主机名（"localhost"）或 PSL 查不到：退化成自身。
		return h
	}
	return etld1
}

// CertName 由分组键派生证书名。
//
// 这是 Name 稳定性的落点：入参只能是注册域，绝不能是域名集合。
func CertName(registered string) string {
	s := strings.NewReplacer(".", "-", ":", "-").Replace(strings.ToLower(registered))
	s = strings.Trim(s, "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}

// Group 是同一注册域下的一组声明。
type Group struct {
	// Registered 是 eTLD+1。
	Registered string

	// Name 是证书名，只由 Registered 派生。
	Name string

	// Wildcards 是已声明的通配符，已排序。
	Wildcards []string

	// Names 是已声明的具体名字，已排序。
	Names []string
}

// GroupBy 按注册域把声明分组。
//
// 结果按证书名排序，保证同样的输入给出逐字节相同的输出。
func GroupBy(declared []string) ([]Group, error) {
	byReg := make(map[string]*Group)
	for _, raw := range declared {
		n, err := Normalize(raw)
		if err != nil {
			return nil, fmt.Errorf("declared name %q: %w", raw, err)
		}
		reg := RegisteredDomain(n)
		if reg == "" {
			return nil, fmt.Errorf("declared name %q has no registered domain", raw)
		}

		g := byReg[reg]
		if g == nil {
			g = &Group{Registered: reg, Name: CertName(reg)}
			byReg[reg] = g
		}
		if IsWildcard(n) {
			g.Wildcards = appendUnique(g.Wildcards, n)
		} else {
			g.Names = appendUnique(g.Names, n)
		}
	}

	out := make([]Group, 0, len(byReg))
	for _, g := range byReg {
		sort.Strings(g.Wildcards)
		sort.Strings(g.Names)
		// 通配符优先：它必须排在最前面吗？不。这里只排序，选择在 Cover 里做。
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Coverage 是覆盖一组声明所需的最小 SAN 集合。
type Coverage struct {
	// Domains 是 SAN 集合，顺序稳定。
	Domains []string

	// Covered 记录哪些名字是被哪个通配符覆盖的，因而不必单独进 SAN。
	// 这张表是可观测性的一部分：回答"我加的子域为什么没出现在证书里"。
	Covered map[string]string
}

// ErrTooManyNames 表示一组声明的 SAN 集合超过了 profile 上限。
//
// 调用方**不应该**把它当成"这组不要了"：正确反应是保留上一版期望状态并告警。
// 直接丢掉会让 wecert 看到一张证书凭空消失。
var ErrTooManyNames = errors.New("group exceeds the profile's max number of names")

// Cover 计算覆盖本组所有声明所需的最小 SAN 集合。
//
// 规则：
//   - 已声明的通配符直接进 SAN
//   - 被某个已声明通配符覆盖的名字不进 SAN（这就是省配额的地方）
//   - 其余名字各自进 SAN
//
// 注意不会**凭空造通配符**：加一张 *.example.com 意味着证书能对
// 任意子域完成握手，那是权限扩张，必须是显式声明的动作。
func (g Group) Cover(maxNames int) (*Coverage, error) {
	cov := &Coverage{Covered: make(map[string]string, len(g.Names))}

	uncovered := make([]string, 0, len(g.Names))
	for _, n := range g.Names {
		coverer := ""
		for _, w := range g.Wildcards {
			if WildcardCovers(w, n) {
				coverer = w
				break
			}
		}
		if coverer != "" {
			cov.Covered[n] = coverer
			continue
		}
		uncovered = append(uncovered, n)
	}
	sort.Strings(uncovered)

	domains := make([]string, 0, len(g.Wildcards)+len(uncovered))
	// 注册域本体排最前：classic profile 会把第一个 dNSName 提升为 Subject CN，
	// 让 CN 是裸域比让 CN 是某个子域可读得多。
	if i := sort.SearchStrings(uncovered, g.Registered); i < len(uncovered) && uncovered[i] == g.Registered {
		domains = append(domains, g.Registered)
		uncovered = append(uncovered[:i], uncovered[i+1:]...)
	}
	domains = append(domains, g.Wildcards...)
	domains = append(domains, uncovered...)
	cov.Domains = domains

	if maxNames > 0 && len(domains) > maxNames {
		return nil, fmt.Errorf(
			"%w: certificate %q needs %d names (%d declared, %d covered by wildcards), max is %d; "+
				"declare a wildcard for one of the busier sub-namespaces, or move some names to another group",
			ErrTooManyNames, g.Name, len(domains), len(g.Names)+len(g.Wildcards),
			len(cov.Covered), maxNames)
	}
	return cov, nil
}

// WildcardCovers 报告通配符 wc 是否覆盖 host。
//
// 只覆盖**一层**标签：*.example.com 覆盖 foo.example.com，
// 但不覆盖 example.com（这是最常见的误解），也不覆盖 a.b.example.com。
func WildcardCovers(wc, host string) bool {
	if !IsWildcard(wc) {
		return false
	}
	parent := Base(wc)
	if host == parent {
		return false
	}
	rest, ok := strings.CutSuffix(host, "."+parent)
	if !ok {
		return false
	}
	return rest != "" && !strings.Contains(rest, ".")
}

func appendUnique(dst []string, v string) []string {
	for _, x := range dst {
		if x == v {
			return dst
		}
	}
	return append(dst, v)
}
