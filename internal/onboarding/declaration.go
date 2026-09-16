package onboarding

import (
	"fmt"
	"strings"

	"github.com/susunola/wecert/internal/group"
)

// DeclarationPrefix 是声明的记录名前缀。
//
// 为什么把声明做成 DNS 记录而不是让 wecert 去枚举 DNS 记录推断意图：
// DNS zone 本来就是这个系统的信任根 —— 谁能写这个 zone，谁本来就能为
// 其中任何名字做 DNS-01 验证、从任何 CA 拿到证书。把声明也放在这里，
// 没有引入新的信任边界，只是把已经存在的能力显式化。
//
// 反过来，"DNS 里有记录就签"是明确不做的：zone 里 MX/TXT/SPF/各种验证
// 记录全在里面，DNS 记录 ≠ 想要证书。授权必须是一个明确的动作。
const DeclarationPrefix = "_wecert."

// DeclarationVersion 是声明格式的版本号，写成 v=wecert1。
const DeclarationVersion = "wecert1"

// Declaration 是一条 _wecert TXT 声明解析后的结果。
type Declaration struct {
	// Hostname 是声明要证书的名字：记录名剥掉 _wecert. 前缀之后的部分。
	Hostname string

	// Wildcard 表示同时声明 *.<Hostname>。
	//
	// 通配符必须是显式声明的：加一张 *.example.com 意味着证书能对
	// 任意子域完成握手，那是权限扩张，不该由分组逻辑替人决定。
	Wildcard bool

	// 以下三项是可选的覆盖，留空表示沿用 onboarding 的默认值。
	Profile string
	KeyType string
	Deploy  *bool

	// Zone 与 Record 只用于报告和排障。
	Zone   string
	Record string
}

// Names 返回这条声明贡献的所有名字，含通配符展开。
func (d *Declaration) Names() []string {
	out := make([]string, 0, 2)
	out = append(out, d.Hostname)
	if d.Wildcard {
		out = append(out, "*."+d.Hostname)
	}
	return out
}

// ParseDeclaration 把一条 _wecert.* TXT 记录解析成声明。
//
// 未知的键一律报错而不是忽略。理由很直接：`wildard=1` 这种拼写错误
// 如果被静默忽略，结果是"声明了通配符但没生效"，而人会以为它生效了 ——
// 这类沉默的偏差比一条清晰的报错昂贵得多。
func ParseDeclaration(zone, record string, values []string) (*Declaration, error) {
	full := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record)), ".")
	if !strings.HasPrefix(full, DeclarationPrefix) {
		return nil, fmt.Errorf("record %q does not start with %q", record, DeclarationPrefix)
	}

	host, err := group.Normalize(strings.TrimPrefix(full, DeclarationPrefix))
	if err != nil {
		return nil, fmt.Errorf("record %q: %w", record, err)
	}
	if group.IsWildcard(host) {
		return nil, fmt.Errorf("record %q: the name after %q must not itself be a wildcard; use wildcard=1 instead",
			record, DeclarationPrefix)
	}

	d := &Declaration{Hostname: host, Zone: zone, Record: full}
	given := make(map[string]string)

	for _, v := range values {
		for _, field := range splitFields(v) {
			key, val, hasValue := strings.Cut(field, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			val = strings.TrimSpace(val)

			if key == "" {
				continue
			}
			if !hasValue {
				// 裸 `v=wecert1` 之外的裸字段没有意义，只有版本号自己允许省略。
				if key != DeclarationVersion {
					return nil, fmt.Errorf("record %q: field %q is neither key=value nor the bare version marker %q",
						record, field, DeclarationVersion)
				}
				continue
			}
			if prev, dup := given[key]; dup && prev != val {
				return nil, fmt.Errorf("record %q: key %q is given twice with different values (%q and %q)",
					record, key, prev, val)
			}
			given[key] = val

			switch key {
			case "v":
				if val != DeclarationVersion {
					return nil, fmt.Errorf("record %q: unsupported declaration version %q (want %q)",
						record, val, DeclarationVersion)
				}
			case "wildcard":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("record %q: wildcard: %w", record, err)
				}
				d.Wildcard = b
			case "profile":
				d.Profile = val
			case "keytype":
				d.KeyType = val
			case "deploy":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("record %q: deploy: %w", record, err)
				}
				d.Deploy = &b
			default:
				return nil, fmt.Errorf("record %q: unknown key %q "+
					"(known: v, wildcard, profile, keytype, deploy); "+
					"a typo here would silently do nothing, so it is rejected instead", record, key)
			}
		}
	}
	return d, nil
}

// splitFields 把 TXT 内容切成一个个字段。
//
// 同时接受空格、逗号和分号分隔：DNS 控制台里手敲 TXT 的人不会记得
// 该用哪个，多一种分隔符的成本远低于"声明没生效"的排障成本。
func splitFields(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	if v == "" {
		return nil
	}
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("want 1/0, true/false, yes/no or on/off, got %q", v)
}
