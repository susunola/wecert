package spec

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// ShadowReport 是"如果按影子来源来会怎样"的对比结果。
//
// 它是 observe 模式的全部产出：不签发、不删除，只回答
// "会加什么、会删什么、会改什么"。
type ShadowReport struct {
	Revision    string    `json:"revision,omitempty"`
	GeneratedAt time.Time `json:"generatedAt,omitempty"`

	// Error 非空表示影子来源这一轮读不到，因此没有对比结果。
	Error string `json:"error,omitempty"`

	AddCertificates    []string            `json:"addCertificates,omitempty"`
	RemoveCertificates []string            `json:"removeCertificates,omitempty"`
	ChangeCertificates []CertificateChange `json:"changeCertificates,omitempty"`

	AddedDomains   int `json:"addedDomains"`
	RemovedDomains int `json:"removedDomains"`
}

// CertificateChange 描述同一张证书的域名集合变化。
type CertificateChange struct {
	Name    string   `json:"name"`
	Added   []string `json:"addedDomains,omitempty"`
	Removed []string `json:"removedDomains,omitempty"`
	Changed []string `json:"changedFields,omitempty"`
}

// Empty 报告影子来源与正在执行的状态是否一致。
func (s *ShadowReport) Empty() bool {
	if s == nil {
		return false // 没有对比结果，不能声称"一致"。
	}
	return s.Error == "" &&
		len(s.AddCertificates) == 0 && len(s.RemoveCertificates) == 0 && len(s.ChangeCertificates) == 0
}

// Observer 包装一个主来源，同时读一份影子来源并报告差异。
//
// 这是从 static 迁到 enforce 之间的必经阶段，而且它**不改变任何行为**：
// 收敛照旧走 primary，影子只用来产生报告。
//
// 文档 §8 把这一步单独拎出来，是因为直接上自动签发会在完全不了解
// 真实漂移形态的情况下把配额赌进去：去抖窗口该多大、有没有批量导入、
// 有没有奇怪的记录，这些只能从几周的真实数据里来。
type Observer struct {
	primary Provider
	shadow  Provider
	log     *slog.Logger
}

// NewObserver 构造观察器。
func NewObserver(primary, shadow Provider, log *slog.Logger) *Observer {
	if log == nil {
		log = slog.Default()
	}
	return &Observer{primary: primary, shadow: shadow, log: log}
}

// Kind 实现 Named。
func (o *Observer) Kind() string { return "observe(" + KindOf(o.primary) + ")" }

// Desired 实现 Provider，永远走主来源。
func (o *Observer) Desired(ctx context.Context) ([]config.Certificate, error) {
	return o.primary.Desired(ctx)
}

// DesiredWithReasons 在主来源的结果上挂一份影子对比。
//
// 影子来源出错**不会**让整个求值失败：观察阶段读不到文档是很正常的事
// （还没开始生成），此时正确的行为是照旧收敛，并把这个事实记下来。
func (o *Observer) DesiredWithReasons(ctx context.Context) (*Result, error) {
	res, err := Desired(ctx, o.primary)
	if err != nil {
		return nil, err
	}

	sh, err := Desired(ctx, o.shadow)
	if err != nil {
		res.Shadow = &ShadowReport{Error: err.Error()}
		o.log.Warn("cannot read the shadow desired state; there is nothing to compare against",
			"shadow", KindOf(o.shadow), "err", err)
		return res, nil
	}

	res.Shadow = Diff(res, sh)
	if !res.Shadow.Empty() {
		o.log.Warn("the shadow desired state differs from what is being enforced; "+
			"this is expected while observing -- switch desiredState.mode to \"enforce\" once the diff stays quiet",
			"shadowRevision", sh.Revision,
			"certificatesToAdd", len(res.Shadow.AddCertificates),
			"certificatesToRemove", len(res.Shadow.RemoveCertificates),
			"certificatesToChange", len(res.Shadow.ChangeCertificates))
	}
	return res, nil
}

// Diff 比较"正在执行的"和"影子来源的"期望状态。
func Diff(enforced, shadow *Result) *ShadowReport {
	rep := &ShadowReport{Revision: shadow.Revision, GeneratedAt: shadow.GeneratedAt}

	byName := func(r *Result) map[string]*config.Certificate {
		m := make(map[string]*config.Certificate, len(r.Certificates))
		for i := range r.Certificates {
			m[r.Certificates[i].Name] = &r.Certificates[i]
		}
		return m
	}
	cur, want := byName(enforced), byName(shadow)

	for name, w := range want {
		c, ok := cur[name]
		if !ok {
			rep.AddCertificates = append(rep.AddCertificates, name)
			rep.AddedDomains += len(w.Domains)
			continue
		}
		ch := diffCert(c, w)
		if ch != nil {
			rep.ChangeCertificates = append(rep.ChangeCertificates, *ch)
			rep.AddedDomains += len(ch.Added)
			rep.RemovedDomains += len(ch.Removed)
		}
	}
	for name := range cur {
		if _, ok := want[name]; !ok {
			rep.RemoveCertificates = append(rep.RemoveCertificates, name)
			rep.RemovedDomains += len(cur[name].Domains)
		}
	}

	sort.Strings(rep.AddCertificates)
	sort.Strings(rep.RemoveCertificates)
	sort.Slice(rep.ChangeCertificates, func(i, j int) bool {
		return rep.ChangeCertificates[i].Name < rep.ChangeCertificates[j].Name
	})
	return rep
}

func diffCert(cur, want *config.Certificate) *CertificateChange {
	ch := &CertificateChange{
		Name:    cur.Name,
		Added:   onlyIn(want.Domains, cur.Domains),
		Removed: onlyIn(cur.Domains, want.Domains),
	}
	if cur.Profile != want.Profile {
		ch.Changed = append(ch.Changed, "profile")
	}
	if cur.KeyType != want.KeyType {
		ch.Changed = append(ch.Changed, "keyType")
	}
	if cur.Deploy.Enabled != want.Deploy.Enabled {
		ch.Changed = append(ch.Changed, "deploy")
	}

	if len(ch.Added) == 0 && len(ch.Removed) == 0 && len(ch.Changed) == 0 {
		return nil
	}
	return ch
}

// onlyIn 返回在 a 里、不在 b 里的名字。
func onlyIn(a, b []string) []string {
	if len(a) == 0 {
		return nil
	}
	have := make(map[string]bool, len(b))
	for _, x := range b {
		have[x] = true
	}
	var out []string
	for _, x := range a {
		if !have[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
