// Package onboarding 是"推断意图"的那一半。
//
// 它枚举声明、套用分组策略与各种熔断，最后写出一份期望状态文档。
// wecert 只读那份文档，不做任何推断。
//
// 这条边界是刻意的：这个系统所有已知的坑（限速、误删、状态漂移）
// 都出在"判断"上，而判断逻辑必然会反复改 —— 加来源、调阈值、修边界。
// 证书生命周期必须稳，所以推断必须待在它自己的组件里，
// 而且要能整个丢掉重写而不影响签发。
//
// 五条不许破的不变量，对应到代码里的位置：
//
//	5.1 来源失败 ≠ 名字消失    → run.gather 里的 sourceErr 分支
//	5.2 期望状态骤变熔断        → run.fuse
//	5.3 删除比增加保守一个量级  → run.resolve 的宽限期与引用检查
//	5.4 配额熔断               → run.budget
//	5.5 显式授权               → Declaration 本身 + Options.Allowlist
package onboarding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/spec"
)

// Report 的处置结果。
const (
	// ModeWritten：期望状态变了，文档已写出。
	ModeWritten = "written"

	// ModeUnchanged：算出来的期望状态与上一版逐字节等价（指纹相同），
	// 文档仍然重写一次以刷新 generatedAt —— 那是 onboarding 的存活信号，
	// 不刷新会让 wecert 侧的"文档太旧"告警误报。
	ModeUnchanged = "unchanged"

	// ModeFrozen：这一轮没有可信的结论，保持上一版不动。
	ModeFrozen = "frozen"
)

// DeclarationLister 枚举 DNS 里所有 _wecert.* 声明。
type DeclarationLister interface {
	// ListDeclarations 返回所有声明。
	//
	// 返回 error 的语义是"这一轮没能完整读到"，而不是"没有声明"。
	// 这两者必须区别对待：前者要冻结，后者才可能是真的空。
	// 把它们混起来的后果是把一次接口抖动读成"域名全没了"。
	ListDeclarations(ctx context.Context) ([]RawDeclaration, error)
}

// RawDeclaration 是一条还没解析的 TXT 记录。
type RawDeclaration struct {
	// Zone 是这条记录所在的 DNS zone，仅用于报告。
	Zone string

	// Record 是完整记录名，形如 _wecert.api.example.com。
	Record string

	// Values 是该名字下所有 TXT 记录的值。
	Values []string
}

// RuleLister 枚举已配置的七层域名。
type RuleLister interface {
	// ListRuleDomains 返回所有 CLB 规则上配置的域名。
	//
	// 它是**守卫**不是来源：只负责否掉已经声明的意图，不负责推断意图。
	// 作为来源它要承担推断的全部风险；作为守卫，它的失败模式安全得多 ——
	// 最坏情况是"该签的没签"，而不是"不该删的删了"。
	ListRuleDomains(ctx context.Context) ([]string, error)
}

// Sources 是 onboarding 需要的外部来源。
type Sources struct {
	// Declarations 枚举 _wecert 声明。必需。
	Declarations DeclarationLister

	// Rules 枚举 CLB 规则域名。可选，但强烈建议开启：
	// 它是唯一能挡住"DNS 里声明了、但规则还没配好"的守卫。
	Rules RuleLister
}

// Options 是 onboarding 的策略参数。
//
// 这些默认值刻意偏保守。文档 §8 说得很清楚：去抖窗口、分组上限、骤变阈值
// 只能从真实漂移数据里来，猜错的代价是账号级的限速。
// 所以先跑 observe 攒数据，再调这里。
type Options struct {
	// DocumentPath 是期望状态文档的写入路径。
	DocumentPath string

	// StatePath 是 onboarding 自己的状态文件的路径。
	//
	// 留空表示不落盘 —— 那会把删除宽限期降级成"每次运行都从头算"，
	// 也就是宽限期永远走不完。只适合一次性排障。
	StatePath string

	// ReportPath 是决策报告的写入路径（JSON）。留空表示不写报告。
	ReportPath string

	// Generator 是写进文档的生成者标识，形如 wecert-onboard/v0.5.0。
	Generator string

	// Profile / KeyType / Deploy 是没有被声明覆盖时的默认值。
	Profile string
	KeyType string
	Deploy  bool

	// MaxNames 是单证书 SAN 上限。0 表示用 profile 自己的上限。
	MaxNames int

	// RequireRule 表示声明必须同时有 CLB 规则才生效（守卫 1 必需）。
	//
	// 打开它会挡住两类真问题：声明写了但规则还没配（会造成一次无用的签发），
	// 以及拼错的域名（规则里根本不存在）。
	RequireRule bool

	// Allowlist 限定允许签发证书的注册域。空表示不限制。
	//
	// 这是 §5.5 的护栏：来源只提供线索，授权必须是一个明确的动作。
	// 只对指定 registered domain 生效，能挡住"某个脚本批量写了 500 条
	// 声明"这类事故的辐射范围。
	Allowlist []string

	// DropThreshold 是骤变熔断阈值：名字集合一次掉超过这个比例就冻结。
	// 0 表示用 DefaultDropThreshold。
	DropThreshold float64

	// GracePeriod 是删除宽限期。0 表示用 DefaultGracePeriod。
	//
	// 删除比增加危险一个量级：增加错了只是多签一张，删除错了是线上握手失败。
	GracePeriod time.Duration

	// BudgetWindow / Budget 是配额预算：窗口内最多允许几次名字集合变更。
	// Budget 为 0 表示用 DefaultBudget。
	BudgetWindow time.Duration
	Budget       int

	// Force 跳过骤变熔断、配额预算和删除宽限期，直接按这一轮算出来的结果写。
	//
	// 它的存在是为了让"这次的骤变确实是我干的"有一个出口。
	// 但它必须是由人敲出来的显式动作 —— 自动化流程里绝不能带上它，
	// 否则这道闸门就等于不存在。
	Force bool

	// Now 可注入，便于测试。
	Now func() time.Time
}

// 默认值。都偏保守，理由见 Options 的注释。
const (
	DefaultDropThreshold = 0.30
	DefaultGracePeriod   = 24 * time.Hour
	DefaultBudgetWindow  = 7 * 24 * time.Hour
	DefaultBudget        = 25
)

// Onboarder 把来源求值成一份期望状态。
type Onboarder struct {
	src  Sources
	opts Options
	log  *slog.Logger
}

// New 构造 onboarding 器。
func New(src Sources, opts Options, log *slog.Logger) (*Onboarder, error) {
	if src.Declarations == nil {
		return nil, errors.New("onboarding: a declaration source is required")
	}
	if opts.DocumentPath == "" {
		return nil, errors.New("onboarding: DocumentPath is required")
	}
	if opts.Profile == "" {
		opts.Profile = config.ProfileClassic
	}
	if opts.KeyType == "" {
		opts.KeyType = config.KeyTypeECDSAP256
	}
	if opts.MaxNames <= 0 {
		opts.MaxNames = 25 // 与 tlsserver 对齐，将来切 profile 不用改架构。
	}
	if opts.DropThreshold <= 0 {
		opts.DropThreshold = DefaultDropThreshold
	}
	if opts.GracePeriod <= 0 {
		opts.GracePeriod = DefaultGracePeriod
	}
	if opts.BudgetWindow <= 0 {
		opts.BudgetWindow = DefaultBudgetWindow
	}
	if opts.Budget <= 0 {
		opts.Budget = DefaultBudget
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}

	// 允许清单也做一次注册域归一，免得有人写 "www.example.com" 却以为
	// 它会匹配整片 example.com。
	if len(opts.Allowlist) > 0 {
		for i, a := range opts.Allowlist {
			opts.Allowlist[i] = group.RegisteredDomain(strings.ToLower(strings.TrimSpace(a)))
		}
	}
	return &Onboarder{src: src, opts: opts, log: log}, nil
}

// Report 是一轮 onboarding 的完整结果，也是给人看的那一份。
type Report struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Generator   string    `json:"generator"`
	Mode        string    `json:"mode"`

	// FreezeReasons 说明为什么冻结。非空即表示这一轮没有可信结论。
	FreezeReasons []string `json:"freezeReasons,omitempty"`

	// GuardUnavailable 表示 CLB 守卫这一轮不可用。这一轮不做删除决策。
	GuardUnavailable bool `json:"guardUnavailable,omitempty"`

	Declared          int `json:"declared"`
	Included          int `json:"included"`
	CoveredByWildcard int `json:"coveredByWildcard"`
	CarriedForward    int `json:"carriedForward"`
	Certificates      int `json:"certificates"`

	Revision         string          `json:"revision,omitempty"`
	PreviousRevision string          `json:"previousRevision,omitempty"`
	Decisions        []spec.Decision `json:"decisions"`

	// Document 是这一轮算出来的期望状态。冻结时仍可能是上一版（用于排查），
	// 但 Commit 不会写它。
	Document *spec.Document `json:"-"`

	// State 是这一轮之后应该落盘的状态。
	State *State `json:"-"`
}

// Frozen 报告这一轮是否冻结。
func (r *Report) Frozen() bool { return r.Mode == ModeFrozen }

// Run 求值一轮，不写任何文件。
func (o *Onboarder) Run(ctx context.Context) (*Report, error) {
	now := o.opts.Now()
	r := &run{
		o:   o,
		now: now,
		rep: &Report{
			GeneratedAt: now,
			Generator:   o.opts.Generator,
			Mode:        ModeWritten,
		},
	}

	// 状态文件坏了要直接失败，不能当空状态继续：那会把宽限期归零，
	// 也就是把删除从保守路径变成激进路径。
	st, err := o.loadState()
	if err != nil {
		return nil, err
	}
	r.st = st
	r.rep.State = st

	r.loadPrevious()
	r.gather(ctx)

	// 顺序是有意的：先按原始声明判骤变，再套守卫和宽限期。
	// 反过来会把"我们自己的过滤"误判成"上游塌了"。
	if !r.rep.Frozen() {
		r.fuse()
	}
	if !r.rep.Frozen() {
		r.resolve()
	}
	if !r.rep.Frozen() {
		r.build()
	}
	// 空期望状态一律拒绝写盘。
	//
	// "合法的空"和"生成失败导致的空"在文件里长得一模一样，而后者一旦被接受，
	// 后果是每张证书的每个域名都被摘掉。这个风险太不对称，
	// 所以"真的想全部拆掉"只能由人显式地、吵闹地去做。
	if !r.rep.Frozen() && len(r.certs) == 0 {
		r.freeze("the desired state came out empty: an empty document is indistinguishable " +
			"from a failed generation, and acting on it would strip every name from every certificate; " +
			"to tear everything down, remove the declarations and stop renewing by hand")
	}
	if !r.rep.Frozen() {
		r.budget()
	}
	if !r.rep.Frozen() {
		r.assemble()
	}

	sortDecisions(r.rep.Decisions)
	return r.rep, nil
}

// Commit 落盘：期望状态文档、决策报告、onboarding 状态。
//
// 冻结时只写报告 —— 报告正是用来告诉人"这一轮为什么没动"的。
func (o *Onboarder) Commit(rep *Report) error {
	if o.opts.ReportPath != "" {
		if err := writeJSONAtomic(o.opts.ReportPath, rep); err != nil {
			return err
		}
	}
	if rep.Frozen() {
		// 冻结时状态一律不动：AbsentSince 会被推进，而这一轮我们
		// 并不知道名字到底还在不在。推进它等于用噪声缩短宽限期。
		return nil
	}

	if err := spec.WriteDocument(o.opts.DocumentPath, rep.Document); err != nil {
		return err
	}
	if o.opts.StatePath != "" {
		if err := rep.State.Save(o.opts.StatePath); err != nil {
			return err
		}
	}
	return nil
}

// run 承载一轮求值的中间状态。
type run struct {
	o   *Onboarder
	now time.Time

	rep *Report
	st  *State

	// prev 是上一版文档，冻结时作为回退目标。可能为 nil（第一次跑）。
	prev *spec.Document

	// guardUnavailable 表示 CLB 守卫这一轮读不到。
	// 一旦为真，这一轮**不做任何删除决策** —— 见 §9"不在来源不可用时降级"。
	guardUnavailable bool

	// rules 是 CLB 规则上的域名集合。名字原样保留（可能含通配符）。
	rules map[string]bool

	// declarations 是解析成功的声明，按 hostname 排序。
	declarations []*Declaration

	// reasons 记录每个展开名字为什么在/不在最终集合里。
	reasons map[string]string

	// eligible 是通过了允许清单与守卫的展开名字集合。
	eligible map[string]bool

	// certs 是这一轮算出来的证书，按证书名排序。
	certs []config.Certificate
}

func (o *Onboarder) loadState() (*State, error) {
	if o.opts.StatePath == "" {
		return &State{AbsentSince: map[string]time.Time{}}, nil
	}
	return LoadState(o.opts.StatePath)
}

// loadPrevious 读上一版文档。
//
// 读不到不是错误：第一次跑本来就没有。但如果文件存在却解析不了，
// 那是"上一版已经烂了"，必须说出来 —— 它意味着这一轮没有回退目标。
func (r *run) loadPrevious() {
	doc, err := spec.LoadDocument(r.o.opts.DocumentPath)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			return
		}
		r.o.log.Warn("previous desired-state document is unusable; there is no freeze target this round",
			"path", r.o.opts.DocumentPath, "err", err)
		return
	}
	r.prev = doc
	r.rep.PreviousRevision = doc.Revision
}

// gather 拿声明和守卫。
//
// §5.1 的落点：声明来源报错时，正确答案是**保持现状**，不是"期望为空"。
// 期望状态一旦塌掉，wecert 会重签一张不含域名的证书、或者把域名从证书里
// 摘掉，线上立刻握手失败 —— 这比不签发严重得多。
func (r *run) gather(ctx context.Context) {
	raw, err := r.o.src.Declarations.ListDeclarations(ctx)
	if err != nil {
		r.freeze(fmt.Sprintf("declaration source failed: %v", err))
		return
	}

	r.parse(raw)
	if r.rep.Frozen() {
		return
	}

	r.loadRules(ctx)
}

// loadRules 读 CLB 守卫。
func (r *run) loadRules(ctx context.Context) {
	r.rules = map[string]bool{}
	if r.o.src.Rules == nil {
		if r.o.opts.RequireRule {
			r.freeze("guards.requireCLBRule is on but no CLB rule source is configured")
		}
		return
	}

	domains, err := r.o.src.Rules.ListRuleDomains(ctx)
	if err != nil {
		// 守卫坏了不等于"规则都不在了"。
		//
		// §9 明确不做"来源不可用时降级成单来源"：降级会让安全性随故障一起消失，
		// 而你恰好在那时最需要它。所以一律冻结判断 —— 具体表现是
		// 这一轮不做任何删除，且守卫当"通过"处理（保守方向是保留）。
		r.guardUnavailable = true
		r.rep.GuardUnavailable = true
		r.o.log.Warn("CLB rule guard is unavailable this round; no name will be removed and the guard is treated as satisfied",
			"err", err)
		return
	}

	for _, d := range domains {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if n != "" {
			r.rules[n] = true
		}
	}
}

// parse 把原始 TXT 记录解析成声明。
//
// 解析不了的记录不参与期望状态，但要留下决策条目：静默丢弃一条声明
// 会让人对着 DNS 控制台怀疑人生。
func (r *run) parse(raw []RawDeclaration) {
	r.reasons = map[string]string{}
	byHost := map[string]*Declaration{}
	byHostRecord := map[string]string{}

	for _, rec := range raw {
		d, err := ParseDeclaration(rec.Zone, rec.Record, rec.Values)
		if err != nil {
			r.reject(hostnameFromRecord(rec.Record), fmt.Sprintf("unparseable declaration: %v", err))
			continue
		}
		if prev, dup := byHost[d.Hostname]; dup {
			// 同一个 hostname 有两条声明：允许，但元数据必须一致。
			// 不一致说明有人在两个 zone 里写了互相矛盾的东西，此时
			// 猜哪条对都是错的。
			if prev.Wildcard != d.Wildcard || prev.Profile != d.Profile ||
				prev.KeyType != d.KeyType || !sameBoolPtr(prev.Deploy, d.Deploy) {
				r.reject(d.Hostname, fmt.Sprintf(
					"conflicting declarations for the same name (%s and %s): they disagree on wildcard/profile/keytype/deploy",
					byHostRecord[d.Hostname], d.Record))
				delete(byHost, d.Hostname)
				delete(byHostRecord, d.Hostname)
				continue
			}
			continue
		}
		byHost[d.Hostname] = d
		byHostRecord[d.Hostname] = d.Record
	}

	r.declarations = r.declarations[:0]
	for _, d := range byHost {
		r.declarations = append(r.declarations, d)
	}
	sort.Slice(r.declarations, func(i, j int) bool {
		return r.declarations[i].Hostname < r.declarations[j].Hostname
	})

	// 展开后的声明名字数，供报告与骤变熔断使用。
	seen := make(map[string]bool, len(r.declarations)*2)
	for _, d := range r.declarations {
		for _, n := range d.Names() {
			seen[n] = true
		}
	}
	r.rep.Declared = len(seen)
}

// reject 记一条"这个名字被排除了"的决策。
func (r *run) reject(hostname, reason string) {
	r.rep.Decisions = append(r.rep.Decisions, spec.Decision{
		Hostname: hostname,
		Included: false,
		Reason:   reason,
	})
}

// hostnameFromRecord 尽力从记录名里取出人认识的那个名字。
//
// 报告里出现 "_wecert.bad.example.com" 而不是 "bad.example.com" 看起来是小事，
// 但报告是给人排障用的：让人在脑子里做一次字符串裁剪，就是在往
// "我明明加了域名怎么没签"这个问题上再糊一层。
func hostnameFromRecord(record string) string {
	full := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record)), ".")
	if !strings.HasPrefix(full, DeclarationPrefix) {
		return record
	}
	return strings.TrimPrefix(full, DeclarationPrefix)
}

// fuse 是 §5.2：期望状态骤变熔断。
//
// 比较的是**声明集合本身**，而不是经过守卫和分组之后的结果。
// 因为这里要抓的是"上游返回不完整"，而守卫过滤、宽限期、分组失败
// 引起的缩小都是我们自己的、有记录的决定。
//
// 正常的一次下线不会让声明少三成。突然少三成，几乎一定是上游出了问题
// （API 返回不完整、权限被改、zone 读失败）。这种情况下照做的后果是
// 批量摘除 SAN。冻结比执行安全。
func (r *run) fuse() {
	if r.o.opts.Force {
		return
	}

	prev := r.st.LastNameSet()
	if len(prev) == 0 {
		return // 没有基线可比，第一次跑就该正常写出。
	}

	now := make(map[string]bool, r.rep.Declared)
	for _, d := range r.declarations {
		for _, n := range d.Names() {
			now[n] = true
		}
	}

	lost := 0
	for n := range prev {
		if !now[n] {
			lost++
		}
	}
	if lost == 0 {
		return
	}

	ratio := float64(lost) / float64(len(prev))
	if ratio <= r.o.opts.DropThreshold {
		return
	}

	r.freeze(fmt.Sprintf(
		"the declared name set dropped from %d to %d (%.0f%%, threshold %.0f%%): "+
			"this is almost always an upstream failure rather than a real decommission, "+
			"so nothing was changed; pass -force if the drop is intentional",
		len(prev), len(now), ratio*100, r.o.opts.DropThreshold*100))
}

// resolve 套用允许清单、守卫 1 和删除宽限期，得到最终要覆盖的名字集合。
func (r *run) resolve() {
	r.eligible = make(map[string]bool, len(r.declarations)*2)

	for _, d := range r.declarations {
		if !r.allowed(d.Hostname) {
			for _, n := range d.Names() {
				r.reject(n, fmt.Sprintf("registered domain %q is not in the allowlist",
					group.RegisteredDomain(d.Hostname)))
			}
			continue
		}

		// 守卫 1 只作用于具体名字：通配符本来就不会出现在七层规则的域名里，
		// 拿它去要求一条规则等于永远不通过。
		if r.o.opts.RequireRule && !r.guardUnavailable && !r.rules[d.Hostname] {
			r.reject(d.Hostname, "no CLB rule serves this name (guard 1 not satisfied)")
			continue
		}

		for _, n := range d.Names() {
			r.eligible[n] = true
		}
	}

	// 骤变熔断要在 eligible 之前判断，所以放在 Run 里 parse 之后单独调用。
	// 这里只看"上一版有、这一轮不合格"的名字。
	r.applyGrace()
}

func (r *run) allowed(hostname string) bool {
	if len(r.o.opts.Allowlist) == 0 {
		return true
	}
	reg := group.RegisteredDomain(hostname)
	i := sort.SearchStrings(r.o.opts.Allowlist, reg)
	return i < len(r.o.opts.Allowlist) && r.o.opts.Allowlist[i] == reg
}

// applyGrace 是 §5.3：删除比增加保守一个量级。
//
// 增加是收敛，删除是决策。双来源的结构天然会让状态抖动：
//
//	t0: 加 _wecert 声明        → 守卫未就绪，不签    正确
//	t1: 加 CLB 规则            → 签发                正确
//	t2: DNS 查询抖一下          → 若立刻删 → 重签     ✗ 白烧配额
//	t3: DNS 恢复               → 又重签              ✗ 再烧一次
//
// 所以删除必须同时满足：所有来源都确认缺失、持续缺失超过宽限期、
// 且没有别的资源还在引用它。
func (r *run) applyGrace() {
	// 先给"这一轮声明里真的还在"的名字拍个快照。
	//
	// 必须在 carry 之前拍：carry 会把上一版的名字塞回 eligible，
	// 而对那些名字清掉缺席标记等于每次都把宽限期重置 —— 宽限期就永远走不完，
	// 删除路径形同虚设。
	present := make(map[string]bool, len(r.eligible))
	for n := range r.eligible {
		present[n] = true
	}

	absent := make([]string, 0)
	for n := range r.st.LastNameSet() {
		if !r.eligible[n] {
			absent = append(absent, n)
		}
	}
	sort.Strings(absent)

	for _, n := range absent {
		since, _ := r.st.MarkAbsent(n, r.now)
		age := r.now.Sub(since)

		switch {
		case r.o.opts.Force:
			r.reject(n, "removed: -force was used, so the grace period and the reference check were skipped")

		case r.guardUnavailable:
			// 守卫读不到的时候连"还在不在服务"都答不了，此时删除是没有依据的。
			r.carry(n, fmt.Sprintf("was declared before but the guard is unavailable; "+
				"keeping it for now (absent for %s)", humanDuration(age)))

		case age < r.o.opts.GracePeriod:
			r.carry(n, fmt.Sprintf("no longer declared, but only absent for %s (grace period %s); "+
				"a declaration can flap, and a flap would otherwise cost two issuances",
				humanDuration(age), humanDuration(r.o.opts.GracePeriod)))

		case r.referenced(n):
			r.carry(n, fmt.Sprintf("no longer declared and absent for %s, but a CLB rule still references it",
				humanDuration(age)))

		default:
			// 确认缺失 + 超过宽限期 + 没人引用 —— 三个条件都满足才允许移除。
			r.reject(n, fmt.Sprintf("removed: confirmed absent for %s, past the %s grace period, "+
				"and no CLB rule references it", humanDuration(age), humanDuration(r.o.opts.GracePeriod)))
		}
	}

	// 这一轮真的出现的名字清掉缺席标记：它回来了，宽限期就该重置。
	for n := range present {
		r.st.MarkPresent(n)
	}
}

// carry 把上一版有、这一轮没合格的名字保留进最终集合。
//
// 保留意味着 wecert 继续按它收敛 —— 域名留在证书里，什么都不会断。
// 这是所有"说不清"的情况下唯一安全的默认动作。
func (r *run) carry(name, reason string) {
	r.eligible[name] = true
	r.reasons[name] = reason
	r.rep.CarriedForward++
}

// referenced 报告名字是否还被某个 CLB 规则引用。
//
// 守卫不可用时一律当成"还被引用"：保守方向是保留，不是删除。
func (r *run) referenced(name string) bool {
	if r.guardUnavailable || r.o.src.Rules == nil {
		return true
	}
	if r.rules[name] {
		return true
	}

	if group.IsWildcard(name) {
		for rd := range r.rules {
			if group.WildcardCovers(name, rd) {
				return true
			}
		}
		return false
	}
	for rd := range r.rules {
		if group.IsWildcard(rd) && group.WildcardCovers(rd, name) {
			return true
		}
	}
	return false
}

// build 分组并算出每张证书的 SAN。
func (r *run) build() {
	names := make([]string, 0, len(r.eligible))
	for n := range r.eligible {
		names = append(names, n)
	}
	sort.Strings(names)
	r.rep.Included = len(names)

	groups, err := group.GroupBy(names)
	if err != nil {
		// 走到这里说明有名字没通过 group.Normalize —— 而声明早就校验过了。
		// 唯一可能是状态里残留了一个已经不合法（比如规则收紧）的名字。
		r.freeze(fmt.Sprintf("cannot group the declared names: %v", err))
		return
	}

	for _, g := range groups {
		cov, err := g.Cover(r.o.opts.MaxNames)
		if err != nil {
			if errors.Is(err, group.ErrTooManyNames) {
				r.overLimit(g, err)
				continue
			}
			r.freeze(fmt.Sprintf("certificate %q: %v", g.Name, err))
			return
		}

		// 组内所有声明对元数据达成一致时用声明的值，否则沿用默认值并留下记录。
		// 让某个子域的声明悄悄改掉整张证书的属性，是那种事后没人能解释的变更。
		profile, keyType, deploy := r.groupSettings(g)

		r.certs = append(r.certs, config.Certificate{
			Name:    g.Name,
			Domains: cov.Domains,
			Profile: profile,
			KeyType: keyType,
			Deploy:  config.Deploy{Enabled: deploy},
		})

		for _, n := range append(append([]string(nil), g.Names...), g.Wildcards...) {
			reason := r.reasons[n]
			if coverer, ok := cov.Covered[n]; ok {
				reason = fmt.Sprintf("covered by the declared wildcard %s, so it costs no extra issuance", coverer)
				r.rep.CoveredByWildcard++
			} else if reason == "" {
				reason = "declared via a " + DeclarationPrefix + " TXT record"
				if r.o.opts.RequireRule && !group.IsWildcard(n) {
					reason += " and served by a CLB rule"
				}
			}
			r.rep.Decisions = append(r.rep.Decisions, spec.Decision{
				Hostname:    n,
				Included:    true,
				Reason:      reason,
				Certificate: g.Name,
			})
		}
	}
}

// overLimit 处理超过 SAN 上限的组。
//
// 不能把整组丢掉：那会让 wecert 看到一张证书凭空消失。
// 正确反应是保留上一版的那张证书，并把原因喊出来 ——
// 修复动作（加一条通配符声明，或把名字挪到别的组）只能由人来做。
func (r *run) overLimit(g group.Group, cause error) {
	all := append(append([]string(nil), g.Names...), g.Wildcards...)

	if prev := r.previousCert(g.Name); prev != nil {
		r.certs = append(r.certs, *prev)
		for _, n := range all {
			r.rep.Decisions = append(r.rep.Decisions, spec.Decision{
				Hostname:    n,
				Included:    true,
				Reason:      fmt.Sprintf("kept at the previous revision: %v", cause),
				Certificate: g.Name,
			})
		}
		r.rep.CarriedForward += len(all)
		return
	}

	for _, n := range all {
		r.reject(n, fmt.Sprintf("cannot be expressed: %v", cause))
	}
}

func (r *run) previousCert(name string) *config.Certificate {
	if r.prev == nil {
		return nil
	}
	for i := range r.prev.Certificates {
		if r.prev.Certificates[i].Name == name {
			return &r.prev.Certificates[i]
		}
	}
	return nil
}

// groupSettings 汇总组内声明的元数据。
func (r *run) groupSettings(g group.Group) (profile, keyType string, deploy bool) {
	profile, keyType, deploy = r.o.opts.Profile, r.o.opts.KeyType, r.o.opts.Deploy

	for _, d := range r.declarations {
		if group.RegisteredDomain(d.Hostname) != g.Registered {
			continue
		}
		if d.Profile != "" {
			profile = d.Profile
		}
		if d.KeyType != "" {
			keyType = d.KeyType
		}
		if d.Deploy != nil {
			deploy = *d.Deploy
		}
	}
	return profile, keyType, deploy
}

// budget 是 §5.4：配额熔断。
//
// 域名集合变化**不算同名续期**，实打实消耗
// "Certificates per Registered Domain"（50 / 7 天，跨账号共享）。
// 留一半余量，默认预算 25 次/周；超了就冻结并告警，
// 而不是替使用者把配额赌进去。
func (r *run) budget() {
	rev := spec.Revision(r.certs)
	r.rep.Revision = rev

	changed := rev != r.st.LastRevision
	if !changed {
		r.rep.Mode = ModeUnchanged
		return
	}

	if r.o.opts.Force {
		r.st.RecordChange(r.now)
		return
	}

	used := r.st.ChangesWithin(r.o.opts.BudgetWindow, r.now)
	if used >= r.o.opts.Budget {
		r.freeze(fmt.Sprintf(
			"the change budget is exhausted: %d name-set changes in the last %s (budget %d); "+
				"Let's Encrypt allows 50 new certificates per registered domain per 7 days, shared across accounts, "+
				"and burning the whole allowance on configuration churn is how an account gets rate limited",
			used, humanDuration(r.o.opts.BudgetWindow), r.o.opts.Budget))
		return
	}

	r.st.RecordChange(r.now)
}

// assemble 组装文档与状态。
func (r *run) assemble() {
	names := make([]string, 0, len(r.eligible))
	for n := range r.eligible {
		names = append(names, n)
	}
	sort.Strings(names)

	r.rep.Certificates = len(r.certs)
	r.st.SetLastNames(names)
	r.st.LastRevision = r.rep.Revision
	r.st.UpdatedAt = r.now

	r.rep.Document = &spec.Document{
		APIVersion:   spec.APIVersionV1,
		Kind:         spec.KindDesiredState,
		GeneratedAt:  r.now,
		Generator:    r.o.opts.Generator,
		Revision:     r.rep.Revision,
		Certificates: r.certs,
	}
}

// freeze 把这一轮标记为冻结，并记下原因。
func (r *run) freeze(reason string) {
	r.rep.Mode = ModeFrozen
	r.rep.FreezeReasons = append(r.rep.FreezeReasons, reason)
	r.o.log.Warn("freezing: keeping the previous desired state", "reason", reason)

	// 冻结时仍然把上一版文档挂出来，方便调用方和报告展示"没动的是什么"。
	if r.prev != nil {
		cp := *r.prev
		r.rep.Document = &cp
		r.rep.Revision = r.prev.Revision
	}
}

func sameBoolPtr(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	if d < time.Hour {
		return d.Round(time.Minute).String()
	}
	return d.Round(time.Hour).String()
}

// sortDecisions 让报告顺序稳定：先按是否包含，再按名字。
//
// 报告是要被人 diff 的，顺序不稳定等于没法看。
func sortDecisions(ds []spec.Decision) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Hostname != ds[j].Hostname {
			return ds[i].Hostname < ds[j].Hostname
		}
		return ds[i].Certificate < ds[j].Certificate
	})
}

func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".onboard-report-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	tmpName = ""
	return nil
}
