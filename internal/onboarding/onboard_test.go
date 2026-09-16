package onboarding

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
)

// ── 测试替身 ────────────────────────────────────────────────────────────────

type fakeDeclarations struct {
	raw []RawDeclaration
	err error
}

func (f *fakeDeclarations) ListDeclarations(context.Context) ([]RawDeclaration, error) {
	return f.raw, f.err
}

type fakeRules struct {
	domains []string
	err     error
}

func (f *fakeRules) ListRuleDomains(context.Context) ([]string, error) {
	return f.domains, f.err
}

// clock 让宽限期和配额预算可以被测出来，而不是靠 sleep。
type clock struct{ t time.Time }

func newClock() *clock                   { return &clock{t: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)} }
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func decl(host string, values ...string) RawDeclaration {
	return RawDeclaration{Zone: "example.com", Record: DeclarationPrefix + host, Values: values}
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type harness struct {
	ob    *Onboarder
	decls *fakeDeclarations
	rules *fakeRules
	clock *clock
	opts  Options
}

func newHarness(t *testing.T, opts Options) *harness {
	t.Helper()

	dir := t.TempDir()
	if opts.DocumentPath == "" {
		opts.DocumentPath = filepath.Join(dir, "desired-state.yaml")
	}
	if opts.StatePath == "" {
		opts.StatePath = filepath.Join(dir, "onboard-state.json")
	}
	if opts.ReportPath == "" {
		opts.ReportPath = filepath.Join(dir, "report.json")
	}
	opts.Generator = "wecert-onboard/test"

	c := newClock()
	if opts.Now == nil {
		opts.Now = c.now
	}

	h := &harness{
		decls: &fakeDeclarations{},
		rules: &fakeRules{},
		clock: c,
		opts:  opts,
	}

	ob, err := New(Sources{Declarations: h.decls, Rules: h.rules}, opts, testLogger())
	if err != nil {
		t.Fatalf("构造 onboarding 失败: %v", err)
	}
	h.ob = ob
	return h
}

// run 跑一轮并落盘，返回报告。
func (h *harness) run(t *testing.T) *Report {
	t.Helper()
	rep, err := h.ob.Run(context.Background())
	if err != nil {
		t.Fatalf("Run 失败: %v", err)
	}
	if err := h.ob.Commit(rep); err != nil {
		t.Fatalf("Commit 失败: %v", err)
	}
	return rep
}

// document 读回落盘的文档，用来验证"没写坏的进去"。
func (h *harness) document(t *testing.T) *spec.Document {
	t.Helper()
	doc, err := spec.LoadDocument(h.opts.DocumentPath)
	if err != nil {
		t.Fatalf("读回文档失败: %v", err)
	}
	return doc
}

func (h *harness) domains(t *testing.T) []string {
	t.Helper()
	doc := h.document(t)
	if len(doc.Certificates) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d: %+v", len(doc.Certificates), doc.Certificates)
	}
	return doc.Certificates[0].Domains
}

func decisionFor(rep *Report, hostname string) (spec.Decision, bool) {
	for _, d := range rep.Decisions {
		if d.Hostname == hostname {
			return d, true
		}
	}
	return spec.Decision{}, false
}

// ── 声明解析 ────────────────────────────────────────────────────────────────

func TestParseDeclaration(t *testing.T) {
	d, err := ParseDeclaration("example.com", "_wecert.example.com",
		[]string{"v=wecert1, wildcard=1, profile=tlsserver, deploy=0"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname != "example.com" {
		t.Errorf("Hostname = %q", d.Hostname)
	}
	if !d.Wildcard {
		t.Error("wildcard=1 应当生效")
	}
	if d.Profile != "tlsserver" {
		t.Errorf("Profile = %q", d.Profile)
	}
	if d.Deploy == nil || *d.Deploy {
		t.Errorf("deploy=0 应当生效，实际 %v", d.Deploy)
	}
	if got := d.Names(); len(got) != 2 || got[1] != "*.example.com" {
		t.Errorf("Names() = %v，应当展开通配符", got)
	}
}

// 裸记录本身就是声明，这是最常见的写法。
func TestParseDeclarationAcceptsABareRecord(t *testing.T) {
	d, err := ParseDeclaration("example.com", "_wecert.api.example.com", []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname != "api.example.com" || d.Wildcard {
		t.Errorf("裸记录应当只声明自己: %+v", d)
	}
}

// 拼错的键必须报错而不是忽略。
//
// `wildard=1` 被静默忽略的结果是"声明了通配符但没生效"，
// 而人会一直以为它生效了 —— 这类沉默的偏差比一条清晰的报错昂贵得多。
func TestParseDeclarationRejectsUnknownKeys(t *testing.T) {
	_, err := ParseDeclaration("example.com", "_wecert.example.com", []string{"wildard=1"})
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("未知键应当报错，实际 %v", err)
	}
}

func TestParseDeclarationRejectsBadVersion(t *testing.T) {
	if _, err := ParseDeclaration("example.com", "_wecert.example.com", []string{"v=wecert9"}); err == nil {
		t.Fatal("未知版本号应当报错")
	}
}

func TestParseDeclarationRejectsConflictingKeys(t *testing.T) {
	_, err := ParseDeclaration("example.com", "_wecert.example.com",
		[]string{"wildcard=1", "wildcard=0"})
	if err == nil {
		t.Fatal("同一个键给出互相矛盾的值应当报错")
	}
}

// ── §5.1 来源失败 ≠ 名字消失 ────────────────────────────────────────────────

// 这是整套设计里唯一能造成灾难的地方。
//
// DNS 枚举接口抖动 → 返回空 → 若被理解成"这些名字都没了" →
// 期望状态里没有域名了 → 重签一张不含域名的证书 → 线上立刻握手失败。
// 这比不签发严重得多，所以正确反应是冻结。
func TestSourceFailureFreezesInsteadOfEmptying(t *testing.T) {
	h := newHarness(t, Options{})
	h.decls.raw = []RawDeclaration{decl("example.com")}
	h.rules.domains = []string{"example.com"}

	if rep := h.run(t); rep.Frozen() {
		t.Fatalf("第一轮不该冻结: %v", rep.FreezeReasons)
	}
	before := h.domains(t)

	// 来源挂了。
	h.decls.err = errors.New("dnspod api timeout")

	rep := h.run(t)
	if !rep.Frozen() {
		t.Fatal("来源失败时必须冻结")
	}
	if len(rep.FreezeReasons) == 0 {
		t.Error("冻结必须带上原因")
	}

	// 文档必须一个字都没变 —— 尤其不能被清空。
	after := h.domains(t)
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("冻结时期望状态被改动了: %v -> %v", before, after)
	}
}

// 冻结时不能推进删除宽限期。
//
// AbsentSince 是"这个名字已经被确认缺席多久"的账本，而冻结的那一轮
// 我们根本不知道名字还在不在。推进它等于用噪声缩短宽限期。
func TestSourceFailureDoesNotAdvanceTheGraceClock(t *testing.T) {
	h := newHarness(t, Options{DropThreshold: 0.9})
	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// b 的声明消失，来源正常 —— 此时应当记下 AbsentSince。
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.run(t)

	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	since, ok := st.AbsentSince["b.example.com"]
	if !ok {
		t.Fatal("b.example.com 应当被记下缺席时刻")
	}

	// 再过几轮，但来源全是失败的：AbsentSince 不能往前推。
	h.clock.advance(time.Hour)
	h.decls.err = errors.New("boom")
	h.run(t)

	after, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.AbsentSince["b.example.com"]; !got.Equal(since) {
		t.Errorf("冻结不该推进缺席时刻: %v -> %v", since, got)
	}
}

// ── §5.2 期望状态骤变熔断 ───────────────────────────────────────────────────

// 正常的一次下线不会让集合少三成。突然少三成，几乎一定是上游出了问题
// （API 返回不完整、权限被改、zone 读失败）。照做的后果是批量摘除 SAN。
func TestAbruptDropFreezes(t *testing.T) {
	h := newHarness(t, Options{})

	var raw []RawDeclaration
	var rules []string
	for _, n := range []string{"a", "b", "c", "d"} {
		raw = append(raw, decl(n+".example.com"))
		rules = append(rules, n+".example.com")
	}
	h.decls.raw, h.rules.domains = raw, rules
	h.run(t)

	// 四个里只剩一个：掉了 75%，远超 30% 的阈值。
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}

	rep := h.run(t)
	if !rep.Frozen() {
		t.Fatal("超过阈值的骤降必须冻结")
	}
	if !strings.Contains(strings.Join(rep.FreezeReasons, " "), "force") {
		t.Error("冻结原因应当告诉人怎么确认这次骤降是有意的")
	}
}

// 小幅度下降不该触发熔断，否则正常下线就走不动了。
func TestSmallDropDoesNotFreeze(t *testing.T) {
	h := newHarness(t, Options{})

	var raw []RawDeclaration
	var rules []string
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		raw = append(raw, decl(n+".example.com"))
		rules = append(rules, n+".example.com")
	}
	h.decls.raw, h.rules.domains = raw, rules
	h.run(t)

	// 掉一个 = 10%，低于 30%。
	h.decls.raw = raw[:9]
	h.rules.domains = rules[:9]
	h.clock.advance(48 * time.Hour) // 越过宽限期

	if rep := h.run(t); rep.Frozen() {
		t.Fatalf("10%% 的下降不该冻结: %v", rep.FreezeReasons)
	}
}

// ── §5.3 删除比增加保守一个量级 ─────────────────────────────────────────────

// 声明消失之后不能立刻把域名从证书里摘掉。
//
// 双来源的结构天然会让状态抖动：DNS 查询抖一下 → 立刻删 → 重签 →
// DNS 恢复 → 又重签。一次上线触发三次签发，白烧配额。
func TestRemovalWaitsForTheGracePeriod(t *testing.T) {
	// 阈值调高，把骤变熔断排除在外，单独观察宽限期。
	h := newHarness(t, Options{DropThreshold: 0.9})

	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// b 的声明没了，规则也不再服务它，来源是健康的。
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("不该冻结: %v", rep.FreezeReasons)
	}
	domains := h.domains(t)
	if len(domains) != 2 {
		t.Fatalf("宽限期内 b 必须留着，实际 %v", domains)
	}
	d, ok := decisionFor(rep, "b.example.com")
	if !ok || !d.Included {
		t.Fatalf("b 应当被标记为保留: %+v", d)
	}
	if !strings.Contains(d.Reason, "grace period") {
		t.Errorf("理由应当提到宽限期，实际 %q", d.Reason)
	}

	// 越过宽限期之后才真的移除。
	h.clock.advance(25 * time.Hour)
	h.run(t)

	if got := h.domains(t); len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("超过宽限期后应当移除 b，实际 %v", got)
	}
}

// 名字回来之后宽限期要重置。
//
// 否则一次抖动会把缺席时刻一路带下去，宽限期形同虚设。
func TestReappearingNameResetsTheGraceClock(t *testing.T) {
	h := newHarness(t, Options{DropThreshold: 0.9})

	two := []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.decls.raw = two
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.run(t)

	h.clock.advance(time.Hour)
	h.decls.raw = two
	h.run(t)

	st, err := LoadState(h.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, still := st.AbsentSince["b.example.com"]; still {
		t.Error("名字回来之后缺席标记应当被清掉")
	}
}

// 还在被 CLB 规则引用的名字不能因为声明没了就拆掉 —— 那会直接打断线上。
func TestRemovalIsBlockedWhileACLBRuleStillReferencesIt(t *testing.T) {
	h := newHarness(t, Options{DropThreshold: 0.9})

	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// 声明没了，但规则还在 —— 说明还有流量。
	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.run(t) // 这一轮才会第一次记下 b 的缺席时刻

	// 越过宽限期：走到这一步才会轮到引用检查，而不是宽限期分支。
	h.clock.advance(72 * time.Hour)

	rep := h.run(t)
	d, ok := decisionFor(rep, "b.example.com")
	if !ok || !d.Included {
		t.Fatalf("规则还引用着，b 必须保留: %+v", d)
	}
	if !strings.Contains(d.Reason, "CLB rule still references") {
		t.Errorf("理由应当说明是引用检查拦下的，实际 %q", d.Reason)
	}
	if got := h.domains(t); len(got) != 2 {
		t.Fatalf("b 应当还在证书里，实际 %v", got)
	}
}

// ── §5.5 显式授权与守卫 ─────────────────────────────────────────────────────

// 声明必须有 CLB 规则兜底（守卫 1）才生效。
//
// 它挡住两类真问题：声明写了但规则还没配（会造成一次无用的签发），
// 以及拼错的域名（规则里根本不存在）。
func TestGuardRequiresACLBRule(t *testing.T) {
	h := newHarness(t, Options{RequireRule: true})

	h.decls.raw = []RawDeclaration{decl("served.example.com"), decl("typo.example.com")}
	h.rules.domains = []string{"served.example.com"}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("不该冻结: %v", rep.FreezeReasons)
	}

	if got := h.domains(t); len(got) != 1 || got[0] != "served.example.com" {
		t.Fatalf("只有被规则服务的名字该进证书，实际 %v", got)
	}
	d, ok := decisionFor(rep, "typo.example.com")
	if !ok || d.Included {
		t.Fatalf("typo.example.com 应当被排除: %+v", d)
	}
	if !strings.Contains(d.Reason, "no CLB rule") {
		t.Errorf("理由应当说明守卫未通过，实际 %q", d.Reason)
	}
}

// 守卫读不到时一律不做删除决策。
//
// §9 明确不做"来源不可用时降级成单来源"：降级会让安全性随故障一起消失，
// 而你恰好在那时最需要它。
func TestUnavailableGuardRemovesNothing(t *testing.T) {
	h := newHarness(t, Options{RequireRule: true, DropThreshold: 0.9})

	h.decls.raw = []RawDeclaration{decl("a.example.com"), decl("b.example.com")}
	h.rules.domains = []string{"a.example.com", "b.example.com"}
	h.run(t)

	// 规则接口挂了，同时 b 的声明也消失了。此时不能判断 b 是不是还在服务。
	h.rules.err = errors.New("clb api unreachable")
	h.decls.raw = []RawDeclaration{decl("a.example.com")}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("守卫不可用不该整体冻结: %v", rep.FreezeReasons)
	}
	if !rep.GuardUnavailable {
		t.Error("报告应当标出守卫这一轮不可用")
	}
	if got := h.domains(t); len(got) != 2 {
		t.Fatalf("守卫不可用时不许删任何名字，实际 %v", got)
	}
}

// 允许清单是 §5.5 的护栏：来源只提供线索，授权必须是明确的动作。
func TestAllowlistLimitsWhichRegisteredDomainsMayBeIssuedFor(t *testing.T) {
	h := newHarness(t, Options{Allowlist: []string{"allowed.example"}})

	h.decls.raw = []RawDeclaration{
		{Zone: "allowed.example", Record: DeclarationPrefix + "allowed.example", Values: []string{""}},
		{Zone: "other.example", Record: DeclarationPrefix + "other.example", Values: []string{""}},
	}
	h.rules.domains = []string{"allowed.example", "other.example"}

	rep := h.run(t)
	if got := h.domains(t); len(got) != 1 || got[0] != "allowed.example" {
		t.Fatalf("允许清单外的注册域不该进证书，实际 %v", got)
	}
	if d, ok := decisionFor(rep, "other.example"); !ok || !strings.Contains(d.Reason, "allowlist") {
		t.Fatalf("other.example 应当因允许清单被排除: %+v", d)
	}
}

// ── §6.1 通配符优先 ─────────────────────────────────────────────────────────

// 这是整个设计里最值钱的一条：声明了 *.example.com 之后，
// 再加子域不动 SAN 集合，也就是 **0 次签发**。
//
// 没有它，批量导入 50 个子域就是 50 次重签 —— 直接撞满
// "50 certificates per registered domain per 7 days"。
func TestWildcardCoverageMakesNewSubdomainsFree(t *testing.T) {
	h := newHarness(t, Options{})

	h.decls.raw = []RawDeclaration{
		decl("example.com", "wildcard=1"),
		decl("api.example.com"),
		decl("www.example.com"),
	}
	h.rules.domains = []string{"example.com", "api.example.com", "www.example.com"}

	first := h.run(t)
	if first.Frozen() {
		t.Fatalf("不该冻结: %v", first.FreezeReasons)
	}

	domains := h.domains(t)
	if len(domains) != 2 || domains[0] != "example.com" || domains[1] != "*.example.com" {
		t.Fatalf("SAN 集合应当是 [example.com *.example.com]，实际 %v", domains)
	}
	if first.CoveredByWildcard != 2 {
		t.Errorf("应当有 2 个名字被通配符覆盖，实际 %d", first.CoveredByWildcard)
	}

	// 现在加一个新的子域，并且规则也配好了。
	h.decls.raw = append(h.decls.raw, decl("foo.example.com"))
	h.rules.domains = append(h.rules.domains, "foo.example.com")

	second := h.run(t)
	if second.Mode != ModeUnchanged {
		t.Fatalf("新子域被通配符覆盖，期望状态不该变，实际 %s (rev %s -> %s)",
			second.Mode, second.PreviousRevision, second.Revision)
	}
	if got := h.domains(t); len(got) != 2 {
		t.Fatalf("SAN 集合不该因为加了子域而变大，实际 %v", got)
	}
	if d, ok := decisionFor(second, "foo.example.com"); !ok || !strings.Contains(d.Reason, "wildcard") {
		t.Fatalf("新子域应当被解释为「被通配符覆盖」: %+v", d)
	}
}

// ── §5.4 配额熔断 ───────────────────────────────────────────────────────────

func TestChangeBudgetFreezes(t *testing.T) {
	h := newHarness(t, Options{Budget: 1})

	h.decls.raw = []RawDeclaration{decl("a.example.com")}
	h.rules.domains = []string{"a.example.com"}
	h.run(t)

	// 第二次集合变更就把只有 1 次的预算用光了。
	h.decls.raw = append(h.decls.raw, decl("b.example.com"))
	h.rules.domains = append(h.rules.domains, "b.example.com")

	rep := h.run(t)
	if !rep.Frozen() {
		t.Fatal("预算耗尽必须冻结")
	}
	if !strings.Contains(strings.Join(rep.FreezeReasons, " "), "budget") {
		t.Errorf("原因应当说明是预算耗尽: %v", rep.FreezeReasons)
	}
}

// ── 空期望状态 ──────────────────────────────────────────────────────────────

// "合法的空"和"生成失败导致的空"在文件里长得一模一样，
// 而后者一旦被写出去，后果是每张证书的每个域名都被摘掉。
func TestEmptyDesiredStateIsRefused(t *testing.T) {
	h := newHarness(t, Options{})

	rep := h.run(t)
	if !rep.Frozen() {
		t.Fatal("空期望状态必须被拒绝")
	}
	if !strings.Contains(strings.Join(rep.FreezeReasons, " "), "empty") {
		t.Errorf("原因应当说明是空期望状态: %v", rep.FreezeReasons)
	}
}

// ── 幂等 ────────────────────────────────────────────────────────────────────

// 同样的输入连着跑两次，第二轮的指纹必须与上一版相同 ——
// 否则期望状态文档每次生成都会 diff 一片，可 review 性直接归零。
func TestSecondRunIsUnchanged(t *testing.T) {
	h := newHarness(t, Options{})
	h.decls.raw = []RawDeclaration{decl("example.com", "wildcard=1"), decl("api.example.com")}
	h.rules.domains = []string{"example.com", "api.example.com"}

	first := h.run(t)
	second := h.run(t)

	if second.Mode != ModeUnchanged {
		t.Fatalf("第二轮应当是 unchanged，实际 %s", second.Mode)
	}
	if first.Revision != second.Revision {
		t.Errorf("指纹不该变: %s vs %s", first.Revision, second.Revision)
	}
}

// 一条声明无效不能连累整轮：那样一个手误就会让所有证书停止更新。
func TestOneBadDeclarationDoesNotFreezeEverything(t *testing.T) {
	h := newHarness(t, Options{})

	h.decls.raw = []RawDeclaration{
		decl("good.example.com"),
		decl("bad.example.com", "wildard=1"), // 拼错的键
	}
	h.rules.domains = []string{"good.example.com", "bad.example.com"}

	rep := h.run(t)
	if rep.Frozen() {
		t.Fatalf("单条声明出错不该冻结整轮: %v", rep.FreezeReasons)
	}
	if got := h.domains(t); len(got) != 1 || got[0] != "good.example.com" {
		t.Fatalf("好声明应当照常生效，实际 %v", got)
	}
	if d, ok := decisionFor(rep, "bad.example.com"); !ok || d.Included {
		t.Fatalf("坏声明应当被排除并留下理由: %+v", d)
	}
}

// 组内声明对元数据不一致时，默认值说了算 —— 让某个子域的声明
// 悄悄改掉整张证书的属性，是那种事后没人能解释的变更。
func TestGroupSettingsComeFromDeclarations(t *testing.T) {
	h := newHarness(t, Options{Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256})

	h.decls.raw = []RawDeclaration{decl("example.com", "profile=tlsserver, keytype=ecdsa-p384")}
	h.rules.domains = []string{"example.com"}
	h.run(t)

	c := h.document(t).Certificates[0]
	if c.Profile != config.ProfileTLSServer {
		t.Errorf("profile 应当来自声明，实际 %q", c.Profile)
	}
	if c.KeyType != config.KeyTypeECDSAP384 {
		t.Errorf("keyType 应当来自声明，实际 %q", c.KeyType)
	}
}
