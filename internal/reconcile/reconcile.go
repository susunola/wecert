// Package reconcile 驱动整体的收敛循环。
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// ErrAlreadyRunning 表示这张证书已经有一轮在跑了。
//
// 这不是异常，而是必须存在的一道闸门：定时器和一个事件触发的收敛
// 很可能同时落到同一张证书上。两边各下一单，就会直接撞上
// "5 certificates per exact set of identifiers / 7 days" —— 而且这条没有 override。
var ErrAlreadyRunning = errors.New("this certificate already has a pass in flight")

// Notifier 在每张证书处理结束后收到通知。可为 nil。
//
// 放在这一层而不是 webhook 层，是为了让"续期结果"这个事件
// 无论由定时器还是由外部触发都同样发得出去。
type Notifier interface {
	Renewal(ctx context.Context, certName string, err error)
}

// CertManager 是 Reconciler 需要的能力。
//
// 定义成接口而不是直接依赖 *acme.Manager，是为了让收敛循环可测 ——
// 直接依赖具体类型的话，"一张证书失败不能拖住其它证书" 这类
// 编排逻辑就只能靠真跑一遍 ACME 才能验证。
type CertManager interface {
	Reconcile(ctx context.Context, c *config.Certificate) error
	ReapRetired(ctx context.Context)
}

// Reconciler 逐张收敛当前期望状态里的证书。
//
// 并发安全：定时循环和 webhook 触发的收敛会同时调用它，
// 靠 running 这张表保证同一张证书不会被并发处理。
type Reconciler struct {
	cfg      *config.Config
	provider spec.Provider
	store    *state.Store
	manager  CertManager
	notifier Notifier
	log      *slog.Logger

	mu      sync.Mutex
	running map[string]struct{}

	// prober 是可选的网络侧探测器。为 nil 表示不探测。
	//
	// 用 SetProber 挂上来而不是塞进 New 的参数表：它是一层纯粹的附加观测，
	// 不该让每一个测试替身都去构造它。
	prober *probe.Runner

	// last 是最近一次成功求值出来的期望状态，供只读诊断端点使用。
	// 存指针是必要的：诊断端点会在另一个 goroutine 里读它。
	last atomic.Pointer[spec.Result]
}

// SetProber 挂上网络侧探测器。必须在第一次收敛之前调用。
//
// 传 nil 时整条探测路径都是空操作，收敛行为与不挂时完全一致。
func (r *Reconciler) SetProber(p *probe.Runner) { r.prober = p }

// New 构造收敛器。
//
// provider 是期望状态的来源，可以是 spec.Static（配置里的 certificates）、
// spec.File（onboarding 写出来的文档）或 spec.Observer（前者 + 影子对比）。
// 收敛逻辑完全不关心是哪一个 —— 这正是切换来源不用动收敛代码的原因。
func New(cfg *config.Config, provider spec.Provider, store *state.Store, manager CertManager, notifier Notifier, log *slog.Logger) *Reconciler {
	return &Reconciler{
		cfg:      cfg,
		provider: provider,
		store:    store,
		manager:  manager,
		notifier: notifier,
		log:      log,
		running:  make(map[string]struct{}),
	}
}

// acquire 尝试占住某张证书。返回 false 表示已经有人在跑。
func (r *Reconciler) acquire(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.running[name]; busy {
		return false
	}
	r.running[name] = struct{}{}
	return true
}

func (r *Reconciler) release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, name)
}

// ── 期望状态 ────────────────────────────────────────────────────────────────

// Prime 求值一次期望状态并缓存，不触发任何收敛。
//
// 启动时调一次，让只读端点（webhook 的名字解析、诊断端点）在第一次
// 收敛跑完之前就能给出正确答案。
func (r *Reconciler) Prime(ctx context.Context) {
	r.resolve(ctx)
}

// resolve 求值期望状态。返回 nil 表示这一轮**什么都不该做**。
//
// 这是整套设计里最关键的一条失败语义：拿不到期望状态，绝不等于
// "期望为空"。后者会让 wecert 把域名从每张证书里摘掉，线上立刻握手失败。
// 跳过一轮的代价只是"这次没续上"，下一轮还有机会。
func (r *Reconciler) resolve(ctx context.Context) *spec.Result {
	res, err := spec.Desired(ctx, r.provider)
	if err != nil {
		metrics.DesiredStateErrors.Inc()
		r.log.Error("cannot read the desired state; skipping this pass entirely "+
			"(an unreadable source is never treated as an empty desired state)",
			"provider", spec.KindOf(r.provider), "err", err)
		return nil
	}

	r.last.Store(res)
	r.publishDesired(res)
	return res
}

// LastResult 返回最近一次成功求值出来的期望状态，可能为 nil。
func (r *Reconciler) LastResult() *spec.Result { return r.last.Load() }

// CertNames 返回当前期望状态里的证书名，顺序与期望状态一致。
//
// 取的是缓存而不是重新求值：这个方法是给只读端点和触发路径用的，
// 每次都去读一遍来源会让一次 HTTP 请求的延迟取决于云 API 的响应时间。
func (r *Reconciler) CertNames() []string {
	res := r.last.Load()
	if res == nil {
		return nil
	}
	return res.CertNames()
}

// publishDesired 把期望状态的健康状况同步到指标和日志。
func (r *Reconciler) publishDesired(res *spec.Result) {
	metrics.DesiredStateCertificates.Set(float64(len(res.Certificates)))

	if res.Frozen {
		metrics.DesiredStateFrozen.Set(1)
		r.log.Warn("the desired state is frozen on the last good revision; "+
			"renewals still run against it, but nothing new will be picked up until the source recovers",
			"provider", spec.KindOf(r.provider), "revision", res.Revision, "reason", res.FreezeReason)
	} else {
		metrics.DesiredStateFrozen.Set(0)
	}

	// 文档年龄是这套架构特有的失败信号：onboarding 组件挂掉之后，
	// wecert 会一直按旧文档正常续期，一切看起来都正常，
	// 只是新域名再也不会进来。
	if !res.GeneratedAt.IsZero() {
		age := time.Since(res.GeneratedAt)
		metrics.DesiredStateAge.Set(age.Seconds())
		if max := r.cfg.DesiredState.MaxStalenessDur; max > 0 && age > max {
			r.log.Error("the desired-state document is stale: the onboarding component has stopped refreshing it; "+
				"renewals keep working, but newly declared names will never be picked up",
				"generatedAt", res.GeneratedAt, "age", age.Round(time.Minute), "threshold", max)
		}
	}

	if res.Shadow != nil && res.Shadow.Error == "" {
		metrics.DesiredStateShadowDiff.Set(float64(len(res.Shadow.AddCertificates) +
			len(res.Shadow.RemoveCertificates) + len(res.Shadow.ChangeCertificates)))
	}
}

// publishOrphans 报告"状态库里有、期望状态里已经没有"的证书。
//
// 这类证书不会再被续期，最终会安静地过期。期望状态的删除路径本来就有
// 宽限期和引用检查，这个检查是最后一道兜底 —— 万一还是漏出去了，
// 至少能在到期之前看见它，而不是等站点握手失败。
func (r *Reconciler) publishOrphans(res *spec.Result) {
	names, err := r.store.ListCertNames()
	if err != nil {
		r.log.Warn("cannot list certificate names for the orphan check", "err", err)
		return
	}

	want := make(map[string]bool, len(res.Certificates))
	for i := range res.Certificates {
		want[res.Certificates[i].Name] = true
	}

	orphans := 0
	for _, name := range names {
		if want[name] {
			continue
		}
		orphans++

		attrs := []any{"cert", name}
		if st, err := r.store.GetCert(name); err == nil && st != nil && !st.NotAfter.IsZero() {
			attrs = append(attrs, "notAfter", st.NotAfter,
				"daysLeft", int(time.Until(st.NotAfter).Hours()/24))
		}
		r.log.Error("this certificate is no longer in the desired state, so it will not be renewed "+
			"and will expire; if that was not intended, restore its declaration and re-run wecert-onboard",
			attrs...)
	}
	metrics.OrphanedCertificates.Set(float64(orphans))
}

// ── 收敛 ────────────────────────────────────────────────────────────────────

// RunAll 跑一轮全部证书。
//
// 单张证书失败不会中断这一轮：否则一张配错域名的证书会把其它所有证书
// 的续期一起拖住 —— 那是自动化里最危险的一种耦合。
//
// 正在被别处处理的证书会被跳过，并在返回值里列出。
func (r *Reconciler) RunAll(ctx context.Context) (skipped []string) {
	res := r.resolve(ctx)
	if res == nil {
		// 即使拿不到期望状态也要回收退役证书：那批证书已经被换掉了，
		// 回收它们和期望状态无关，而放着不管会把云端证书配额慢慢耗光。
		r.manager.ReapRetired(ctx)
		return nil
	}
	r.publishOrphans(res)

	for i := range res.Certificates {
		c := &res.Certificates[i]

		if err := ctx.Err(); err != nil {
			return skipped
		}

		if !r.acquire(c.Name) {
			r.log.Info("skipping: this certificate already has a pass in flight", "cert", c.Name)
			skipped = append(skipped, c.Name)
			continue
		}
		r.reconcileOne(ctx, c)
		r.release(c.Name)
	}

	r.manager.ReapRetired(ctx)
	return skipped
}

// RunOnce 是 RunAll 的兼容别名。
func (r *Reconciler) RunOnce(ctx context.Context) {
	r.RunAll(ctx)
}

// RunCert 只处理指定的一张证书。未知名字返回错误；
// 已在处理中返回 ErrAlreadyRunning。
func (r *Reconciler) RunCert(ctx context.Context, name string) error {
	res := r.resolve(ctx)
	if res == nil {
		return fmt.Errorf("cannot read the desired state, so %q was not processed", name)
	}
	found := res.Find(name)
	if found == nil {
		return fmt.Errorf("no certificate named %q in the desired state", name)
	}

	if !r.acquire(name) {
		return ErrAlreadyRunning
	}
	defer r.release(name)

	r.reconcileOne(ctx, found)
	return nil
}

// StartCert 异步处理一张证书。
//
// 求值和占位都是**同步**做的 —— 所以"这张证书是否已经在处理中"、
// "这个名字到底存不存在"都能立刻回答调用方；真正的收敛丢到后台，
// 因为它可能要几分钟（DNS 传播），让 HTTP 请求等着会把调用方的超时拖爆。
//
// ctx 必须是**进程级**上下文，不能用请求的 context：
// 请求一返回它的 context 就被取消，后台那一轮会被立刻打断。
func (r *Reconciler) StartCert(ctx context.Context, name string) error {
	res := r.resolve(ctx)
	if res == nil {
		return fmt.Errorf("cannot read the desired state, so %q was not processed", name)
	}
	found := res.Find(name)
	if found == nil {
		return fmt.Errorf("no certificate named %q in the desired state", name)
	}

	if !r.acquire(name) {
		return ErrAlreadyRunning
	}

	// res 是在堆上分配的，这一轮期间不会被复用，所以引用它的元素是安全的。
	go func() {
		defer r.release(name)
		r.reconcileOne(ctx, found)
	}()
	return nil
}

// StartAll 异步处理全部证书，同步返回被跳过的（已在处理中的）名字。
func (r *Reconciler) StartAll(ctx context.Context) []string {
	res := r.resolve(ctx)
	if res == nil {
		return nil
	}

	var skipped []string
	for _, name := range res.CertNames() {
		if err := r.StartCert(ctx, name); err != nil {
			skipped = append(skipped, name)
		}
	}
	return skipped
}

// reconcileOne 处理单张证书，并把结果同步到指标和通知。
func (r *Reconciler) reconcileOne(ctx context.Context, c *config.Certificate) {
	err := r.manager.Reconcile(ctx, c)
	if err != nil {
		metrics.ReconcileTotal.WithLabelValues(c.Name, "error").Inc()
		// manager 内部已经打过日志并安排了退避，这里只补一条摘要。
		r.log.Warn("this pass did not succeed", "cert", c.Name, "err", err)
	} else {
		metrics.ReconcileTotal.WithLabelValues(c.Name, "ok").Inc()
	}

	r.publish(c.Name)
	r.probeCert(ctx, c)

	if r.notifier != nil {
		r.notifier.Renewal(ctx, c.Name, err)
	}
}

// probeCert 拨一个真实的 TLS 连接，确认线上服务的确实是刚部署的那张证书。
//
// 这是整套系统里唯一不信任云控制面的证据。控制面说"绑定成功"和浏览器
// 真的能拿到这张证书是两件事，而这两件事之间的差距 —— 换绑是异步的、
// SNI 上可能有另一张证书在赢 —— 恰好是 CLB 上最容易出问题的地方。
//
// 拿不到结论**不会**影响这一轮的结果：一个拨不出去的探测不该让一次
// 成功的续期看起来像失败。它只影响指标和告警。
func (r *Reconciler) probeCert(ctx context.Context, c *config.Certificate) {
	if r.prober == nil {
		return
	}

	// 还没确认部署的东西拨了也只会报错 —— 首次上传之后要人工绑一次，
	// 在那之前线上服务的本来就还是旧证书。
	st, err := r.store.GetCert(c.Name)
	if err != nil || st == nil || !st.DeployConfirmed {
		return
	}

	hosts := probeHosts(c.Domains, r.cfg.Probe.MaxHostsPerCert)
	if len(hosts) == 0 {
		// 整张证书都是通配符：没有具体名字可以拨。
		r.log.Debug("nothing to probe: every name in this certificate is a wildcard",
			"cert", c.Name, "domains", c.Domains)
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}

	e := probe.Expectation{
		Domains:     c.Domains,
		NotAfter:    st.NotAfter,
		MinValidFor: r.cfg.Probe.MinValidDur,
	}

	// 同一张证书的几个名字并发拨。串行的话，一张 3 个名字的证书在
	// 全部超时的情况下要占 30 秒，而这是每一轮都要跑的东西。
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			r.prober.Check(ctx, h, e)
		}(host)
	}
	wg.Wait()
}

// probeHosts 从一张证书的域名里挑出可以拨的名字。
//
// 通配符没有自己的地址，所以跳过；其余按声明顺序取前 max 个 ——
// 声明顺序把注册域放在最前面，而那通常是最该被验的那个。
func probeHosts(domains []string, max int) []string {
	if max <= 0 {
		return nil
	}
	out := make([]string, 0, max)
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			continue
		}
		out = append(out, d)
		if len(out) >= max {
			break
		}
	}
	return out
}

// publish 把状态库里的现状同步到 Prometheus。
func (r *Reconciler) publish(name string) {
	st, err := r.store.GetCert(name)
	if err != nil || st == nil {
		return
	}

	if st.NotAfter.IsZero() {
		metrics.CertNotAfter.WithLabelValues(name).Set(0)
	} else {
		metrics.CertNotAfter.WithLabelValues(name).Set(float64(st.NotAfter.Unix()))
	}

	// 只有确认已经换到新证书才算"deployed"：首次上传之后还要人工绑一次，
	// 在那之前指示灯不能变绿，否则到期告警会以为一切正常。
	if st.DeployConfirmed && st.DeployedCertID != "" {
		metrics.CertDeployed.WithLabelValues(name).Set(1)
	} else {
		metrics.CertDeployed.WithLabelValues(name).Set(0)
	}

	metrics.CertConsecutiveFailures.WithLabelValues(name).Set(float64(st.ConsecutiveFailures))

	if st.ARIWindowStart.IsZero() {
		metrics.CertARIWindowStart.WithLabelValues(name).Set(0)
	} else {
		metrics.CertARIWindowStart.WithLabelValues(name).Set(float64(st.ARIWindowStart.Unix()))
	}

	if !st.NotAfter.IsZero() {
		days := time.Until(st.NotAfter).Hours() / 24
		if days < 21 {
			r.log.Warn("certificate approaching expiry",
				"cert", name, "notAfter", st.NotAfter, "daysLeft", int(days),
				"consecutiveFailures", st.ConsecutiveFailures, "lastError", st.LastError)
		}
	}
}
