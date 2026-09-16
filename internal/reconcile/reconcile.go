// Package reconcile 驱动整体的收敛循环。
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
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

// Reconciler 遍历所有证书，逐张收敛。
//
// 并发安全：定时循环和 webhook 触发的收敛会同时调用它，
// 靠 running 这张表保证同一张证书不会被并发处理。
type Reconciler struct {
	cfg      *config.Config
	store    *state.Store
	manager  CertManager
	notifier Notifier
	log      *slog.Logger

	mu      sync.Mutex
	running map[string]struct{}
}

// New 构造收敛器。manager 传 *acme.Manager 即可，notifier 可为 nil。
func New(cfg *config.Config, store *state.Store, manager CertManager, notifier Notifier, log *slog.Logger) *Reconciler {
	return &Reconciler{
		cfg:      cfg,
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

// CertNames 返回配置里所有证书的名字，顺序与配置一致。
func (r *Reconciler) CertNames() []string {
	names := make([]string, 0, len(r.cfg.Certificates))
	for i := range r.cfg.Certificates {
		names = append(names, r.cfg.Certificates[i].Name)
	}
	return names
}

// RunAll 跑一轮全部证书。
//
// 单张证书失败不会中断这一轮：否则一张配错域名的证书会把其它所有证书
// 的续期一起拖住 —— 那是自动化里最危险的一种耦合。
//
// 正在被别处处理的证书会被跳过，并在返回值里列出。
func (r *Reconciler) RunAll(ctx context.Context) (skipped []string) {
	for i := range r.cfg.Certificates {
		c := &r.cfg.Certificates[i]

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

	// 回收超过保留期的退役证书，避免云端证书配额被慢慢耗光。
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
	var found *config.Certificate
	for i := range r.cfg.Certificates {
		if r.cfg.Certificates[i].Name == name {
			found = &r.cfg.Certificates[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("no certificate named %q in the config", name)
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
// 占位是**同步**做的 —— 所以"这张证书是否已经在处理中"能立刻回答调用方；
// 真正的收敛丢到后台，因为它可能要几分钟（DNS 传播），
// 让 HTTP 请求等着会把调用方的超时拖爆。
//
// ctx 必须是**进程级**上下文，不能用请求的 context：
// 请求一返回它的 context 就被取消，后台那一轮会被立刻打断。
func (r *Reconciler) StartCert(ctx context.Context, name string) error {
	var found *config.Certificate
	for i := range r.cfg.Certificates {
		if r.cfg.Certificates[i].Name == name {
			found = &r.cfg.Certificates[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("no certificate named %q in the config", name)
	}

	if !r.acquire(name) {
		return ErrAlreadyRunning
	}

	// 配置在启动后不再变更，所以这里直接引用它的元素是安全的。
	go func() {
		defer r.release(name)
		r.reconcileOne(ctx, found)
	}()
	return nil
}

// StartAll 异步处理全部证书，同步返回被跳过的（已在处理中的）名字。
func (r *Reconciler) StartAll(ctx context.Context) []string {
	var skipped []string
	for i := range r.cfg.Certificates {
		name := r.cfg.Certificates[i].Name
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

	if r.notifier != nil {
		r.notifier.Renewal(ctx, c.Name, err)
	}
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
