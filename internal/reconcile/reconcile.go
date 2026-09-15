// Package reconcile 驱动整体的收敛循环。
package reconcile

import (
	"context"
	"log/slog"
	"time"

	"github.com/atom/wecert/internal/acme"
	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/metrics"
	"github.com/atom/wecert/internal/state"
)

// Reconciler 遍历所有证书，逐张收敛。
type Reconciler struct {
	cfg     *config.Config
	store   *state.Store
	manager *acme.Manager
	log     *slog.Logger
}

// New 构造收敛器。
func New(cfg *config.Config, store *state.Store, manager *acme.Manager, log *slog.Logger) *Reconciler {
	return &Reconciler{cfg: cfg, store: store, manager: manager, log: log}
}

// RunOnce 跑一轮。
//
// 单张证书失败不会中断这一轮：否则一张配错域名的证书会把其它所有证书
// 的续期一起拖住 —— 那是自动化里最危险的一种耦合。
func (r *Reconciler) RunOnce(ctx context.Context) {
	for i := range r.cfg.Certificates {
		c := &r.cfg.Certificates[i]

		if err := ctx.Err(); err != nil {
			return
		}

		err := r.manager.Reconcile(ctx, c)
		if err != nil {
			metrics.ReconcileTotal.WithLabelValues(c.Name, "error").Inc()
			// manager 内部已经打过日志并安排了退避，这里只补一条摘要。
			r.log.Warn("本轮未成功", "cert", c.Name, "err", err)
		} else {
			metrics.ReconcileTotal.WithLabelValues(c.Name, "ok").Inc()
		}

		r.publish(c.Name)
	}

	// 回收超过保留期的退役证书，避免云端证书配额被慢慢耗光。
	r.manager.ReapRetired(ctx)
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

	if st.DeployedCertID != "" {
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
			r.log.Warn("证书临近到期",
				"cert", name, "notAfter", st.NotAfter, "daysLeft", int(days),
				"consecutiveFailures", st.ConsecutiveFailures, "lastError", st.LastError)
		}
	}
}
