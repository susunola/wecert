// Package metrics 暴露 Prometheus 指标。
//
// 最要紧的一条是 wecert_certificate_not_after_timestamp_seconds：
// 到期告警应该基于它做（(not_after - time()) < 阈值），
// 而不是基于"续期任务有没有报错" —— 后者会在程序静默失效时保持沉默。
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CertNotAfter 是证书到期时间（unix 秒）。
	CertNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_not_after_timestamp_seconds",
		Help: "当前生效证书的 notAfter（unix 秒）。",
	}, []string{"cert"})

	// CertDeployed 表示证书是否已经成功部署到云端。
	CertDeployed = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_deployed",
		Help: "1 表示已确认绑到腾讯云资源，0 表示尚未绑定（含首次上传后等待人工绑定）。",
	}, []string{"cert"})

	// CertConsecutiveFailures 是连续失败次数，持续大于 0 需要人工介入。
	CertConsecutiveFailures = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_consecutive_failures",
		Help: "连续失败次数。重置为 0 表示最近一次处理成功。",
	}, []string{"cert"})

	// CertARIWindowStart 是 ARI 建议的续期窗口起点。
	CertARIWindowStart = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_ari_window_start_timestamp_seconds",
		Help: "ARI 建议的续期窗口起点（unix 秒），0 表示尚未取得。",
	}, []string{"cert"})

	// ReconcileTotal 记录每张证书的处理结果。
	ReconcileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_reconcile_total",
		Help: "收敛轮次计数，result 取值为 ok / error。",
	}, []string{"cert", "result"})
)
