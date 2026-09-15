// Package metrics 暴露 Prometheus 指标。
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	CertNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_not_after_timestamp_seconds",
		Help: "当前生效证书的 notAfter（unix 秒）。",
	}, []string{"cert"})

	CertDeployed = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_deployed",
		Help: "1 表示已确认绑到腾讯云资源，0 表示尚未绑定（含首次上传后等待人工绑定）。",
	}, []string{"cert"})

	CertConsecutiveFailures = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_consecutive_failures",
		Help: "连续失败次数。重置为 0 表示最近一次处理成功。",
	}, []string{"cert"})

	CertARIWindowStart = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_ari_window_start_timestamp_seconds",
		Help: "ARI 建议的续期窗口起点（unix 秒），0 表示尚未取得。",
	}, []string{"cert"})

	ReconcileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_reconcile_total",
		Help: "收敛轮次计数，result 取值为 ok / error。",
	}, []string{"cert", "result"})
)
