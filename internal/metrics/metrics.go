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
		Help: "notAfter of the live certificate, in unix seconds.",
	}, []string{"cert"})

	// CertDeployed 表示证书是否已经成功部署到云端。
	CertDeployed = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_deployed",
		Help: "1 when the certificate is confirmed bound to a Tencent Cloud resource, 0 otherwise (including the period after the first upload while waiting for a manual bind).",
	}, []string{"cert"})

	// CertConsecutiveFailures 是连续失败次数，持续大于 0 需要人工介入。
	CertConsecutiveFailures = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_consecutive_failures",
		Help: "Consecutive failures. Reset to 0 by a successful pass.",
	}, []string{"cert"})

	// CertARIWindowStart 是 ARI 建议的续期窗口起点。
	CertARIWindowStart = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wecert_certificate_ari_window_start_timestamp_seconds",
		Help: "Start of the ARI-suggested renewal window in unix seconds; 0 means not yet obtained.",
	}, []string{"cert"})

	// ReconcileTotal 记录每张证书的处理结果。
	ReconcileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wecert_reconcile_total",
		Help: "Reconcile passes, with result being ok or error.",
	}, []string{"cert", "result"})
)
