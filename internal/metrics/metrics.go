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

	// DesiredStateErrors 统计"这一轮根本没拿到期望状态"的次数。
	//
	// 它一涨就说明整轮被跳过了：没有任何证书被处理，但也没有任何证书
	// 被误删 —— 那正是"来源失败 ≠ 期望为空"这条不变量的表现。
	DesiredStateErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wecert_desired_state_errors_total",
		Help: "Passes skipped because the desired state could not be read. Skipping is deliberate: an unreadable source is never treated as an empty desired state.",
	})

	// DesiredStateFrozen 表示期望状态是否冻结在上一版。
	//
	// 冻结时续期照常，但新域名不会被纳入。持续为 1 说明来源一直没恢复。
	DesiredStateFrozen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_frozen",
		Help: "1 when the desired state is frozen on the last good revision (renewals continue, new names do not).",
	})

	// DesiredStateCertificates 是当前期望状态里的证书数量。
	DesiredStateCertificates = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_certificates",
		Help: "Number of certificates in the current desired state.",
	})

	// DesiredStateAge 是期望状态文档的年龄（秒）。
	//
	// 它回答的是这套架构特有的那个问题：onboarding 组件还活着吗？
	// 它死了之后一切看起来都正常，只是新域名再也不进来。
	DesiredStateAge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_age_seconds",
		Help: "Age of the desired-state document in seconds. A growing value means the onboarding component stopped refreshing it.",
	})

	// DesiredStateShadowDiff 是 observe 模式下影子来源与当前执行的差异条数。
	//
	// 从 static 切到 enforce 之前，这个指标应该长期为 0。
	DesiredStateShadowDiff = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_desired_state_shadow_diff",
		Help: "In observe mode, the number of certificate-level differences between what is enforced and what the shadow source asks for. Should stay at 0 before switching to enforce.",
	})

	// OrphanedCertificates 统计状态库里有、但期望状态里已经没有的证书。
	//
	// 这类证书不会再被续期，最终会过期 —— 一种无声的失败。
	// 期望状态的删除路径本来就有宽限期和引用检查，这个指标是最后一道兜底。
	OrphanedCertificates = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wecert_orphaned_certificates",
		Help: "Certificates present in the state store but absent from the desired state. They will not be renewed and will eventually expire.",
	})
)
