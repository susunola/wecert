// Package deploy 负责把签发好的证书推送到真正的消费方。
//
// 本项目的形态是"TLS 在腾讯云 CLB 终结"，所以节点上没有任何 agent、
// 也没有证书文件分发 —— 整个部署动作就是几次腾讯云 API 调用。
package deploy

import "context"

// Deployer 是部署目标的抽象。
//
// 之所以做成接口：腾讯云有两条路可以走，控制器不应该关心是哪条。
//
//   - UpdateCertificateInstance（公开，本项目默认）：
//     上传新证书拿到新 CertId，再由腾讯云自己去查"哪些 CLB 监听器绑了旧证书"
//     并换成新的。好处是我们完全不用维护监听器清单，
//     同一监听器上 SNI 多证书也不会被误覆盖。
//
//   - UploadUpdateCertificateInstance（需提工单开白名单）：
//     证书 ID 保持不变、内容原地替换，部署目标仅支持 clb。
//     唯一的额外好处是省掉一次 CertId 变更，属于锦上添花。
type Deployer interface {
	// Deploy 推送新证书，返回部署后应记录的证书标识。
	// oldID 为空表示首次签发（腾讯云侧还没有绑定关系）。
	Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (newID string, err error)

	// Delete 删除一张已经退役的证书，用于控制腾讯云侧证书数量不无限增长。
	Delete(ctx context.Context, certID string) error
}

// Noop 在 deploy.enabled=false 时使用：只把证书留在本地状态库里。
type Noop struct{}

// Deploy 原样返回 oldID，不做任何远端操作。
func (Noop) Deploy(_ context.Context, _ string, oldID string, _, _ []byte) (string, error) {
	return oldID, nil
}

// Delete 什么都不做。
func (Noop) Delete(_ context.Context, _ string) error { return nil }
