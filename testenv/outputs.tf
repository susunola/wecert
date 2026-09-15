###############################################################################
# 输出：验证和后续步骤需要的东西
###############################################################################

output "region" {
  description = "资源所在地域。"
  value       = var.region
}

# ── 阶段 B：CLB ─────────────────────────────────────────────────────────────

output "clb_id" {
  description = "CLB 实例 ID。"
  value       = var.create_clb ? tencentcloud_clb_instance.test[0].id : null
}

output "listener_id" {
  description = "HTTPS 监听器 ID。验证重绑定时要看它的 certificate_id。"
  value       = var.create_clb ? tencentcloud_clb_listener.https[0].listener_id : null
}

# 这个值要预置进 wecert 状态库的 deployed_cert_id，
# 用来模拟"wecert 管理的证书当前已经绑在监听器上"。
output "placeholder_cert_id" {
  description = "占位证书的 CertId。预置到 wecert 的 deployed_cert_id 后，续期就会触发 UpdateCertificateInstance。"
  value       = var.create_clb ? tencentcloud_ssl_certificate.placeholder[0].id : null
}

output "placeholder_domain" {
  description = "占位证书的域名。"
  value       = var.clb_sni_domain
}

# ── 网络 ────────────────────────────────────────────────────────────────────

output "vpc_id" {
  value = (var.create_clb || var.create_cvm) ? tencentcloud_vpc.test[0].id : null
}

output "subnet_id" {
  value = (var.create_clb || var.create_cvm) ? tencentcloud_subnet.test[0].id : null
}

# ── 阶段 C：CVM ─────────────────────────────────────────────────────────────

output "cvm_instance_id" {
  description = "CVM 实例 ID。用 TAT 在上面跑命令，不需要 SSH。"
  value       = var.create_cvm ? tencentcloud_instance.test[0].id : null
}

output "cvm_public_ip" {
  description = "CVM 公网 IP。"
  value       = var.create_cvm ? tencentcloud_instance.test[0].public_ip : null
}

output "cvm_cam_role" {
  description = "CVM 关联的 CAM 角色。为空说明走的是静态凭证路径。"
  value       = var.create_cvm ? var.enable_cvm_role ? var.cam_role_name : "" : null
}

output "cvm_private_ip" {
  description = "CVM 内网 IP。目标组就是按它注册后端的。"
  value       = var.create_cvm ? tencentcloud_instance.test[0].private_ip : null
}

# ── 端到端 TLS 验证所需 ─────────────────────────────────────────────────────

output "clb_vip" {
  description = "CLB 的 VIP。从 CVM 内部 curl 这个地址就能读到实际服务的证书。"
  value       = var.create_clb ? tencentcloud_clb_instance.test[0].vip : null
}

output "verify_command" {
  description = "从 CVM 内部做端到端 TLS 验证的命令模板（把 <域名> 换成实际域名）。"
  value = var.create_clb && var.create_cvm ? join(" ", [
    "./bin/wecert-tatrun",
    "-region", var.region,
    "-instance", tencentcloud_instance.test[0].id,
    "-cmd", "'echo | openssl s_client -connect <域名>:443 -servername <域名> -showcerts 2>/dev/null | openssl x509 -noout -subject -dates'",
  ]) : null
}

# ── 清理提醒 ────────────────────────────────────────────────────────────────

output "teardown_command" {
  description = "销毁全部测试资源。"
  value       = "cd ${abspath(path.module)} && terraform destroy -auto-approve"
}
