###############################################################################
# wecert 测试环境 —— 变量
#
# 设计原则：所有资源都带统一 tag，且全部由 Terraform 管理，
# 保证 `terraform destroy` 能一件不剩地清干净，不留孤儿计费资源。
###############################################################################

variable "region" {
  description = "地域。CLB 是分地域资源，必须和你实际要用的地域一致。"
  type        = string
  default     = "ap-guangzhou"
}

variable "availability_zone" {
  description = "可用区。必须属于上面的 region。"
  type        = string
  default     = "ap-guangzhou-3"
}

variable "name_prefix" {
  description = "所有资源统一前缀，便于识别和清理。"
  type        = string
  default     = "wecert-test"
}

# ── 测试阶段开关 ────────────────────────────────────────────────────────────
#
# 阶段 A（wildcard 签发）：不需要任何云资源，这个模块都不用 apply。
# 阶段 B（验证 UpdateCertificateInstance 重绑定）：create_clb = true
# 阶段 C（验证 systemd + CVM 角色）：create_cvm = true（依赖 create_clb）

variable "create_clb" {
  description = "是否创建 VPC + CLB + HTTPS 监听器（阶段 B）。"
  type        = bool
  default     = true
}

variable "create_cvm" {
  description = "是否额外创建 CVM（阶段 C：验证 systemd 与 CVM 角色凭证）。"
  type        = bool
  default     = false
}

variable "clb_network_type" {
  description = "CLB 网络类型。INTERNAL 不产生公网带宽/EIP 费用，够用即可。"
  type        = string
  default     = "INTERNAL"

  validation {
    condition     = contains(["INTERNAL", "OPEN"], var.clb_network_type)
    error_message = "clb_network_type 只能是 INTERNAL 或 OPEN。"
  }
}

variable "clb_sni_domain" {
  description = "绑定到监听器上的占位证书域名。wecert 续期后会替换掉它。"
  type        = string
  default     = "placeholder.atomwangnus.com"
}

variable "cvm_instance_type" {
  description = "CVM 规格。默认 2C2G 最低配。"
  type        = string
  default     = "S5.MEDIUM2"
}

variable "cvm_image_id" {
  description = "CVM 镜像 ID，默认 Ubuntu 22.04。不同地域镜像 ID 不同，必要时覆盖。"
  type        = string
  default     = "img-487zeit5" # Ubuntu Server 22.04 LTS 64bit (ap-guangzhou)
}

variable "cvm_charge_type" {
  description = "CVM 计费方式。按量计费便于随时销毁。"
  type        = string
  default     = "POSTPAID_BY_HOUR"
}

variable "enable_cvm_role" {
  description = "为 CVM 关联 CAM 角色（验证 wecert 的 cvm-role 凭证路径）。"
  type        = bool
  default     = false
}

variable "cam_role_name" {
  description = "要关联到 CVM 的 CAM 角色名。"
  type        = string
  default     = "wecert-test-role"
}

locals {
  # 统一 tag，方便在控制台一眼认出哪些是测试资源、以及事后清理。
  #
  # 注意：不要用 `project` 作 key —— 它是腾讯云的保留 tag key，
  # 会直接报 UnsupportedOperation.TagSystemReservedTagKey，
  # 而且是资源创建到一半才失败。
  tags = {
    app        = "wecert"
    purpose    = "acme-e2e-test"
    managed-by = "terraform"
  }
}
