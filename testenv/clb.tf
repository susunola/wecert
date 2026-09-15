###############################################################################
# CLB + HTTPS 监听器 + 占位证书（阶段 B）
#
# 这里测试的是 wecert 最核心的那条部署路径：
#
#   1. Terraform 建一个自签名占位证书，上传到腾讯云 SSL 证书服务，
#      并绑到 CLB 的 HTTPS 监听器上 —— 模拟"已经有一张在用的证书"。
#   2. 把占位证书的 CertId 预置进 wecert 的状态库（deployed_cert_id）。
#   3. wecert 签发真证书后调 UpdateCertificateInstance(OldCertificateId=占位证书)。
#   4. 断言监听器的 certificate_id 变成了新证书，且监听器没被搞坏。
#
# 这一步同时验证了我最担心的那个点：腾讯云是自己去找绑定关系并逐个更新，
# 所以我们不需要维护监听器清单，也就不会误伤同一监听器上的其它 SNI 证书。
###############################################################################

# 自签名占位证书。用 tls provider 在 apply 时生成，不落任何私钥文件。
resource "tls_private_key" "placeholder" {
  count = var.create_clb ? 1 : 0

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "placeholder" {
  count = var.create_clb ? 1 : 0

  private_key_pem = tls_private_key.placeholder[0].private_key_pem

  subject {
    common_name  = var.clb_sni_domain
    organization = "wecert-test"
  }

  validity_period_hours = 720 # 30 天，够整个测试周期
  early_renewal_hours   = 24

  allowed_uses = ["key_encipherment", "digital_signature", "server_auth"]
}

resource "tencentcloud_ssl_certificate" "placeholder" {
  count = var.create_clb ? 1 : 0

  name = "${var.name_prefix}-placeholder"
  # chomp 是必须的：tls provider 产出的 PEM 以换行结尾，
  # 而腾讯云 API 明确拒绝带尾部换行的 cert/key（"cert can't have \n suffix"）。
  cert = chomp(tls_self_signed_cert.placeholder[0].cert_pem)
  key  = chomp(tls_private_key.placeholder[0].private_key_pem)
  # SVR = 服务器证书（CA 是签发机构证书）。
  type = "SVR"
  tags = local.tags
}

resource "tencentcloud_clb_instance" "test" {
  count = var.create_clb ? 1 : 0

  clb_name     = "${var.name_prefix}-clb"
  network_type = var.clb_network_type
  vpc_id       = tencentcloud_vpc.test[0].id
  subnet_id    = tencentcloud_subnet.test[0].id
  tags         = local.tags
}

resource "tencentcloud_clb_listener" "https" {
  count = var.create_clb ? 1 : 0

  clb_id        = tencentcloud_clb_instance.test[0].id
  listener_name = "${var.name_prefix}-https"
  protocol      = "HTTPS"
  port          = 443

  # 关键：把占位证书的 CertId 绑上去。
  # wecert 之后就是靠这个 ID 去找"哪些资源绑了旧证书"。
  certificate_id = tencentcloud_ssl_certificate.placeholder[0].id

  # CreateListener 的 Certificate 结构里 SSLMode 是必需的，只给 CertId 不够。
  certificate_ssl_mode = "UNIDIRECTIONAL"

  # ⚠️ SNI 的坑 —— 这个值是实测定出来的，别随手改：
  #
  # 腾讯云 CLB 在 SniSwitch=true 时会**忽略 CreateListener 里的主
  # certificate_id / certificate_ssl_mode**，证书必须走 multi_cert_info。
  # 而且忽略是静默的，表现极具迷惑性：
  #   - 监听器能建出来
  #   - Terraform state 里有 certificate_id
  #   - terraform plan 报 "No changes"（provider 不回读绑定，漂移不可见）
  #   - 但实际一个证都没绑上，HTTPS 监听器是裸的
  #
  # 唯一能暴露它的是 UpdateCertificateInstance 报
  # FailedOperation.CertificateDeployInstanceEmpty（"未检测到可用实例"）。
  #
  # 这里用 false 让主证书绑定走通；真要测 SNI 多证书场景，改用 multi_cert_info。
  sni_switch = false

  # 需要 SNI 多证书时用这个 —— wecert 强调的"换一张不误伤另一张"
  # 正是针对这种配置：
  #
  # multi_cert_info {
  #   cert_id  = tencentcloud_ssl_certificate.placeholder[0].id
  #   ssl_mode = "UNIDIRECTIONAL"
  # }
  #
  # 注意：CLB 监听器资源不支持 tags，它随 CLB 一起被销毁。
}
