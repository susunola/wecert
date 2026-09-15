###############################################################################
# CLB + HTTPS 监听器（SNI 模式）+ 目标组（阶段 B/C）
#
# 这个版本测试的是比上次更严格的一组场景：
#
#   1. 一张证书带 2 个 wildcard SAN（*.alpha / *.beta）
#   2. SNI 模式 —— 正是上次踩坑的地方：SniSwitch=true 时服务端会忽略
#      主 certificate_id，证书必须走 multi_cert_info。这里就走这条正确的路。
#   3. 监听器挂真实后端（CVM），可以做端到端 TLS 验证而不只是看 API 返回。
#
# 流程：Terraform 建自签占位证书并绑到监听器 → 预置进 wecert 状态库 →
# wecert 签发真证书 → UpdateCertificateInstance 重绑定 →
# 从 CVM 内部 curl CLB VIP 读实际服务的证书。
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

  # 公网型 CLB 不能指定 SubnetId（会报
  # "You can't specify parameter SubnetId when create open loadbalancer"），
  # 内网型则必须指定。
  subnet_id = var.clb_network_type == "INTERNAL" ? tencentcloud_subnet.test[0].id : null

  # 公网型才需要带宽配置。按流量计费 + 1Mbps，测试用几乎不产生费用。
  internet_charge_type       = var.clb_network_type == "OPEN" ? "TRAFFIC_POSTPAID_BY_HOUR" : null
  internet_bandwidth_max_out = var.clb_network_type == "OPEN" ? 1 : null

  tags         = local.tags
}

resource "tencentcloud_clb_listener" "https" {
  count = var.create_clb ? 1 : 0

  clb_id        = tencentcloud_clb_instance.test[0].id
  listener_name = "${var.name_prefix}-https"
  protocol      = "HTTPS"
  port          = 443

  # ⚠️ SNI 模式下的关键：主 certificate_id / certificate_ssl_mode 会被
  # 服务端**静默忽略**，证书必须通过 multi_cert_info 配置。
  #
  # 这个坑的表现极具迷惑性：监听器能建出来、Terraform state 里有
  # certificate_id、terraform plan 报 "No changes"（provider 不回读绑定），
  # 但实际一个证都没绑上。唯一能暴露它的是 UpdateCertificateInstance 报
  # FailedOperation.CertificateDeployInstanceEmpty。
  sni_switch = true

  multi_cert_info {
    cert_id_list = [tencentcloud_ssl_certificate.placeholder[0].id]
    ssl_mode     = "UNIDIRECTIONAL"
  }

  # ⚠️ 证书绑定交给 wecert 管，Terraform 不要碰。
  #
  # 否则会打架：Terraform 的 certificate_id / multi_cert_info 是期望状态，
  # 每次 apply 都会把它刷回这里配置的占位证书，
  # 而 wecert 是通过 UpdateCertificateInstance 在带外改这个字段的。
  # 实测就是这样：几轮 apply 之后，两条规则的证书被悄悄改回了占位证书，
  # 而 wecert 状态库还以为部署的是新证书 —— 两边认知不一致。
  lifecycle {
    ignore_changes = [multi_cert_info, certificate_id, certificate_ssl_mode]
  }

  # 注意：CLB 监听器资源不支持 tags，它随 CLB 一起被销毁。
}

# ── 后端：按域名建转发规则 + 挂同一个 CVM ───────────────────────────────────
#
# HTTPS 是七层监听器，必须有转发规则才能挂后端；
# 而且腾讯云不允许 url 兜底的默认规则 —— 每条规则必须带域名。
# 所以这里一个 wildcard 域名一条规则，两条规则挂同一个 CVM。
#
# 用经典的 tencentcloud_clb_attachment 而不是目标组：
# 目标组资源在当前账号下会报
# "Current account do not support to create v1 target group"。

resource "tencentcloud_clb_listener_rule" "wildcard" {
  count = var.create_clb && var.create_cvm ? length(var.clb_rule_domains) : 0

  clb_id      = tencentcloud_clb_instance.test[0].id
  listener_id = tencentcloud_clb_listener.https[0].listener_id

  domain = var.clb_rule_domains[count.index]
  url    = "/"

  # 证书要挂在**规则**上，不是只在监听器上。
  # 这正是 CLB 实现 SNI 多证书的方式：每个域名一条规则，规则各自带证书。
  # 少了它，建规则时会报 "Lack of parameter Certificate or MultiCertInfo"。
  certificate_id       = tencentcloud_ssl_certificate.placeholder[0].id
  certificate_ssl_mode = "UNIDIRECTIONAL"

  health_check_switch       = true
  health_check_type         = "HTTP"
  health_check_http_path    = "/"
  health_check_interval_time = 5
  health_check_time_out     = 2
  health_check_health_num   = 3
  health_check_unhealth_num = 3
  # 注意：不要设 health_check_http_code —— 它是位掩码（1~31），
  # 不是 HTTP 状态码，填 200 会直接报 "cannot be higher than 31"。

  # 同上：证书绑定归 wecert 管，Terraform 不要覆盖。
  lifecycle {
    ignore_changes = [certificate_id, certificate_ssl_mode, certificate_ca_id]
  }
}

resource "tencentcloud_clb_attachment" "wildcard" {
  count = var.create_clb && var.create_cvm ? length(var.clb_rule_domains) : 0

  clb_id      = tencentcloud_clb_instance.test[0].id
  listener_id = tencentcloud_clb_listener.https[0].listener_id
  rule_id     = tencentcloud_clb_listener_rule.wildcard[count.index].rule_id

  # 两条规则挂同一个 CVM —— 后端不区分域名。
  targets {
    instance_id = tencentcloud_instance.test[0].id
    port        = 80
    weight      = 10
  }
}

# ── CLB 安全组 ──────────────────────────────────────────────────────────────
#
# 公网型 CLB 默认对全网开放。挂一个安全组把它收窄到只允许你本机访问。
#
# 注意这里管的是**到达 CLB 443** 的流量，和后端 CVM 的安全组是两回事：
# 后者管的是 CLB → CVM 的健康检查与转发。
#
# 出口 IP 变了就会把自己关在门外，改 clb_allowed_cidrs 重新 apply 即可。

resource "tencentcloud_security_group" "clb" {
  count = var.create_clb && length(var.clb_allowed_cidrs) > 0 ? 1 : 0

  name        = "${var.name_prefix}-clb-sg"
  description = "wecert e2e test - who may reach the public CLB"
  tags        = local.tags
}

resource "tencentcloud_security_group_rule_set" "clb" {
  count = var.create_clb && length(var.clb_allowed_cidrs) > 0 ? 1 : 0

  security_group_id = tencentcloud_security_group.clb[0].id

  dynamic "ingress" {
    for_each = var.clb_allowed_cidrs
    content {
      action      = "ACCEPT"
      cidr_block  = ingress.value
      protocol    = "TCP"
      port        = "443"
      description = "test access to HTTPS listener"
    }
  }

  # 出网不限制：CLB 只是被动接流量。
  egress {
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "ALL"
    port        = "ALL"
    description = "egress"
  }
}

resource "tencentcloud_clb_security_group_attachment" "clb" {
  count = var.create_clb && length(var.clb_allowed_cidrs) > 0 ? 1 : 0

  load_balancer_ids = [tencentcloud_clb_instance.test[0].id]
  security_group    = tencentcloud_security_group.clb[0].id
}
