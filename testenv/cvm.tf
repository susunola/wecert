###############################################################################
# CVM（阶段 C）—— 真实后端 + systemd/CVM 角色验证
#
# 用 TAT（自动化助手）在机器上跑命令，因此不需要 SSH 密钥，
# 也不需要在安全组上开放任何公网入站端口。
#
# 后端刻意不装任何软件包：python3 是 Ubuntu 默认自带的，
# 用它起一个静态 HTTP 服务就够了，省掉 apt 网络依赖的不确定性。
# TLS 在 CLB 终结，CVM 只需要说 HTTP。
###############################################################################

resource "tencentcloud_security_group" "test" {
  count = var.create_cvm ? 1 : 0

  name        = "${var.name_prefix}-sg"
  description = "wecert e2e test - inbound only from VPC (CLB health check + forwarding)"
  tags        = local.tags
}

# 只放通 VPC 网段到 80：CLB 的健康检查和流量转发都来自 VPC 内部。
# 不给任何公网入站 —— 排障走 TAT，不需要 SSH。
#
# 用 rule_set 而不是已被弃用的 security_group_lite_rule
# （provider 1.81.90 起标记 deprecated）。
resource "tencentcloud_security_group_rule_set" "test" {
  count = var.create_cvm ? 1 : 0

  security_group_id = tencentcloud_security_group.test[0].id

  ingress {
    action     = "ACCEPT"
    cidr_block = tencentcloud_vpc.test[0].cidr_block
    protocol   = "TCP"
    port       = "80"
    description = "CLB health check and forwarding, from inside the VPC"
  }

  # ⚠️ 公网型 CLB 的健康检查源实测**不在** VPC 网段，也不在
  # 100.64.0.0/10。只放通这两段时，健康检查一直失败，
  # CLB 会对所有请求返回 504（TLS 握手正常，所以很容易误判成后端挂了）。
  #
  # 这里放开 0.0.0.0/0 是为了让测试可复现。生产上应当把这个段收窄到
  # 实际健康检查源 —— 或者在 CLB 前面就不要让后端直接暴露。
  # 内网型 CLB 只需上面那条 VPC 规则即可。
  ingress {
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "TCP"
    port        = "80"
    description = "public CLB health check + forwarding (test only; narrow in production)"
  }

  # 出网全放通：TAT agent 要连服务端。
  egress {
    action     = "ACCEPT"
    cidr_block = "0.0.0.0/0"
    protocol   = "ALL"
    port       = "ALL"
    description = "TAT agent egress"
  }
}

resource "tencentcloud_instance" "test" {
  count = var.create_cvm ? 1 : 0

  instance_name              = "${var.name_prefix}-cvm"
  availability_zone          = var.availability_zone
  image_id                   = var.cvm_image_id
  instance_type              = var.cvm_instance_type
  instance_charge_type       = var.cvm_charge_type
  vpc_id                     = tencentcloud_vpc.test[0].id
  subnet_id                  = tencentcloud_subnet.test[0].id
  security_groups            = [tencentcloud_security_group.test[0].id]
  internet_charge_type       = "TRAFFIC_POSTPAID_BY_HOUR"
  internet_max_bandwidth_out = 1 # 够 TAT agent 出网即可
  allocate_public_ip         = true

  # 关联 CAM 角色 —— wecert 生产环境推荐的凭证方式：
  # 密钥不落盘，从实例元数据服务现取现用。
  cam_role_name = var.enable_cvm_role ? var.cam_role_name : null

  # 用 user_data_raw 而不是 user_data：后者要求调用方自己 base64 编码，
  # 直接塞明文会报 InvalidParameterValue.InvalidUserDataFormat。
  user_data_raw = <<-EOF
    #cloud-config
    write_files:
      - path: /usr/local/bin/wecert-backend
        permissions: '0755'
        content: |
          #!/bin/sh
          # 极简后端：python3 是 Ubuntu 默认自带，不装任何包。
          mkdir -p /srv/www
          printf 'wecert-test-backend host=%s\n' "$(hostname)" > /srv/www/index.html
          exec python3 -m http.server 80 --directory /srv/www
      - path: /etc/systemd/system/wecert-backend.service
        content: |
          [Unit]
          Description=wecert test backend
          After=network.target
          [Service]
          ExecStart=/usr/local/bin/wecert-backend
          Restart=always
          RestartSec=2
          [Install]
          WantedBy=multi-user.target
    runcmd:
      - systemctl daemon-reload
      - systemctl enable --now wecert-backend
  EOF

  tags = local.tags
}

