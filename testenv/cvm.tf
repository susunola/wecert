###############################################################################
# CVM（阶段 C）—— 真实后端 + systemd/CVM 角色验证
#
# 后端按 Host 头返回不同测试页，用来验证 CLB 的域名路由是否真的生效：
# test.alpha.<域> 显示 ALPHA，test.beta.<域> 显示 BETA。
# 两个域名返回同一个页面 = 路由没生效，一眼就能看出来。
#
# 刻意不装任何软件包：python3 是 Ubuntu 默认自带的，写一个极简 HTTP 服务
# 就够了，省掉 apt 网络依赖的不确定性。TLS 在 CLB 终结，CVM 只说 HTTP。
###############################################################################

resource "tencentcloud_security_group" "test" {
  count = var.create_cvm ? 1 : 0

  name        = "${var.name_prefix}-cvm-sg"
  description = "wecert e2e test - backend CVM, inbound only on 80"
  tags        = local.tags
}

# 只放通到后端的 80 端口。
#
# ⚠️ 0.0.0.0/0 是实测出来的，不是偷懒：
# 公网型 CLB 的健康检查源既不在 VPC 网段，也不在 100.64.0.0/10。
# 只放通那两段时健康检查一直失败，CLB 对所有请求返回 504 ——
# 而 TLS 握手完全正常，所以极易误判成"后端挂了"（实际直连 CVM 返回 200）。
#
# 生产上应该收窄到实际健康检查源，或者干脆别让后端有公网入口。
resource "tencentcloud_security_group_rule_set" "test" {
  count = var.create_cvm ? 1 : 0

  security_group_id = tencentcloud_security_group.test[0].id

  ingress {
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "TCP"
    port        = "80"
    description = "CLB health check + forwarding (test only; narrow in production)"
  }

  # 出网全放通：TAT agent 要连服务端。
  egress {
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "ALL"
    port        = "ALL"
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

  # 改 user_data 必须重建实例，否则新脚本只在**下次开机**才生效 ——
  # 而 terraform plan 只会显示 "updated in-place"，看起来像已经生效了。
  user_data_replace_on_change = true

  # 用 user_data_raw 而不是 user_data：后者要求调用方自己 base64 编码，
  # 直接塞明文会报 InvalidParameterValue.InvalidUserDataFormat。
  user_data_raw = <<-EOF
    #cloud-config
    write_files:
      - path: /srv/www/pages.json
        permissions: '0644'
        content: |
          ${jsonencode(var.backend_pages)}

      - path: /usr/local/bin/wecert-backend
        permissions: '0755'
        content: |
          #!/usr/bin/env python3
          """按 Host 头返回不同测试页的极简后端。

          只用 python3 自带库，不装任何包 —— 测试环境里少一个失败点。
          TLS 在 CLB 终结，这里只说 HTTP。
          """
          import http.server
          import json
          import os

          PAGES_FILE = "/srv/www/pages.json"

          PAGE_TEMPLATE = """<!DOCTYPE html>
          <html lang="zh"><head><meta charset="utf-8"><title>{label}</title></head>
          <body style="font-family:system-ui,sans-serif;text-align:center;padding:4rem">
          <h1 style="font-size:6rem;margin:0;color:{colour}">{label}</h1>
          <p style="font-size:1.2rem">{note}</p>
          <hr style="margin:2rem auto;max-width:24rem">
          <p style="color:#666">Host: <code>{host}</code></p>
          <p style="color:#666">Backend: <code>{backend}</code></p>
          </body></html>
          """


          def load_pages():
              try:
                  with open(PAGES_FILE, encoding="utf-8") as f:
                      return json.load(f)
              except Exception:
                  return {}


          class Handler(http.server.BaseHTTPRequestHandler):
              server_version = "wecert-test-backend"

              def do_GET(self):
                  host = (self.headers.get("Host") or "").split(":")[0].lower()
                  label = load_pages().get(host)
                  if label is None:
                      label = "UNKNOWN"
                      note = "没有为 " + host + " 配置测试页"
                      colour = "#c92a2a"
                  else:
                      note = "这是 " + host + " 的测试页"
                      colour = "#0b7285"

                  payload = PAGE_TEMPLATE.format(
                      label=label,
                      colour=colour,
                      note=note,
                      host=host,
                      backend=os.uname().nodename,
                  ).encode("utf-8")

                  # 一律返回 200：CLB 的健康检查也打这个端点。
                  # 未知 Host 返回 404 会让健康检查失败，CLB 随即对真实请求回 504。
                  self.send_response(200)
                  self.send_header("Content-Type", "text/html; charset=utf-8")
                  self.send_header("Content-Length", str(len(payload)))
                  self.send_header("Cache-Control", "no-store")
                  self.end_headers()
                  self.wfile.write(payload)

              def log_message(self, fmt, *args):
                  print("%s - %s" % (self.address_string(), fmt % args), flush=True)


          if __name__ == "__main__":
              http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()

      - path: /etc/systemd/system/wecert-backend.service
        content: |
          [Unit]
          Description=wecert test backend (per-Host pages)
          After=network.target
          [Service]
          ExecStart=/usr/local/bin/wecert-backend
          Restart=always
          RestartSec=2
          [Install]
          WantedBy=multi-user.target
    runcmd:
      - mkdir -p /srv/www
      - systemctl daemon-reload
      - systemctl enable --now wecert-backend
  EOF

  tags = local.tags
}
