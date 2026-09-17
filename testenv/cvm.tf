###############################################################################
# CVM (stage C) — real backend + systemd/CVM role verification
#
# The backend returns a different test page per Host header, to verify that the
# CLB's domain routing really works: test.alpha.<domain> shows ALPHA and
# test.beta.<domain> shows BETA. Both domains returning the same page means
# routing is not working, and it is obvious at a glance.
#
# It deliberately installs no packages at all: python3 ships with Ubuntu, and a
# minimal HTTP server is enough, which removes the uncertainty of depending on apt
# over the network. TLS terminates at the CLB; the CVM speaks plain HTTP.
###############################################################################

resource "tencentcloud_security_group" "test" {
  count = var.create_cvm ? 1 : 0

  name        = "${var.name_prefix}-cvm-sg"
  description = "wecert e2e test - backend CVM, inbound only on 80"
  tags        = local.tags
}

# Only port 80 toward the backend is allowed.
#
# ⚠️ The 0.0.0.0/0 is empirical, not laziness: a public CLB's health check source
# is neither in the VPC CIDR nor in 100.64.0.0/10. When only those two ranges were
# allowed, health checks kept failing and the CLB returned 504 for every request —
# while the TLS handshake was perfectly fine, so this is very easily misdiagnosed
# as "the backend is down" (direct connections to the CVM actually returned 200).
#
# In production this should be narrowed to the real health check source, or the
# backend should have no public ingress at all.
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

  # Egress is fully open: the TAT agent needs to reach its server.
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
  internet_max_bandwidth_out = 1 # just enough for the TAT agent's egress
  allocate_public_ip         = true

  # Attach the CAM role — the credential method wecert recommends in production:
  # no key ever touches disk; credentials are fetched on demand from the instance
  # metadata service.
  cam_role_name = var.enable_cvm_role ? var.cam_role_name : null

  # Changing user_data must rebuild the instance; otherwise the new script only
  # takes effect on the **next boot** — while terraform plan merely shows
  # "updated in-place", which looks like it already took effect.
  user_data_replace_on_change = true

  # Use user_data_raw rather than user_data: the latter requires the caller to
  # base64-encode it, and passing plaintext fails with
  # InvalidParameterValue.InvalidUserDataFormat.
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
          """Minimal backend returning a different test page per Host header.

          It uses only the python3 standard library and installs no packages —
          one fewer failure point in a test environment. TLS terminates at the
          CLB; this speaks plain HTTP.
          """
          import http.server
          import json
          import os

          PAGES_FILE = "/srv/www/pages.json"

          PAGE_TEMPLATE = """<!DOCTYPE html>
          <html lang="en"><head><meta charset="utf-8"><title>{label}</title></head>
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
                      note = "No test page configured for " + host
                      colour = "#c92a2a"
                  else:
                      note = "Test page for " + host
                      colour = "#0b7285"

                  payload = PAGE_TEMPLATE.format(
                      label=label,
                      colour=colour,
                      note=note,
                      host=host,
                      backend=os.uname().nodename,
                  ).encode("utf-8")

                  # Always return 200: the CLB health check hits this endpoint too.
                  # Returning 404 for an unknown Host would fail the health check,
                  # and the CLB would then answer real requests with 504.
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
      # The whole Stage C runbook drives this machine through TAT, so the agent is
      # a hard dependency -- and it is not always present: the public Ubuntu image
      # this module defaults to (img-487zeit5) booted without it, and every
      # RunCommand then failed with ResourceUnavailable.AgentNotInstalled while
      # DescribeAutomationAgentStatus returned an empty set. Tencent's own
      # installer is idempotent and the instance already has egress, so installing
      # it here makes the module self-sufficient instead of leaving the operator to
      # discover the gap from an error message.
      - wget -qO - https://mirrors.tencentyun.com/install/tat_agent/tat_agent_installer.sh | sh
  EOF

  tags = local.tags
}
