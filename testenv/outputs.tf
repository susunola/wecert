###############################################################################
# Outputs: what verification and the follow-up steps need
###############################################################################

output "region" {
  description = "Region the resources live in."
  value       = var.region
}

# ── stage B: CLB ────────────────────────────────────────────────────────────

output "clb_id" {
  description = "CLB instance ID."
  value       = var.create_clb ? tencentcloud_clb_instance.test[0].id : null
}

output "listener_id" {
  description = "HTTPS listener ID. Verifying the rebind means looking at its certificate_id."
  value       = var.create_clb ? tencentcloud_clb_listener.https[0].listener_id : null
}

# This value is seeded into the wecert state store's deployed_cert_id to simulate
# "the certificate wecert manages is currently bound to the listener".
output "placeholder_cert_id" {
  description = "CertId of the placeholder cert. Once seeded into wecert's deployed_cert_id, renewal triggers UpdateCertificateInstance."
  value       = var.create_clb ? tencentcloud_ssl_certificate.placeholder[0].id : null
}

output "placeholder_domain" {
  description = "Domain of the placeholder certificate."
  value       = var.clb_sni_domain
}

# ── network ─────────────────────────────────────────────────────────────────

output "vpc_id" {
  value = (var.create_clb || var.create_cvm) ? tencentcloud_vpc.test[0].id : null
}

output "subnet_id" {
  value = (var.create_clb || var.create_cvm) ? tencentcloud_subnet.test[0].id : null
}

# ── stage C: CVM ────────────────────────────────────────────────────────────

output "cvm_instance_id" {
  description = "CVM instance ID. Use TAT to run commands on it; SSH is not needed."
  value       = var.create_cvm ? tencentcloud_instance.test[0].id : null
}

output "cvm_public_ip" {
  description = "CVM public IP."
  value       = var.create_cvm ? tencentcloud_instance.test[0].public_ip : null
}

output "cvm_cam_role" {
  description = "CAM role attached to the CVM. Empty means the static credential path is used."
  value       = var.create_cvm ? var.enable_cvm_role ? var.cam_role_name : "" : null
}

output "cvm_private_ip" {
  description = "CVM private IP. This is what the target group registers the backend by."
  value       = var.create_cvm ? tencentcloud_instance.test[0].private_ip : null
}

# ── needed for end-to-end TLS verification ──────────────────────────────────

output "clb_vip" {
  description = "The CLB's VIP. Curling this address from inside the CVM reads the certificate actually being served."
  value       = var.create_clb ? tencentcloud_clb_instance.test[0].vip : null
}

output "verify_command" {
  description = "Command template for end-to-end TLS verification from inside the CVM (replace <domain> with the real domain)."
  value = var.create_clb && var.create_cvm ? join(" ", [
    "./bin/wecert-tatrun",
    "-region", var.region,
    "-instance", tencentcloud_instance.test[0].id,
    "-cmd", "'echo | openssl s_client -connect <domain>:443 -servername <domain> -showcerts 2>/dev/null | openssl x509 -noout -subject -dates'",
  ]) : null
}

# ── URLs to open directly from your machine ─────────────────────────────────

output "test_urls" {
  description = "Open these in a browser to see the matching test page (provided the DNS records exist and your egress IP is in clb_allowed_cidrs)."
  value = var.create_clb && var.create_cvm ? {
    for d in var.clb_rule_domains : d => "https://${d}/  ->  ${lookup(var.backend_pages, d, "UNKNOWN")}"
  } : null
}

output "dns_records_created" {
  description = "A records created for the test (cleaned up along with destroy when testing is done)."
  value       = var.create_dns && var.create_clb ? [for r in tencentcloud_dnspod_record.test : "${r.sub_domain}.${var.dns_zone} -> ${r.value}"] : []
}

output "clb_access_from" {
  description = "Source CIDRs allowed to reach CLB:443. Empty means no security group is attached (open to the whole internet)."
  value       = var.clb_allowed_cidrs
}

# ── teardown reminder ───────────────────────────────────────────────────────

output "teardown_command" {
  description = "Destroy all test resources."
  value       = "cd ${abspath(path.module)} && terraform destroy -auto-approve"
}
