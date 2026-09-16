###############################################################################
# DNS records — make the test domains resolvable so a browser can test them
#
# Previously the only way to test was curl --resolve or openssl -connect with an
# IP, because test.alpha / test.beta had no resolution records at all.
#
# alpha / beta are not separate zones, only subdomains of the dns_zone apex, so
# the records are created in that zone with sub_domain "test.alpha".
#
# These records carry an explicit remark and are cleaned up by terraform destroy
# when testing is done.
###############################################################################

resource "tencentcloud_dnspod_record" "test" {
  count = var.create_dns && var.create_clb && var.clb_public_ip != "" ? length(var.clb_rule_domains) : 0

  domain = var.dns_zone

  # "test.alpha.example.com" minus ".example.com" -> "test.alpha"
  sub_domain = trimsuffix(var.clb_rule_domains[count.index], ".${var.dns_zone}")

  record_type = "A"
  record_line = "\u9ed8\u8ba4" # DNSPod's built-in "default" line; the escape keeps this source free of CJK
  value       = var.clb_public_ip

  # The DNSPod free tier's TTL floor is 600, for the same reason as the limit on the wecert side.
  ttl = 600

  remark = "wecert e2e test - safe to delete"
}
