###############################################################################
# DNS 记录 —— 让测试域名可解析，这样直接用浏览器就能测
#
# 之前只能用 curl --resolve 或 openssl -connect 加 IP 来测，
# 因为 test.alpha / test.beta 根本没有解析记录。
#
# alpha / beta 不是独立的 zone，只是 atomwangnus.com 下的子域，
# 所以记录建在 atomwangnus.com 这个 zone 里，sub_domain 是 "test.alpha"。
#
# 这些记录明确带 remark 标记，测试完随 terraform destroy 一起清掉。
###############################################################################

resource "tencentcloud_dnspod_record" "test" {
  count = var.create_dns && var.create_clb ? length(var.clb_rule_domains) : 0

  domain = var.dns_zone

  # "test.alpha.atomwangnus.com" 去掉 ".atomwangnus.com" -> "test.alpha"
  sub_domain = trimsuffix(var.clb_rule_domains[count.index], ".${var.dns_zone}")

  record_type = "A"
  record_line = "默认"
  value       = var.clb_public_ip

  # DNSPod 免费套餐 TTL 下限 600，和 wecert 那边的限制是同一个原因。
  ttl = 600

  remark = "wecert e2e test - safe to delete"
}
