###############################################################################
# wecert test environment — variables
#
# Design principle: every resource carries a uniform tag and is managed entirely by
# Terraform, so `terraform destroy` cleans up every last one and leaves no orphaned
# billable resources.
###############################################################################

variable "region" {
  description = "Region. CLB is a regional resource, so this must match the region you actually use."
  type        = string
  default     = "ap-guangzhou"
}

variable "availability_zone" {
  description = <<-EOT
    Availability zone. It must belong to the region above, and it must be a zone
    where CVM is actually sellable for this account (a subnet being creatable does
    not mean a CVM can boot there).

    Do not hard-code a guess: use `terraform plan` and read the available_zones
    output, or look up data.tencentcloud_availability_zones.cvm.zones temporarily.
    ap-guangzhou-3 reports InvalidZone.MismatchRegion under this account.
  EOT
  type        = string
  default     = "ap-guangzhou-6"
}

variable "name_prefix" {
  description = "Uniform prefix for all resources, to make them easy to identify and clean up."
  type        = string
  default     = "wecert-test"
}

# ── test stage switches ─────────────────────────────────────────────────────
#
# Stage A (wildcard issuance): needs no cloud resources; this module need not be
# applied at all.
# Stage B (verify the UpdateCertificateInstance rebind): create_clb = true
# Stage C (verify systemd + the CVM role): create_cvm = true (requires create_clb)

variable "create_clb" {
  description = "Whether to create the VPC + CLB + HTTPS listener (stage B)."
  type        = bool
  default     = true
}

variable "create_cvm" {
  description = "Whether to additionally create a CVM (stage C: verify systemd and CVM role credentials)."
  type        = bool
  default     = false
}

variable "clb_network_type" {
  description = <<-EOT
    CLB network type.
    INTERNAL: internal, incurs no public bandwidth cost, but can only be verified
              from inside the VPC.
    OPEN    : public, allows black-box probing from outside (reading the
              certificate actually being served), at the cost of public bandwidth.
  EOT
  type        = string
  default     = "OPEN"

  validation {
    condition     = contains(["INTERNAL", "OPEN"], var.clb_network_type)
    error_message = "clb_network_type must be INTERNAL or OPEN."
  }
}

variable "clb_sni_domain" {
  description = "Domain of the placeholder certificate bound to the listener. wecert replaces it on renewal."
  type        = string
  default     = "placeholder.wecert-test.invalid"
}

variable "clb_rule_domains" {
  description = <<-EOT
    Domain list for the CLB layer-7 forwarding rules. Tencent Cloud does not allow
    a url-fallback default rule; every rule must carry a domain, so this is one
    rule per domain.

    Note: use **concrete hostnames** here, not wildcards. The provider uses the
    rule domain as the health check Host, and the health check's HttpCheckDomain
    explicitly rejects wildcards:
      "HttpCheckDomain:*.alpha.example.com can't be regular expression or wildcards"
    A concrete hostname is still covered by the certificate's wildcard
    (*.alpha.example.com includes test.alpha.example.com), so this does not affect
    verification.
  EOT
  type        = list(string)
  default     = ["test.alpha.wecert-test.invalid", "test.beta.wecert-test.invalid"]
}

variable "backend_pages" {
  description = <<-EOT
    Test pages the backend returns per Host header. The key is the Host (the CLB
    forwarding rule's domain) and the value is the large label shown on the page.
    A Host with no entry shows UNKNOWN, so whether the CLB routes correctly is
    obvious at a glance.
  EOT
  type        = map(string)
  default = {
    "test.alpha.wecert-test.invalid" = "ALPHA"
    "test.beta.wecert-test.invalid"  = "BETA"
  }
}

variable "clb_allowed_cidrs" {
  description = <<-EOT
    Source CIDRs allowed to reach CLB:443.

    Empty means no security group is attached (the CLB is open to the whole
    internet) — acceptable in a test environment, but a public CLB carrying a real
    certificate and test pages is safer when narrowed.

    There is a reason the default is wide open (0.0.0.0/0); do not rush to tighten
    it: during one session the local egress IP was observed changing from
    121.35.103.225 to 14.153.66.173, and different probing services reported a
    third address — the egress address is not stable. On top of that, there is no
    way to know the network egress the browser sits behind, and one mistake in the
    allowlist locks you out, while diagnosing that (the TLS handshake is simply
    reset) is not intuitive.

    Once you have confirmed a fixed egress IP, change this to ["x.x.x.x/32"] and
    re-apply to tighten it. Look up the egress IP with:
    curl -s https://ifconfig.me/ip
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "dns_zone" {
  description = "DNSPod apex domain the test domains live in (records are created under this zone)."
  type        = string
  default     = "wecert-test.invalid"
}

variable "create_dns" {
  description = "Whether to create A records pointing at the CLB for the forwarding-rule domains, so a browser can reach them directly."
  type        = bool
  default     = true
}

variable "clb_public_ip" {
  description = <<-EOT
    Public IP of the CLB, used for the DNS A record.

    A public CLB in the Guangzhou region gets no static VIP, only a
    *.clb.gz-tencentclb.net domain, and that domain does not resolve on some
    resolvers (observed: the local router returns NXDOMAIN while DNSPod public DNS
    resolves it). So the DNS record points straight at the IP with an A record,
    which is more reliable than a CNAME to that domain.

    This value has to be updated when the CLB changes or the environment is rebuilt.
    There is no meaningful default — set it in terraform.tfvars after stage B outputs
    the CLB address.
  EOT
  type        = string
  default     = ""
}

variable "cvm_instance_type" {
  description = "CVM instance type. Defaults to the smallest 2C2G configuration."
  type        = string
  default     = "S5.MEDIUM2"
}

variable "cvm_image_id" {
  description = "CVM image ID, Ubuntu 22.04 by default. Image IDs differ per region; override when needed."
  type        = string
  default     = "img-487zeit5" # Ubuntu Server 22.04 LTS 64bit (ap-guangzhou)
}

variable "cvm_charge_type" {
  description = "CVM billing mode. Pay-as-you-go makes it easy to destroy at any time."
  type        = string
  default     = "POSTPAID_BY_HOUR"
}

variable "enable_cvm_role" {
  description = "Attach a CAM role to the CVM (to verify wecert's cvm-role credential path)."
  type        = bool
  default     = false
}

variable "cam_role_name" {
  description = "Name of the CAM role to attach to the CVM."
  type        = string
  default     = "wecert-test-role"
}

locals {
  # Uniform tags, so test resources are recognizable at a glance in the console and
  # easy to clean up afterwards.
  #
  # Note: do not use `project` as a key — it is a reserved Tencent Cloud tag key,
  # which fails with UnsupportedOperation.TagSystemReservedTagKey, and only halfway
  # through creating the resource.
  tags = {
    app        = "wecert"
    purpose    = "acme-e2e-test"
    managed-by = "terraform"
  }
}
