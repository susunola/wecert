# wecert test environment

<a href="README.zh-CN.md">简体中文</a> · <b>English</b>

Test resources managed with Terraform. **Everything lives in this module, so a
single `terraform destroy` wipes it clean and leaves no orphaned billables.**

Three stages, increasing in cost. **Get stage A working before deciding whether to
go further.**

---

## Stage A: wildcard issuance — needs no cloud resources

This is counter-intuitive but important: **testing a wildcard certificate needs
neither a CLB nor a CVM.**

A wildcard can only use DNS-01, which means:
- write one `_acme-challenge.<domain>` TXT record
- wait for it to propagate to every authoritative NS
- tell LE to validate

The whole run is DNS API calls. Once the certificate is issued, uploading it to
Tencent Cloud SSL Certificate Service is likewise just API calls — **nothing needs
to be bound to it**.

```bash
# use the dedicated wildcard config (domain must include both the apex and the wildcard)
./scripts/e2e-test.sh example.com e2e-config-wildcard.yaml
```

This stage actually verifies the most:

| What is verified | Why it matters |
|---|---|
| **wildcard + apex share one TXT name** | the challenge values for `example.com` and `*.example.com` both go on `_acme-challenge.example.com` and must exist at the same time. This is the easiest place to get a DNS-01 implementation wrong |
| **waiting for propagation to authoritative NS** | LE validates from multiple vantage points and requires all of them to agree |
| **ARI certID construction** | without it there is no "exempt from all rate limits" treatment |
| **idempotency** | another round must not create a new order |
| **CNAME delegation** (if configured) | `EffectiveFQDN` follows the CNAME to the central zone |

This module **does not need to be applied**.

---

## Stage B: verify that `UpdateCertificateInstance` rebinds the CLB

```bash
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
export TF_PLUGIN_CACHE_DIR=/Users/atom/Documents/dsh/.terraform-plugin-cache

cd testenv
terraform init
terraform plan      # look at what would be created first
terraform apply
```

Resources created:

| Resource | Spec | Notes |
|---|---|---|
| `tencentcloud_vpc` | 10.99.0.0/16 | free |
| `tencentcloud_subnet` | 10.99.1.0/24 | free |
| `tencentcloud_clb_instance` | **internal** | no public bandwidth, so no EIP charges |
| `tencentcloud_clb_listener` | HTTPS:443, SNI on | bound to the placeholder certificate |
| `tencentcloud_ssl_certificate` | self-signed placeholder | generated at apply time; the private key never touches disk |

### How to test

The placeholder certificate Terraform creates is bound to the listener, simulating
"**the certificate wecert manages is currently serving live traffic**". Then seed
its CertId into the wecert state store:

```bash
PLACEHOLDER_ID=$(terraform output -raw placeholder_cert_id)

# seed it: make wecert believe this certificate is already bound
sqlite3 /tmp/wecert-e2e/state.db \
  "UPDATE certificates SET deployed_cert_id='${PLACEHOLDER_ID}' WHERE name='e2e-test';"

# run one round; wecert issues a new certificate and calls
# UpdateCertificateInstance(OldCertificateId=<placeholder>)
./bin/wecert -config e2e-config.yaml -state /tmp/wecert-e2e/state.db -once
```

### Assertion

```bash
# the listener's certificate_id should become the new certificate, not the placeholder
tccli clb DescribeListeners --LoadBalancerId "$(terraform output -raw clb_id)" \
  --region "$(terraform output -raw region)"
```

**What this step verifies is the single most important design assumption in the
whole project**: Tencent Cloud itself finds "which resources have the old
certificate bound" and updates them one by one, so we do not maintain a listener
inventory and therefore cannot accidentally damage other SNI certificates on the
same listener.

---

## Stage C: verify systemd + the CVM role

```bash
terraform apply -var create_cvm=true -var enable_cvm_role=true
```

| Resource | Spec | Notes |
|---|---|---|
| `tencentcloud_instance` | S5.MEDIUM2 (2C2G) | pay-as-you-go |
| `tencentcloud_security_group` | no inbound rules | TAT is an agent that dials out, so no port needs to be opened |
| public IP | 1 Mbps, traffic-based | just enough for TAT |

What is verified:
- the systemd unit starts cleanly and `StateDirectory` permissions are correct
- **the CVM role credential path**: wecert fetches temporary credentials from `metadata.tencentyun.com`; no key ever touches disk
- no credential-expiry problem in long-running daemon mode (this is why `dns.provider=tencentcloud` rebuilds the provider every time)

No SSH key is needed — TAT (Automation Tools) runs commands remotely.

---

## Cost

| Resource | Billing | Order of magnitude |
|---|---|---|
| VPC / subnet / security group | free | ¥0 |
| internal CLB | hourly instance fee | a few tenths of a yuan per day |
| CVM (stage C) | hourly | a few yuan per day |
| public IP (stage C) | traffic-based | TAT traffic only, essentially 0 |
| SSL Certificate Service | uploading certificates is free | ¥0 |
| Let's Encrypt | free | ¥0 |

> ⚠️ Actual prices vary by region and promotion, **so treat the console billing
> page as authoritative**. The table above is only an order-of-magnitude guide.
> Set up a cost alert in the console before you start.

## Cleanup

```bash
terraform destroy
```

**Run this after every test session.** All resources carry uniform tags
(`project=wecert`, `purpose=acme-e2e-test`), so you can check by tag in the console
whether anything is left behind.

Also remember to clean up the test certificates wecert uploaded to SSL Certificate
Service — they are not managed by Terraform (wecert created them), and enough of
them will hit the account quota:

```bash
tccli ssl DescribeCertificates --region ap-guangzhou   # find the ones whose Alias starts with wecert/
```

## Minimum CAM permissions required

Stage A (wildcard) needs:

```
ssl:UploadCertificate / DescribeCertificate / DeleteCertificate
dnspod:DescribeDomainList / DescribeRecordList / CreateRecord / ModifyRecord / DeleteRecord
```

Stage B additionally needs:

```
ssl:UpdateCertificateInstance
clb:CreateLoadBalancer / DescribeLoadBalancers / DeleteLoadBalancer
clb:CreateListener / DescribeListeners / ModifyListener / DeleteListener
vpc:CreateVpc / CreateSubnet / DescribeVpcs / DescribeSubnets / DeleteVpc / DeleteSubnet
```

Stage C additionally needs:

```
cvm:RunInstances / DescribeInstances / TerminateInstances
tat:RunCommand / DescribeCommands / DescribeInvocationTasks
cam:PassRole                       # attach the role to the CVM
```

`deploy/cam-policy-test.json` only covers stage A. Running B/C needs extra
permissions.

---

## Stage B2: 2-SAN wildcard + SNI + CVM backend (observed in practice)

A stricter set of scenarios than stage B: **one certificate with 2 wildcard SANs**,
bound to a **listener with SNI enabled**, sitting behind a **real CVM backend**,
with end-to-end TLS verification from the public internet.

```bash
terraform apply -var create_cvm=true
```

What gets built:

```
CLB (public)
└── listener HTTPS:443 (SniSwitch=1)
    ├── rule test.alpha.<domain>  -> certificate + CVM
    └── rule test.beta.<domain>   -> certificate + CVM (the same one)
```

### Conclusion (all passed)

- one certificate covers `*.alpha` + `*.beta` with exactly the right SANs
- a TLS handshake from the public internet reads the new certificate on both SNI domains
- both domains reach the same CVM backend through the CLB (HTTP 200)
- **`UpdateCertificateInstance` did rebind both rules**

### One important product-level finding: the rebind is not atomic

Observed timeline:

| Time | test.alpha | test.beta |
|---|---|---|
| 30s after the call returned | new certificate ✅ | **old placeholder cert** ❌ |
| after 60s | new certificate ✅ | new certificate ✅ |
| 90s / 120s | stable | stable |

A single call rebinds every resource, but **each resource takes effect at a
different time**, leaving a 30-60 second window in which different endpoints serve
different certificate versions.

In a renewal scenario this is harmless (both the old and the new certificate are
valid), but anything that relies on "the rebind completes instantly" will be wrong
— for example, when a brand-new domain is issued for the first time, it may not get
the certificate within that window.

**External black-box probing must poll; a single measurement is not enough.**

### The 8 traps hit along the way (none visible until it was really run)

| # | Symptom | Cause / fix |
|---|---|---|
| 1 | `InvalidZone.MismatchRegion` | the availability zone was hard-coded wrong. CVM is not sellable in `ap-guangzhou-3` under this account; it is actually `-5/-6/-7`. **A subnet being creatable does not mean a CVM can boot there.** Use `data.tencentcloud_availability_zones_by_product` to look it up |
| 2 | `InvalidUserDataFormat` | `user_data` requires base64; plaintext needs `user_data_raw` |
| 3 | `do not support to create v1 target group` | this account does not support target groups; use the classic `tencentcloud_clb_attachment` |
| 4 | `Lack of parameter Certificate or MultiCertInfo` | the certificate must be supplied when creating the **rule** too — CLB's multi-certificate SNI is configured at the rule layer |
| 5 | `HttpCheckDomain:*.alpha... can't be wildcards` | a rule domain cannot be a wildcard (it is used as the health check Host). Use a concrete hostname; the certificate's wildcard still covers it |
| 6 | `health_check_http_code cannot be higher than 31` | this field is a **bitmask**, not an HTTP status code; do not put 200 in it |
| 7 | `uin don't support set L7 custom port for health check` | this account does not allow a custom health check port on a layer-7 rule |
| 8 | `You can't specify SubnetId when create open loadbalancer` | a public CLB cannot specify a subnet; an internal one must |

### One more: a public CLB's health check source is not in the VPC CIDR

When only the VPC CIDR and `100.64.0.0/10` are allowed, health checks keep failing
and the CLB returns **504** for every request.

The confusing part: **the TLS handshake is fine** (`curl` reports 504 rather than a
connection error, and `ssl_verify_result=20` shows a certificate was sent), so it
is easily misdiagnosed as "the backend is down". The backend was perfectly healthy
— connecting straight to the CVM's public IP returned 200.

How it was tracked down: temporarily opening `0.0.0.0/0 -> 80` made the 504 vanish
immediately, which pinned it on the security group.

### The most important one: do not let Terraform and wecert fight over the same field

While debugging the security group I ran `terraform apply` a few times, and
**the certificates on both rules were quietly reverted to the placeholder**, while
the wecert state store still believed the new certificate was deployed — the two
sides disagreed completely.

The cause: Terraform's `certificate_id` is **desired state**, and every apply forces
it back to the configured value, while wecert changes that field **out of band**
through `UpdateCertificateInstance`. Two systems managing the same field are bound
to fight.

The fix is to make Terraform leave the field alone:

```hcl
resource "tencentcloud_clb_listener" "https" {
  # ...
  lifecycle {
    ignore_changes = [multi_cert_info, certificate_id, certificate_ssl_mode]
  }
}

resource "tencentcloud_clb_listener_rule" "wildcard" {
  # ...
  lifecycle {
    ignore_changes = [certificate_id, certificate_ssl_mode, certificate_ca_id]
  }
}
```

The cost: in Terraform state this field **stays at its old value for a long time**
(in this project it is forever the placeholder certificate's ID), and
`terraform plan` no longer reports drift. That is deliberate — the truth about this
field lives in the wecert state store, not in Terraform.

**Generalizing: any combination of "Terraform manages the infrastructure + another
system manages certificate/key rotation" has this problem.** Either let Terraform
manage the binding (in which case wecert must not call
`UpdateCertificateInstance`), or let wecert manage it (in which case
`ignore_changes` is mandatory). It cannot be both.

---

## Stage B3: per-domain routing + locally testable

On top of B2 this adds: a backend that returns a different page per Host, a CLB
security group, and DNS records.

### Backend routing by Host

The Python backend on the CVM reads the `Host` header and returns a different page:

| Request | Page |
|---|---|
| `https://test.alpha.<domain>/` | a large **ALPHA** |
| `https://test.beta.<domain>/` | a large **BETA** |
| any other Host | **UNKNOWN** (red) |

That makes "is the CLB's domain routing actually working" obvious at a glance — two
domains showing the same page means it is not.

The page mapping is changed in `var.backend_pages`; no script edit is needed.

### Why DNS records are created

Previously the only way to test was `curl --resolve` or `openssl -connect` with an
IP, because `test.alpha` / `test.beta` had no resolution records at all. Once the A
records exist, a browser can open them directly.

Note that `alpha` / `beta` are **not separate zones**, only subdomains of the
`dns_zone` apex, so the records are created in that zone with `sub_domain`
written as `test.alpha`.

### CLB security group: open by default, on purpose

```hcl
clb_allowed_cidrs = ["0.0.0.0/0"]   # default
```

Tightening this to an IP allowlist was tried, but **the egress IP is not stable**:
during one session the local egress changed from `121.35.103.225` to
`14.153.66.173`, and different probing services reported a third address. On top of
that there is no way to know the egress of the network the browser sits behind, and
one mistake in the allowlist locks you out.

And the symptom of "blocked by the security group" is that **the TLS handshake is
simply reset** (`SSL_ERROR_SYSCALL`), which is not intuitive and expensive to
diagnose. So the test environment leaves it open by default; once you have confirmed
a fixed egress IP, change it to `["x.x.x.x/32"]` and re-apply to tighten it.

### New: local cloud-init validation

```bash
make validate-cloudinit
```

It extracts `write_files` from the `.tf` source and syntax-checks the embedded
Python / shell.

**This was forced by a real incident**: a Python string in user_data had an
unmatched quote (`'...\n"`), the CVM came up and cloud-init "succeeded" as well, but
the backend never listened on port 80, and the symptom was the CLB returning 502 —
easily misdiagnosed as a network or security-group problem, wasting a long time.

The scripts in `user_data` only run after the machine boots, so a syntax error is
completely invisible before that, which is why it is checked before apply. Add
`--from-state` to validate the version that was already applied.
