# CAM policies

Least-privilege CAM policies for running wecert and for the e2e environment.

| File | Purpose |
|---|---|
| `cam-policy-test.json` | Runtime permissions for the wecert binary itself (SSL certificate service + DNSPod record management). |
| `cam-policy-stage-ab.json` | The e2e stage A/B run: wecert runtime + Terraform-managed CLB/VPC/tag permissions, split into separate statements by concern. |

## Why every statement uses `resource: "*"`

The action lists are already minimal — wecert needs exactly four `ssl:*` and five
`dnspod:*` actions at runtime. The resource side is deliberately not narrowed,
for different reasons per service:

- **`dnspod:*`** — DNSPod supports qcs resource scoping by domain
  (`qcs::dnspod::domain/<domain>`), and narrowing to the zones wecert actually
  manages is worthwhile hardening if your account hosts other zones. It is left
  at `*` here because this policy is a starting template, not a per-account
  deployment artifact; substitute your zones before production use. Note that
  `dnspod:DeleteRecord` cannot be restricted to `_acme-challenge.*` names — the
  API's resource granularity is the domain, not the record — so record-level
  least privilege is not achievable with CAM today.
- **`ssl:*`** — the SSL certificate service does not support resource-level
  scoping for these actions in CAM; `*` is the only option.

Every statement deliberately omits `condition` blocks for the same reason: this
file documents the minimum action set; tightening resources/conditions is an
account-specific decision that belongs in your own policy derived from this one.
