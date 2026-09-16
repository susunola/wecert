# CAM policies

Least-privilege CAM policies for running wecert and for the e2e environment.

| File | Purpose |
|---|---|
| `cam-policy-runtime.json` | Attach this to the CVM role that runs `wecert`. SSL upload/rebind plus DNSPod record writes. |
| `cam-policy-test.json` | Same runtime actions as above; kept as the historical name used by preflight/docs. |
| `cam-policy-stage-ab.json` | **Not a runtime policy.** The e2e stage A/B run: wecert runtime + Terraform-managed CLB/VPC/tag create and delete. Do not attach this to the production `wecert` role. |

## Why every statement uses `resource: "*"`

The action lists are already minimal — wecert needs exactly seven `ssl:*` and five
`dnspod:*` actions at runtime. The three `ssl:*` entries beyond upload/describe/delete
are the asynchronous ones: `DescribeHostUpdateRecordDetail` polls every one-click
rebind to completion, and `CreateCertificateBindResourceSyncTask` /
`DescribeCertificateBindResourceTaskResult` are how a first-issued certificate is
confirmed to be bound after a human binds it in the console. The resource side is deliberately not narrowed,
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
