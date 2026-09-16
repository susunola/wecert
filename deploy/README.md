# Deployment artifacts

## CAM policies

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

## Prometheus rules

`prometheus/wecert-alerts.yml` is a ready-to-load rule file: 17 alerts in three groups
(`wecert.expiry`, `wecert.convergence`, `wecert.integrity`), with a comment above each threshold saying
where the number came from. Point `rule_files:` at it.

It is here rather than left as an exercise because several of the failures it watches for are silent
by construction -- a revocation the CA never accepted, a pass that has not finished in two hours, a
certificate serving that is not the one deployed. None of them produce an error log, so the alert is
the only thing that notices. `make check-alerts` verifies the file still refers to series this program
actually exports; a rule against a series that does not exist parses perfectly and never fires.
