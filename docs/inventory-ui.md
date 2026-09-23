# Read-only certificate inventory

wecert already issues, uploads, rebinds and probes. Operators still have to
join four places to answer a simple question: which certificate is bound to
which CLB, which names it covers, and when it expires.

This document is the contract for a read-only inventory page and JSON API.
It is not a management console.

Related issue: #77.

## Why read-only

Desired state drives action. ARI, the first manual CLB bind, and the local
rate-limit ledger are part of that loop. A page that can issue, rebind or
edit SAN sets would race the reconciler and hide the one-time console bind
that Tencent Cloud still requires.

v1 answers three questions and surfaces drift between them:

1. What the desired-state document asked for.
2. What `state.db` recorded (issued, uploaded, confirmed).
3. What the cloud and a TLS handshake currently present.

The only mutation allowed later is the existing authenticated
`POST /hook/reconcile`.

## What already exists

Do not invent a parallel status model. Assemble.

| Source | Already exposes | Missing for inventory |
| --- | --- | --- |
| `GET /hook/status` | name, notAfter, daysLeft, uploaded, deployConfirmed, consecutiveFailures, nextAttemptAt, lastError | domains, CLB rows, probe verdict |
| `GET /hook/desired` | domains, profile, keyType, freeze, shadow, revision | live bindings |
| `state.CertState` | DeployedCertID, DeployConfirmed, ARI window, PEM (do not serve) | listener identity |
| `TencentCLB.Bindings` | binding **count** and `complete` | resource IDs. `countBindings` today sums `TotalCount` and drops the CLB / listener / SNI rows the API already returns |
| `wecert-clbverify` | listener CertId + ExtCertIds, per-rule certs | not called from the daemon |
| `probe.Result` / `probe.Verdict` | host, SANs, notAfter, trusted, problem kind | last result is metrics-only (`host` label), not a stored row |
| Prometheus | deployed, not_after, probe_match, probe_trusted, ratelimit_blocked, desired_state_frozen | no CLB id label |

`/hook/status` stays. The inventory is a wider assembly, not a replacement.

## HTTP surface

Serve on the existing webhook listener (`webhook.listen`, default
`127.0.0.1:9801`). Reuse the hook authenticator: `Authorization: Bearer` or
`X-Wecert-Token`, constant-time compare, per-IP lockout.

| Method | Path | Auth | Body |
| --- | --- | --- | --- |
| GET | `/api/inventory` | required | JSON, see below |
| GET | `/status` | required | HTML table over the same payload |
| GET | `/hook/status` | required | unchanged |
| POST | `/hook/reconcile` | required | unchanged; v3 may offer a button that posts this |

Do not add a third listen address. Do not bind `/status` on the metrics
port: metrics stay scrapeable without a token; inventory must not.

Timer mode (`wecert -once`) has no long-lived listener. Document that the
page exists only in daemon mode, same as `/metrics` and the hooks.

## Assembly rules

- Never put `CertPEM`, `KeyPEM`, ACME account keys, or webhook tokens in
  the payload.
- A field that cannot be answered must be omitted or marked unknown. Do
  not invent a zero that means "unbound".
- Binding counts follow the existing contract: only `complete && count == 0`
  means "bound nowhere". `complete == false` is a lower bound.
- Live cloud enumeration is optional in v1 and cached in v2. A status
  request must not run `CreateCertificateBindResourceSyncTask` on the
  reconcile hot path and must not inherit the 3-minute enumeration budget.
- Probe hosts are concrete names only. Wildcards have no address; pick up
  to `probe.maxHostsPerCert` non-wildcard names from the cert's domain
  list, same as the probe runner.
- Clock for `daysLeft` is the process clock already used by
  `config.DaysUntil`.
- `regions` is observed, not configured: it is the set of regions named by the
  live binding rows. A Tencent Cloud SSL certificate is not itself regional --
  the regions are the load balancers it is attached to -- and `tencent.regions`
  is the deployment's search list, not a property of one certificate. Absent
  means no enumeration has named one; it is never filled in with a guess.

### Status values

Exactly one primary status per certificate, first match wins. The list separates
three things that used to share one wrong word: "no certificate exists yet" is
not `ok`, "the name could not be dialled" is not `probe_mismatch`, and "the
probe has not run for this certificate this process life" is not
`binding_unknown`.

| Status | When |
| --- | --- |
| `frozen` | desired-state document is frozen |
| `rate_limited` | a rate-limit gauge for this cert's scope is blocking |
| `revoke_pending` | a revoke request row exists for this name |
| `state_unreadable` | the state row could not be read; `error` carries the message |
| `not_issued` | no certificate exists for this name: no state row, or no `notAfter` and nothing uploaded |
| `waiting_manual_bind` | uploaded (`DeployedCertID != ""`) and `DeployConfirmed == false` |
| `pending_deploy` | issued, deployment enabled, and the first upload has not happened yet |
| `probe_mismatch` | the probe read a served certificate for some host and it is not the deployed one |
| `probe_unreachable` | the probe could not read a served certificate for any host (`unreachable`, `no_certificate`) |
| `binding_unknown` | a live enumeration came back incomplete with `count == 0` |
| `probe_unknown` | probing is on, the deployment is confirmed, and this process has no answer yet |
| `failing` | `consecutiveFailures > 0` |
| `expiring` | the certificate is inside its `renewBefore` window (30 days if unset) |
| `ok` | issued, deployed as configured, probe match (or probing off), not expiring |

Three notes decide whether the page can be believed:

- `ok` is not "the API said the switch worked". With probing enabled, a
  confirmed certificate that this process has not read a served certificate for
  is `probe_unknown`.
- `expiring` compares exact instants, the same test the renewer applies before
  it orders, while `daysLeft` is rounded up for display. A row can therefore
  read "Expiring · 30d" when the window is 30 days, and that is not a
  contradiction.
- `probe_mismatch` and `probe_unreachable` are the same prober's answers, not a
  second health check, and they are deliberately different statuses: a wrong
  certificate and a name that cannot be dialled have different owners.

## `GET /api/inventory`

```json
{
  "time": "2026-09-22T06:00:00Z",
  "desired": {
    "revision": "…",
    "frozen": null,
    "freezeReason": "",
    "generatedAt": "2026-09-22T05:00:00Z"
  },
  "summary": {
    "certificates": 12,
    "waitingManualBind": 1,
    "pendingDeploy": 0,
    "notIssued": 0,
    "unreadable": 0,
    "failing": 0,
    "expiring": 2,
    "probeMismatch": 0,
    "probeUnreachable": 0,
    "probeUnknown": 1,
    "bindingUnknown": 1
  },
  "certificates": [
    {
      "name": "example-com",
      "uin": "100012345678",
      "status": "waiting_manual_bind",
      "profile": "classic",
      "keyType": "ecdsa-p256",
      "domains": ["example.com", "*.example.com"],
      "regions": ["ap-guangzhou"],
      "notAfter": "2026-12-20T00:00:00Z",
      "daysLeft": 89,
      "issuedAt": "2026-09-21T12:00:00Z",
      "uploaded": true,
      "deployConfirmed": false,
      "deployedCertId": "cYk1…",
      "bindings": {
        "resourceTypes": ["clb"],
        "count": 0,
        "complete": true,
        "freshness": "store",
        "items": []
      },
      "probe": {
        "enabled": true,
        "ok": null,
        "hosts": []
      },
      "ari": {
        "windowStart": "2026-12-01T00:00:00Z",
        "windowEnd": "2026-12-10T00:00:00Z"
      },
      "consecutiveFailures": 0,
      "nextAttemptAt": "",
      "lastError": "",
      "drift": ["waiting_for_first_clb_console_bind"]
    }
  ]
}
```

`bindings.freshness` is one of `store`, `cached`, `live`, `unavailable`.
v1 always uses `store`, and a store-side count is a lower bound, never the
whole set: it is what this program deployed, and an operator can bind the same
certificate to further listeners while a console bind nobody has confirmed
stays invisible here. So store rows carry `complete: false` and the page prints
`≥1`, not `1`.

`bindings.observedAt` is when a live enumeration produced the rows. Store-side
rows have no observation instant because they were never observed on the cloud.

`probe.ok` is `true` / `false` / `null`. `null` means no sample this
process life, or probe disabled.

`drift` is a stable list of machine-readable tokens, not free text:

- `state_unreadable`
- `waiting_for_first_clb_console_bind`
- `desired_names_not_on_issued_cert`
- `issued_cert_not_confirmed_on_cloud`
- `served_cert_not_after_mismatch`
- `served_names_mismatch`
- `served_chain_untrusted`
- `served_validity_below_floor`
- `binding_enumeration_incomplete`
- `desired_state_frozen`
- `consecutive_failures`

Only what the probe actually reported becomes a token. A mismatch with no
problem kind produces the status and no drift token, because naming a cause
nobody observed is how "the names differ" gets attached to a chain problem.
`unreachable` and `no_certificate` produce no token either: the status already
says the certificate was not read.

Keep `/hook/status` field names when they overlap (`notAfter`,
`daysLeft`, `deployConfirmed`, `consecutiveFailures`). New fields go on
the inventory object only.

`uin` is the Tencent Cloud account id. It comes from `tencent.uin` on
the daemon, or from a certificate-level `uin` in the desired-state
document (the latter wins). It is omitted when neither is set. The page
groups and filters by it so operators running more than one account can
classify the register without a second tool. It does not change which
credentials deploy the certificate, and a GET must not call CAM to
discover it.

## Page layout (`GET /status`)

One HTML page, no JavaScript framework, no external CDN. A small script
may filter the already-rendered table. Default refresh is not required.

```
wecert  certificate inventory                      Read-only  2026-09-22T16:30:02Z
Inventory                                    desired state rev-2026-09-22.3
12 certificates  2 accounts  1 waiting bind  0 failing  2 expiring  ...

[All accounts ▾]  [All|Attention|Expiring]        search name, domain, account, CLB

100012345678 · 8 certificates
STATUS         CERTIFICATE   NAMES             REGION       CLB                DAYS  PROBE
Waiting bind   example-com   example.com +1    —            —                  89    —
Healthy        cdn-static    static.ex… +2     Guangzhou    lb-8f3k2m1p +1     77    Match
```

The account control is a single-select picker, not a row of chips: an
installation can carry hundreds of accounts, and the picker lists each one with
its certificate count and filters as you type. The summary bar always reports
the whole fleet, so a filtered table is never mistaken for the fleet.

Click a row to expand:

- full SAN list
- the regions the bindings were observed in, and the profile and key type
- each binding row: region, resource type, load-balancer id, listener id,
  protocol:port, SNI domain, role (`primary` / `ext`)
- each probe host: match, trusted, served notAfter, problem kind
- last error and next attempt
- when v3 exists: "reconcile this cert" (POST `/hook/reconcile`)

Sort default: trouble first (`waiting_manual_bind`, `probe_mismatch`,
`failing`, `binding_unknown`, `expiring`), then `daysLeft` ascending.

Colour is secondary. The status token is the thing an alert or a log
line can repeat.

## Binding rows (v2)

`countBindings` must grow a sibling that keeps the resource list the SSL
API already returns. Until that parser exists, the page must not pretend
to know listener ids.

A binding item:

```json
{
  "resourceType": "clb",
  "region": "ap-guangzhou",
  "loadBalancerId": "lb-xxxxxxxx",
  "listenerId": "lbl-xxxxxxxx",
  "protocol": "HTTPS",
  "port": 443,
  "sniDomain": "example.com",
  "role": "primary",
  "complete": true
}
```

`sniDomain` empty means listener-default. `role` is `primary` when the
id is `Certificate.CertId`, `ext` when it is in `ExtCertIds`.

If a region or resource type is unanswered, emit no fake row; set
`bindings.complete = false` and add `binding_enumeration_incomplete`.

Cache live enumeration per `deployedCertId` for at least 60s and at most
the SSL API's own cache window. Serve stale-with-timestamp rather than
block the page.

Do not scan every CLB with `DescribeListeners` just to fill this table.
That is what `wecert-clbverify` is for when the operator already knows
the lb id. Inventory should read the bind-resource task result, which is
certificate-centric.

## What this page still cannot know

Honest limits, so a reader does not take the table for more than it is:

- `rate_limited` is defined and unit-tested but nothing supplies blocked scopes
  to the page yet, so a running daemon will not show it. The alert on
  `wecert_ratelimit_blocked` is still the way to learn that the CA is refusing.
- CLB / listener rows exist only for certificates the reconciler has enumerated.
  `Bindings()` runs to confirm a first bind, so a confirmed certificate usually
  shows the store-side lower bound rather than listener ids.
- Probe answers live in the prober's memory for this process life. A restart
  empties them and rows read `probe_unknown` until the next pass; v1 stores no
  probe history.
- `time` is the reader's clock. The only observation instants in the payload are
  `desired.generatedAt` and `bindings.observedAt`; there is no per-source
  staleness for the store yet.
- `desired.frozen` is `null`, not `false`, when the document has never been
  read. A `false` there would be an invented answer, and the page says
  "desired state not read" instead.

## Implementation sketch

1. `internal/inventory` — pure assembly. Inputs: desired snapshot,
   `[]*state.CertState`, last probe results, optional binding snapshot.
   Output: the JSON struct above. No HTTP, no SDK.
2. `internal/webhook` — `GET /api/inventory` and `GET /status` next to
   `/hook/status`. Same `auth` wrapper.
3. `internal/deploy` — v2 only: parse resource IDs from
   `DescribeCertificateBindResourceTaskResult` without changing the
   `Bindings() (int, bool, error)` signature used by reconcile.
4. Tests: assembly table tests for every status token and every drift
   token; webhook auth tests copied from `/hook/status`; a parser test
   against a recorded bind-resource payload so a zero `TotalCount` with
   missing region data cannot become `complete`.
5. Docs: this file, a short pointer from README / README.zh-CN under
   Day-2, a CHANGELOG Unreleased line when the handlers ship.

`scripts/check-cli-surface.py` does not need a new flag. No new binary.

## Phases

### v1 — assemble what we already know

Store + desired + probe metrics. Bindings are count/completeness derived
from `DeployConfirmed` / `DeployedCertID`. Ships the page operators can
use tomorrow. Honest about what it cannot see.

### v2 — name the CLB

Parse bind-resource results. Cache. Show region / lb / listener / SNI.
Mark incomplete enumerations instead of guessing.

### v3 — one button

"Reconcile this cert" posts `/hook/reconcile`. Still no issue, upload,
rebind, revoke, or SAN editor.

## Non-goals

- Replacing Prometheus or `deploy/prometheus/wecert-alerts.yml`
- Serving on `0.0.0.0` or adding users and roles
- HTTP-01 / challenge-type work
- Off-host snapshots, NFS refusal, release signing (those stay on the
  availability backlog)
- Storing probe history in SQLite in v1

## Acceptance

v1 is done when:

- `curl -H "Authorization: Bearer …" http://127.0.0.1:9801/api/inventory`
  lists every desired-state certificate name
- a cert that has been uploaded but not console-bound is
  `waiting_manual_bind` and `daysLeft` matches `/hook/status`
- the HTML page renders that row without JavaScript from a CDN
- unauthenticated requests get 401 and count toward the existing
  auth lockout
- PEM material is absent from the JSON
- `go test ./internal/inventory ./internal/webhook` covers the status
  and drift tokens
