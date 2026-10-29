# wecert Observability Overview & Deployment Guide

> **Component baseline**: wecert daemon (`/metrics` 127.0.0.1:9800) · self-hosted Prometheus 2.53.1 · Alertmanager 0.27.0 · a Tencent Cloud Prometheus instance (with Integration-Center node exporter) · managed Grafana 10.x
> **Scope**: the single document for the whole wecert observability stack — architecture, data flows, the three alert engines, the complete steps for the B1/B2 email pipelines and the cloud integration (remote_write / dashboards / alerting), acceptance, rollback, and known pitfalls. Self-contained: apart from the wecert base install (the repo README install section) it depends on no other document.
> **Environment**: the wecert CVM, in the same region as the Prometheus instance (same VPC is optimal, internal network).
> **Placeholders** (replaced at execution time, never committed):

| Placeholder | Meaning |
|---|---|
| `<PROM_INSTANCE_ID>` | the Tencent Cloud Prometheus instance id (e.g. `prom-xxxxxx`) |
| `<GRAFANA_INSTANCE>` / `<GRAFANA_URL>` | the managed Grafana instance name / URL |
| `<RW_URL>` / `<RW_TOKEN>` | the Remote Write address / token from the instance "service address" card |
| `<NOTICE_ID>` | the alarm-notice template id (`notice-xxx`, created in the console) |
| `<TCCLI_PROFILE>` | the local tccli profile name (key stored 0600 under `~/.tccli/`) |
| `<RECIPIENT>` | the alert/event email recipient |
| `<SMTP_USER>` / `<SMTP_AUTH_CODE>` | the SMTP relay account address / SMTP authorization code (the sender address must equal the account — see §4.2.5) |
| `<RELAY_HOST>` | the SMTP relay host (e.g. `smtp.example.com`) |
| `<region>` | the resource region (e.g. `ap-singapore`) |

---

## 1. Layered Architecture

Four layers, three alert engines (A local / B Grafana / C Tencent-native) plus one event push (B1), one cloud aggregation point:

```
┌─ Signal layer ────────────────────────────────────────────────────────────┐
│  wecert daemon                                                             │
│    ├─ /metrics (127.0.0.1:9800) — ~30 metric families: cert expiry/        │
│    │   deployment/probe, renewal health, desired state, backup, rate      │
│    │   limits, revocation, DNS cleanup, binding patrol                     │
│    └─ B1 renewal-event webhook (POST after every real renewal attempt,     │
│        HMAC-signed)                                                        │
├─ Local processing layer (CVM, loopback-only listeners) ───────────────────┤
│  [ALERT ENGINE A · local pipeline] Local Prometheus 2.53.1 (:9090)        │
│    scrapes wecert (30s); evaluates 21 rules from                          │
│    /etc/prometheus/wecert-alerts.yml (30s) ──alert events──> the LOCAL    │
│    Alertmanager 0.27.0 (:9093, a standalone systemd service doing         │
│    grouping/repeat/suppression; start/stop on demand)                     │
│        │                                                                   │
│        │ remote_write (forwards metric SAMPLES only — not rules,          │
│        v  not alert events)                                                │
│  Tencent Cloud <PROM_INSTANCE_ID> <──Integration Center── node exporter   │
│        │ (CVM :9100)                                                       │
│        └─[ALERT ENGINE C · Tencent-native] instance-native alerting:      │
│           a rule group (21 rules, platform-managed) ──> a Tencent Cloud   │
│           notice template (EMAIL; SMS/CALL/WECHAT can be added)            │
├─ Visualization & alerting layer ───────────────────────────────────────────┤
│  <GRAFANA_INSTANCE> (datasource <PROM_INSTANCE_ID>, auto-injected)         │
│    ├─ Node Exporter Full (community ID 1860) ─────── server monitoring    │
│    ├─ wecert Overview (ZH / EN editions) ────────── business monitoring   │
│    └─ [ALERT ENGINE B · cloud pipeline] Grafana Alerting (unified):       │
│       21 transcribed rules querying the cloud data, evaluated 60s ──>     │
│       the Grafana BUILT-IN Alertmanager (contact points + notification    │
│       policies) — a different thing from the local Alertmanager despite   │
│       the shared name                                                     │
└────────────────────────────────────────────────────────────────────────────┘
```

**Invariants**: remote_write forwards metric samples only (no rules, no alert events); local TSDB and the cloud are dual-write; `9090/9093/9800` keep listening on `127.0.0.1` only; local rule evaluation and notification delivery never affect each other.

## 2. Data Flows

| # | Flow | Content | Frequency | Notes |
|---|---|---|---|---|
| 1 | daemon → local Prometheus | all wecert metrics | scrape 30s | the metrics endpoint comes up with the daemon |
| 2 | local Prometheus → (its own rule evaluator) | 21 rules evaluated (**engine A**) | eval 30s | the evaluator runs inside the Prometheus process — evaluation continues even with Alertmanager stopped (event delivery to :9093 fails, visible in logs, no real impact) |
| 3 | local Prometheus → cloud instance | metric samples via remote_write (Bearer token; the cloud auto-appends a `tcloud_region_name` label) | with scrapes (30s) | verify: `prometheus_remote_storage_samples_failed` stays 0 |
| 4 | node exporter → cloud instance | CVM host metrics (CPU/memory/disk/network, managed by Integration Center) | platform-managed | requires TAT on the CVM |
| 5 | cloud instance → Grafana | dashboard queries | 30s refresh | the datasource is the auto-injected read-only one |
| 6 | cloud data → Grafana alerting engine | 21 transcribed rules evaluated (**engine B**) | eval 60s | status visible under Grafana Alerting |
| 6b | cloud data → instance-native alerting | 21 rules evaluated (**engine C**, Tencent-native) | platform-managed (minute-level) | notifications go through the Tencent Cloud notice template |
| 7 | daemon → notify bridge → SMTP (B1 event email) | renewal events (signature-verified relay) | per real renewal | the bridge is an optional component |
| 8 | [engine A's notification layer] LOCAL Alertmanager (:9093, standalone service) → SMTP | B2 alert emails (group 30s / repeat 3h / send_resolved) | event-driven | start/stop via `systemctl` |
| 9 | [engine B's notification layer] Grafana BUILT-IN Alertmanager → email contact point | cloud alert emails | event-driven | the root-policy receiver decides delivery vs silence (evaluation continues while silent) |

**Dual-write semantics**: the local TSDB keeps the full history; the cloud accumulates from the moment of connection. A local outage loses nothing — the cloud is the remote view and the data source for dashboards and alerting.

## 3. The Three Alert Engines & Notifications (do not conflate)

**Three fully independent alert engines — each holds its own copy of the rules, evaluates on its own, and notifies on its own; the state of one never affects the others**. Pick a **single** primary notification path (engine C has the strongest channels, engine B the simplest); B/C may evaluate in parallel as mutual backup, but notifications left on in both will double the emails:

| Dimension | Engine A · local pipeline | Engine B · Grafana pipeline | Engine C · Tencent-native pipeline |
|---|---|---|---|
| Rule evaluator | the rule evaluator built into local Prometheus 2.53.1 (30s/round, inside the Prometheus process) | the Grafana Alerting engine (60s/round) | instance-native alerting on the cloud instance (platform-managed, minute-level) |
| Rule definitions | `/etc/prometheus/wecert-alerts.yml` (native format, the **authoritative source**) | Grafana alert rules (**transcribed copy**; mapping in §4.5a) | a Tencent Cloud alert rule group (**transcribed copy**; mapping in §4.5b) |
| Evaluated data | wecert /metrics scraped locally | the cloud instance (samples forwarded by remote_write) | the cloud instance (same data as B; the engines are independent) |
| Notification component | the **LOCAL Alertmanager 0.27.0** (standalone CVM systemd service, :9093) | the **Grafana BUILT-IN Alertmanager** (contact points + policies) | the **Tencent Cloud alarm-notice template** (Cloud Monitor) |
| Channels | SMTP → `<RECIPIENT>` | email contact point → same | **EMAIL (SMS/CALL/WECHAT can be added at any time from the console)** |
| On / off | `systemctl enable --now alertmanager` (off: `disable --now`) | root-policy receiver switch (real contact point or placeholder) | console: notice template channels / rule-group state |

**Things that are easy to conflate**:

1. remote_write forwards **metric samples only** — neither rules nor alert events. Engines B/C can alert because each **re-evaluates** the cloud data itself, not because "local alerts were forwarded up";
2. an engine's **evaluation** and its **notification** are two independent layers — stopping the notification component or silencing the notification policy never stops rule evaluation;
3. the B1 renewal-event email (notify bridge) is unrelated to all three engines — an active event push from the daemon that never passes through any alert engine;
4. **sync responsibility when rules change**: `wecert-alerts.yml` is the authoritative source and B/C are its two transcribed copies — an upstream change needs to be synced to all three places (local reload / Grafana API / tccli `UpdatePrometheusAlertGroup`, which is a full replace).

**Notification channels at a glance**:

| Event | Engine/component | Channel | On / off |
|---|---|---|---|
| Renewal event (B1) | daemon webhook (no alert engine involved) | bridge(9810) → SMTP → `<RECIPIENT>` | `systemctl enable/disable --now wecert-demo-receiver` |
| Local alert (B2) | **engine A** | local Alertmanager(9093) → SMTP → same | `systemctl enable/disable --now alertmanager` |
| Cloud alert (Grafana) | **engine B** | Grafana built-in AM → email contact point → same | root-policy receiver switch |
| Cloud alert (Tencent) | **engine C** | notice template → EMAIL (SMS/CALL/WECHAT addable) → same | console notice template / rule group |

## 4. Complete Deployment & Integration Steps

### 4.1 Prerequisite: base deployment
The repo `README.md` (install section): official `install.sh` (includes `/metrics`). The metrics endpoint comes up with the daemon — nothing to deploy separately.

### 4.2 Email notifications (B1 + B2)

Two independent email channels (components and ports in the §1 diagram): the **B1 renewal-event email** (daemon webhook → notify bridge → SMTP, pushed after every real renewal attempt, HMAC-verified) and the **B2 alert email** (local Prometheus 21 rules → Alertmanager → SMTP).

**Prerequisites**: ① the wecert daemon running (§4.1); ② an SMTP relay account with its authorization code; ③ outbound 587 reachable (`timeout 5 bash -c "echo > /dev/tcp/<RELAY_HOST>/587"`); ④ the recipient address `<RECIPIENT>`. Every web interface listens on `127.0.0.1` only — reach it through an SSH tunnel.

#### 4.2.1 B1: the renewal-event channel

**① Daemon side** (append inside the `webhook:` block of `/etc/wecert/config.yaml`):

```yaml
webhook:
  # ...existing listen / tokenFile / adminToken...
  notifyURL: http://127.0.0.1:9810/notify     # the local notify bridge
  notifyFormat: generic                        # RenewalEvent JSON + verifiable signature
  notifySecretFile: /etc/wecert/notify.secret  # HMAC signing key (0600)
```

```bash
openssl rand -hex 32 > /etc/wecert/notify.secret
chown wecert:wecert /etc/wecert/notify.secret && chmod 600 /etc/wecert/notify.secret
systemctl restart wecert
```

**② Notify bridge deployment**. SMTP settings (`/etc/wecert-demo/smtp.json`, 0600, owner wecert):

```json
{
  "host": "<RELAY_HOST>",
  "port": 587,
  "user": "<SMTP_USER>",
  "pass": "<SMTP_AUTH_CODE>",
  "from": "<SMTP_USER>",
  "from_display": "wecert (<brand tag, optional>)",
  "to": "<RECIPIENT>"
}
```

The service itself: `/opt/wecert-demo/notify-receiver.py` (python3, standard library only, no dependencies):
- `POST /notify`: verifies `X-Wecert-Signature` first (`sha256=<hex HMAC-SHA256(key, body)>`); **only a verified event is relayed as email** — a failed verification is logged and never sent;
- `POST /alerts`: delivery log for Alertmanager notifications (Alertmanager sends its own email; this endpoint is visibility only);
- `GET /healthz`: liveness.

The systemd unit (`/etc/systemd/system/wecert-demo-receiver.service`):

```ini
[Unit]
Description=wecert notify bridge (B1 renewal-event email relay)
After=network.target

[Service]
User=wecert
ExecStart=/usr/bin/python3 /opt/wecert-demo/notify-receiver.py
Restart=on-failure
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**③ Start and verify**:

```bash
systemctl enable --now wecert-demo-receiver
systemctl restart wecert        # produce one real round of events (one per certificate per restart)
journalctl -u wecert-demo-receiver -f   # expect:
# [NOTIFY] signature=verified body={"event":"renewal","cert":"...","result":"ok",...}
# [MAIL] relay accepted (<SMTP_USER> -> <RECIPIENT>)
```

#### 4.2.2 B2: the alert channel (Prometheus + Alertmanager)

**① Install** (linux-amd64 binaries; the rule file is the in-repo `deploy/prometheus/wecert-alerts.yml`, copied to `/etc/prometheus/`):

```bash
curl -fsSL -o /tmp/prom.tar.gz https://github.com/prometheus/prometheus/releases/download/v2.53.1/prometheus-2.53.1.linux-amd64.tar.gz
curl -fsSL -o /tmp/am.tar.gz  https://github.com/prometheus/alertmanager/releases/download/v0.27.0/alertmanager-0.27.0.linux-amd64.tar.gz
tar xzf /tmp/prom.tar.gz && tar xzf /tmp/am.tar.gz
install -m 0755 prometheus-2.53.1.linux-amd64/{prometheus,promtool} /usr/local/bin/
install -m 0755 alertmanager-0.27.0.linux-amd64/{alertmanager,amtool} /usr/local/bin/

useradd --system --no-create-home --shell /usr/sbin/nologin prometheus
install -d -o prometheus -g prometheus -m 0755 /etc/prometheus /var/lib/prometheus
install -d -o prometheus -g prometheus -m 0755 /etc/alertmanager /var/lib/alertmanager

cp deploy/prometheus/wecert-alerts.yml /etc/prometheus/ && chown prometheus:prometheus /etc/prometheus/wecert-alerts.yml
```

**② `/etc/prometheus/prometheus.yml`**:

```yaml
global:
  scrape_interval: 30s
  evaluation_interval: 30s
alerting:
  alertmanagers:
    - static_configs:
        - targets: ["127.0.0.1:9093"]
rule_files:
  - /etc/prometheus/wecert-alerts.yml
scrape_configs:
  - job_name: wecert
    static_configs:
      - targets: ["127.0.0.1:9800"]
```

**③ `/etc/alertmanager/alertmanager.yml`** (0600, owner prometheus):

```yaml
route:
  receiver: email
  group_by: ["alertname"]
  group_wait: 30s        # let a group settle before the first notification
  group_interval: 1m
  repeat_interval: 3h    # unhandled alerts re-notify every 3 hours
receivers:
  - name: email
    email_configs:
      - to: "<RECIPIENT>"
        from: "<SMTP_USER>"
        smarthost: "<RELAY_HOST>:587"
        auth_username: "<SMTP_USER>"
        auth_password: "<SMTP_AUTH_CODE>"
        require_tls: true     # 587 STARTTLS
        send_resolved: true   # also email when an alert resolves
    webhook_configs:          # mirror deliveries to the local bridge (optional, visibility only)
      - url: "http://127.0.0.1:9810/alerts"
        send_resolved: true
```

**④ The two systemd units**:

```ini
# /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus (wecert metrics)
After=network-online.target
Wants=network-online.target

[Service]
User=prometheus
ExecStart=/usr/local/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus --web.listen-address=127.0.0.1:9090
Restart=on-failure
StateDirectory=prometheus
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/alertmanager.service
[Unit]
Description=Alertmanager (wecert alerts)
After=network-online.target
Wants=network-online.target

[Service]
User=prometheus
ExecStart=/usr/local/bin/alertmanager --config.file=/etc/alertmanager/alertmanager.yml --storage.path=/var/lib/alertmanager --web.listen-address=127.0.0.1:9093
Restart=on-failure
StateDirectory=alertmanager
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**⑤ Start and verify**:

```bash
systemctl daemon-reload
systemctl enable --now prometheus alertmanager

promtool check config /etc/prometheus/prometheus.yml
promtool check rules /etc/prometheus/wecert-alerts.yml
amtool check-config /etc/alertmanager/alertmanager.yml

curl -s http://127.0.0.1:9090/api/v1/targets | grep -o '"health":"[^"]*"'    # wecert -> up
curl -s http://127.0.0.1:9090/api/v1/rules | python3 -c "import json,sys; print(sum(len(g['rules']) for g in json.load(sys.stdin)['data']['groups']))"  # rule count (21)
journalctl -u alertmanager -f        # any error/failed line means the email channel is unhealthy
```

#### 4.2.3 Service management quick reference

| Action | Command |
|---|---|
| Start all | `systemctl enable --now wecert wecert-demo-receiver prometheus alertmanager` |
| Status | `systemctl is-active <unit>` (four units: `wecert` / `wecert-demo-receiver` / `prometheus` / `alertmanager`) |
| Restart | `systemctl restart <unit>`; config-only changes can use `systemctl kill -s HUP prometheus` / `alertmanager` |
| Logs | `journalctl -u <unit> -f` |
| Event / delivery log | `journalctl -u wecert-demo-receiver -f` (grep `NOTIFY` / `MAIL` / `ALERTS`) |

#### 4.2.4 Day-2 operations

- **Credential locations (exactly two, both 0600, never in any git repository)**: `/etc/wecert-demo/smtp.json` (owner wecert) and `/etc/alertmanager/alertmanager.yml` (owner prometheus). When rotating the authorization code, edit both and restart the two units;
- **notify.secret** (the B1 signing key): `/etc/wecert/notify.secret` (0600, wecert). Changing the key updates signer and verifier together (the bridge reads the same file) — restart both units;
- **repeat_interval**: unhandled alerts re-notify every 3 hours; they stop automatically once the root cause is fixed;
- **Upgrade order**: upgrade wecert first, then sync `deploy/prometheus/wecert-alerts.yml` to `/etc/prometheus/` and `systemctl kill -s HUP prometheus`.

#### 4.2.5 FAQ: `501 Mail from address must be same as authorization user`

**Symptom**: with an independent sending domain (e.g. `wecert@<your-brand-domain>`) in `from`, no email goes out and the relay answers `501 Mail from address must be same as authorization user.` — on B1 the bridge log shows `[MAIL] failed: (501, ...)`; on B2 `journalctl -u alertmanager` shows `Notify attempt failed ... 501` retrying.

**Cause**: this class of relays requires the **envelope sender (MAIL FROM) to equal the authenticated account** — sending from your own domain is impossible on them (personal/free mailbox relays behave this way as a rule; it is a platform policy, not an account setting).

**Solutions (cheapest first)**:

| Option | How | When |
|---|---|---|
| **① Sender address = relay account address** (this guide's default) | put the relay account address in `from`; carry the brand in the display name (`from_display`) | zero cost, enough for most cases |
| **② A mailbox that supports verified sender addresses** | register the brand address as a verified sender in the mailbox console; or use an **enterprise mailbox account on your own domain** (the account address already lives on the brand domain, so "From = auth user" holds by construction) | when the provider explicitly supports it; an enterprise mailbox is the cleanest fix |
| **③ Switch to a transactional email service** | SendGrid / SES &c.: complete **domain ownership verification** (DNS) first, after which any verified domain can be the sender, and configure SPF include + DKIM + DMARC per their guide | when a real brand sending domain is required |

**How to confirm**: run one real send against the relay (python `smtplib`'s `send_message(..., from_addr=<brand address>)`). A refusal with code 501 is exactly this problem. Caveat: judge by the result of a **real send** — `smtplib.SMTP.mail()` does not raise on 5xx replies and cannot be the verdict.

### 4.3 Cloud integration: remote_write (~10 minutes)

**① Fetch credentials from the console**: Prometheus console → instance `<PROM_INSTANCE_ID>` → basic info → the "service address" card: the **Remote Write address** (`<RW_URL>`, internal address within the same VPC) and the **token** (`<RW_TOKEN>`).

**② Network precheck** (on the CVM):
```bash
curl -v -X POST <RW_URL>
# Expect HTTP 401 Unauthorized: the link is reachable, only auth is missing
```

**③ Token into a 0600 file**:
```bash
printf '%s' '<RW_TOKEN>' > /etc/prometheus/remote_write.token
chown prometheus:prometheus /etc/prometheus/remote_write.token && chmod 600 /etc/prometheus/remote_write.token
```

**④ Edit prometheus.yml** (the url must be double-quoted; the metric volume is small, default queue settings suffice):
```bash
cp -a /etc/prometheus/prometheus.yml /etc/prometheus/prometheus.yml.bak-$(date +%Y%m%d)
cat >> /etc/prometheus/prometheus.yml <<'EOF'

# Remote write to Tencent Cloud Prometheus (<PROM_INSTANCE_ID>) — data relay only.
remote_write:
  - name: tencent-prom
    url: "<RW_URL>"
    bearer_token_file: /etc/prometheus/remote_write.token
    remote_timeout: 30s
EOF
```

**⑤ Validate and hot-reload**:
```bash
promtool check config /etc/prometheus/prometheus.yml && systemctl kill -s HUP prometheus
```

**⑥ Verify**:
```bash
sleep 65   # two scrape periods
# prometheus_remote_* are process-own metrics (this setup does not self-scrape); read /metrics directly:
curl -s http://127.0.0.1:9090/metrics | grep -E '^prometheus_remote_storage_samples_(total|failed)'
# Expect total increasing, failed constant 0
```
Cloud-side: Grafana → Explore (datasource `<PROM_INSTANCE_ID>`) — `up{job="wecert"}` = 1, `count(wecert_certificate_not_after_timestamp_seconds > 0)` = the number of certificates.

### 4.4 Grafana dashboard import (~10 minutes)

**① Datasource**: if the managed Grafana was associated with the Prometheus instance at creation, the datasource is auto-injected (default, read-only); otherwise add a Prometheus datasource manually (URL = the query address from the instance's service-address card + Bearer token). Verify: `node_uname_info` returns series in Explore.

**② Server dashboard**: Import → community ID **1860** → datasource = the instance. **One required fix**: if the charts are blank, change the `$job` variable query to `label_values(node_uname_info, job)` and select the Integration Center's actual job name. Acceptance: CPU/memory/disk/network charts have data.

**③ wecert dashboards**: Import → upload `wecert-grafana-dashboard-en.json` (EN) or `wecert-grafana-dashboard.json` (ZH) → datasource = the instance. Both editions share identical queries/thresholds/layout (six rows, 30 panels, 27 queries, thresholds aligned with the 21 alert rules); paths after import: `/d/wecert-overview` / `/d/wecert-overview-en`.

### 4.5 Cloud alert transcription (two paths — pick one or run in parallel)

#### 4.5a. Grafana unified alerting (engine B)
Create the 21 alert rules via the Grafana HTTP API (or the UI), folder `wecert alerts`, five rule groups keeping the original names. **Three semantic-mapping points**:
1. **PromQL verbatim** (instant query); the Prometheus filtering semantics "a non-empty result series ⇒ alerting, one instance per series" is reproduced with a threshold expression (value > -1e12) — any returned series fires, and the labels become instance labels;
2. **noDataState=OK**: a vanished series means the condition no longer holds (same as Prometheus), producing no NoData noise;
3. **Template rewrite**: `{{ $labels.X }}` → `{{ labels.X }}`, `{{ $value }}` → `{{ values.B }}` (Grafana template syntax).

Notifications: create an email contact point (`<RECIPIENT>`) and set it as the root-policy receiver, or point the policy at a placeholder receiver to stay silent (evaluation continues, status visible, nothing delivered).

#### 4.5b. Tencent-native alerting (engine C, the strongest channels)
1. **Notice template**: console → observability platform → notification management → notice templates → create (initially EMAIL only, to avoid existing alerts immediately triggering SMS/CALL ringing). **Pick the receiver from the page dropdown** (see §6 pitfalls 6/7); note the `<NOTICE_ID>`;
2. **Alert rule group**: use the local template `wecert-amp-alertgroup-payload.json` (21 rules, RepeatInterval 3h) — first replace the `<PROM_INSTANCE_ID>` and `<NOTICE_ID>` placeholders inside, then:
   ```bash
   tccli monitor CreatePrometheusAlertGroup --region <region> --profile <TCCLI_PROFILE> \
       --cli-input-json file://wecert-amp-alertgroup-payload.json
   ```
   Rule semantics: `Expr` is PromQL verbatim, `Duration` = `for`, `Labels` carries severity (8 critical / 13 warning), `Annotations` uses the official `summary`/`description` keys with native Prometheus template syntax (`{{ $labels.x }}` / `{{ $value }}`);
3. **Verify**: create a temporary always-true test policy (e.g. Expr `up{job="wecert"}`, no Duration), confirm the email reaches `<RECIPIENT>`, then delete the test policy.

> The two paths may coexist (same data source, independent engines); leaving notifications on in both doubles the emails — keep a single primary path (see §3).

### 4.6 Acceptance checklist

| # | Check | Method | Expected |
|---|---|---|---|
| 1 | Send counter grows | `curl -s http://127.0.0.1:9090/metrics \| grep remote_storage_samples_total` | one step per 30s |
| 2 | Zero send failures | same (failed) | 0 |
| 3 | Visible on the cloud | Explore `up{job="wecert"}` | 1 |
| 4 | Local rule evaluation | `curl -s http://127.0.0.1:9090/api/v1/rules \| grep -c '"health":"ok"'` | 21 |
| 5 | Server dashboard | after 1860 import | CPU/memory have data |
| 6 | wecert overview | Row 1 eight stats | values present (certs > 0) |
| 7 | Expiry detail table | row count | = number of certificates |
| 8 | Cloud alerting | temporary always-true policy | email delivered, then delete |

### 4.7 Rollback

```bash
cp -a /etc/prometheus/prometheus.yml.bak-<date> /etc/prometheus/prometheus.yml
systemctl kill -s HUP prometheus
rm /etc/prometheus/remote_write.token
```
Data already written to the cloud stays; deleting the Grafana dashboards and the alert rule group rolls those back.

## 5. Dashboards & Alerts at a Glance

**Three dashboards** (managed Grafana, admin login):

| Dashboard | Entry (path after import) | Content |
|---|---|---|
| Node Exporter Full | `/d/node-exporter-full` | server: CPU/memory/disk/network/systemd |
| wecert Overview (ZH) | `/d/wecert-overview` | six rows: 8 overview stats / expiry detail table / live probe verification / renewal health / desired state & fallback / infrastructure |
| wecert Overview (EN) | `/d/wecert-overview-en` | same, in English |

**21 alerts** (**three coexisting definitions**; their relationship and sync responsibility in §3): local `wecert-alerts.yml` (authoritative source) / Grafana (folder `wecert alerts`, visible under Alerting) / Tencent Cloud (alert rule group).
Groups: expiry 5 (three expiry tiers: classic 22.5d / tlsserver 11.25d / shortlived 40h) · convergence 6 · integrity 7 · dns-cleanup 1 · binding-patrol 2; severity: 8 critical / 13 warning.

**Two "looks broken but is correct" display semantics (do not "fix")**:
1. timestamp metrics are explicitly reduced by `time()` into days/hours — do not re-plot raw values;
2. **absence is the signal**: a vanished `probe_trusted` / `probe_not_after` series means "the probe never completed a handshake (no answer)" — No data on the panel is correct behavior; check-type stats are explicitly backfilled with `or vector(0)`.

**Expected behavior in test environments**: if the probed domains are not actually serving (no DNS records / 443 closed), `WecertServedCertificateIsNotTheDeployedOne` stays critical — that is "the probe could not verify", not "the wrong certificate is served"; the alerts self-resolve and the two No-data panels light up once the domains serve real traffic. To quiet it down, silence that alert or set `probe.enabled: false`.

## 6. Notes & Known Pitfalls (grouped by topic)

**Services & verification**
1. Before integrating, check the three local units (`systemctl is-active prometheus alertmanager wecert-demo-receiver`) — in long-unattended environments they are often disabled+stopped; restore with `enable --now`;
2. `prometheus_remote_*` are Prometheus process-own metrics; if the config does not self-scrape (wecert only), verification must read the `/metrics` endpoint directly, not `/api/v1/query`;
3. Cloud queries automatically append `tcloud_region_id` / `tcloud_region_name` labels — account for them when comparing PromQL results across sides.

**Grafana**
4. Blank charts after importing 1860 usually mean the `$job` variable does not match the actual job name (verify with `label_values(node_uname_info, job)`);
5. A datasource auto-associated by the managed Grafana is read-only — do not rewrite it via API; the Grafana alerting v2-alerts injection endpoint may be rejected by the managed platform — verify notifications with a real alert or the UI.

**The Tencent Cloud notification system (where the pitfalls concentrate)**
6. **Receiver ids come in three mutually different schemes**: the CAM sub-account/collaborator Uin, the owner Uin, and the **notification-scheme Uin** — the notice-template API (`CreateAlarmNotice` `UserIds`) accepts only the third; using the first two is rejected (`users [...] do not belong to owner`), but even copying a "notification Uin" from another template can fail **silently if that Uin's email contact was never verified in the message center** (the API call succeeds, nothing is sent, no error anywhere) — **change receivers via the console notice-template page dropdown** and let the platform resolve the correct id;
7. `DescribeAlarmHistories` **does not include AMP (Prometheus) alert records** — queries stay empty across regions while the alerts actually fired; do not rely on that API for AMP alerting — verify by **actual email delivery / the console alert-event page**;
8. Configure EMAIL only at first: with already-active alerts (e.g. unreachable probes in a test environment), enabling SMS/CALL rings immediately; add the other channels after the pipeline is confirmed.

**tccli**
9. `--cli-input-json` requires the **`file://` prefix**; an inline JSON string is rejected;
10. A new profile needs no interactive configure: copy any existing `.configure` + write a fresh `.credential` (`{"secretId","secretKey","token":""}`, chmod 600);
11. `UpdatePrometheusAlertGroup` is a **full-replace** semantic (GroupName and the complete Rules are required; passing only the fields to change fails with `group name cant empty` / `alert rules cant empty`);
12. CAM's `DescribeSubAccounts` requires `--FilterSubAccountUin` per account and cannot list all sub-accounts.

**Semantics & display (not bugs — do not "fix")**
13. See the two display semantics in §5;
14. A persistently critical `WecertServedCertificateIsNotTheDeployedOne` with unreachable probe targets in a test environment is expected (see §5).

## 7. Credentials & Security Discipline

- Credentials live only in 0600 files: on the CVM `/etc/alertmanager/alertmanager.yml`, `/etc/prometheus/remote_write.token`, `/etc/wecert-demo/smtp.json`, `/etc/wecert/notify.secret`; on the operator machine `~/.tccli/<TCCLI_PROFILE>.credential` (the cloud API key); none enter any git repository or any committed document;
- Every local port listens on `127.0.0.1` only (browser access via SSH tunnel); remote_write is the single new outbound request;
- Grafana/console access goes through the Tencent Cloud account.

## 8. Deliverables & Related Documents

**Deliverables in this directory**:

| File | Purpose |
|---|---|
| `wecert-observability-overview-zh.md` / `-en.md` | this document (overview + full manual, ZH/EN) |
| `wecert-grafana-dashboard.json` / `-en.json` | the wecert dashboard import files (ZH/EN; Grafana Import, datasource = the instance) |
| `wecert-amp-alertgroup-payload.json` | the Tencent alert rule-group import template (21 rules; replace `<PROM_INSTANCE_ID>` / `<NOTICE_ID>` then tccli `--cli-input-json file://`; edit this JSON directly when rules change) |
| `deploy/prometheus/wecert-alerts.yml` | the authoritative 21-rule source (the alignment baseline for local deployment and both cloud transcriptions; upgraded together with wecert) |

**Related documents**:

| Document | Content |
|---|---|
| `README.md` / `README.zh-CN.md` (install section) | base daemon deployment via `install.sh` (detail behind §4.1; from §4.2 on this document is self-contained) |
