# wecert 可观测性总览与部署手册（Observability Overview & Deployment Guide）

> **组件基线**：wecert daemon（`/metrics` 127.0.0.1:9800）· 自建 Prometheus 2.53.1 · Alertmanager 0.27.0 · 腾讯云 Prometheus 实例（含集成中心 node exporter）· 托管 Grafana 10.x
> **本文定位**：整个 wecert 可观测体系的**总览 + 完整部署手册**（合一）——架构、数据流向、三套告警体系、B1/B2 邮件链路与云端对接（remote_write / 面板 / 告警）的完整部署步骤、验收与回滚、已知坑。自包含：除 wecert 基础安装（仓库 `README.zh-CN.md` 安装节）外不依赖其他文档。
> **适用环境**：wecert 所在 CVM（与 Prometheus 实例同地域，同 VPC 走内网最优）。
> **占位符约定**（执行时替换，不写入任何 git 仓库）：

| 占位符 | 含义 |
|---|---|
| `<PROM_INSTANCE_ID>` | 腾讯云 Prometheus 实例 ID（形如 `prom-xxxxxx`） |
| `<GRAFANA_INSTANCE>` / `<GRAFANA_URL>` | 托管 Grafana 实例名 / 访问地址 |
| `<RW_URL>` / `<RW_TOKEN>` | 实例"服务地址"卡片中的 Remote Write 地址 / Token |
| `<NOTICE_ID>` | 告警通知模板 ID（形如 `notice-xxx`，控制台创建） |
| `<TCCLI_PROFILE>` | 本机 tccli profile 名（密钥 0600 存于 `~/.tccli/`） |
| `<RECIPIENT>` | 告警/事件邮件收件人 |
| `<SMTP_USER>` / `<SMTP_AUTH_CODE>` | SMTP 中继账号地址 / SMTP 授权码（发件地址需与账号一致，原因见 §4.2.5） |
| `<RELAY_HOST>` | SMTP 中继主机（如 `smtp.example.com`） |
| `<region>` | 资源地域（如 `ap-singapore`） |

---

## 1. 分层架构

wecert 的可观测性分四层，三套告警引擎（A 本地 / B Grafana / C 腾讯云原生）外加一条事件推送（B1），一份云端汇聚：

```
┌─ 信号层 ─────────────────────────────────────────────────────────────────┐
│  wecert daemon                                                            │
│    ├─ /metrics（127.0.0.1:9800）——约 30 个指标族：证书到期/部署/探针、    │
│    │   续期健康、期望状态、备份、限流、吊销、DNS 清理、绑定巡逻           │
│    └─ B1 续期事件 webhook（每次真实续期尝试后 POST，HMAC 签名）           │
├─ 本地处理层（CVM，全部仅监听回环）──────────────────────────────────────┤
│  【告警引擎 A · 本地链路】本地 Prometheus 2.53.1（:9090）                 │
│    抓取 wecert（30s）；用 /etc/prometheus/wecert-alerts.yml 自行评估      │
│    21 条规则（30s/轮）──告警事件──> 本地 Alertmanager 0.27.0（:9093，   │
│    独立 systemd 服务，负责分组/重发/抑制；按需启停）                      │
│        │                                                                  │
│        │ remote_write（仅转发指标样本——不转发规则、不转发告警事件）      │
│        v                                                                  │
│  腾讯云 <PROM_INSTANCE_ID> <──集成中心── node exporter（CVM :9100）      │
│        │                                                                  │
│        └─【告警引擎 C · 腾讯云原生】实例自带告警：告警规则组（21 条，     │
│           评估由平台托管）──> 腾讯云通知模板（EMAIL，可加短信/电话/微信）│
├─ 可视化与告警层 ─────────────────────────────────────────────────────────┤
│  <GRAFANA_INSTANCE>（数据源 <PROM_INSTANCE_ID>，实例关联自动注入）        │
│    ├─ Node Exporter Full（社区 ID 1860）────────服务器监控               │
│    ├─ wecert Overview（中/英两版）────────────业务监控                    │
│    └─ 【告警引擎 B · 云端链路】Grafana 统一告警（Grafana Alerting）：     │
│       21 条转录规则，查询云端数据、60s/轮自行评估 ──> Grafana 内置        │
│       Alertmanager（contact point + 通知策略）——与本地那个               │
│       Alertmanager 是两个东西，仅重名                                     │
└───────────────────────────────────────────────────────────────────────────┘
```

**不变项**：remote_write 只转发指标样本（不转发规则、不转发告警事件）；本地 TSDB 与云端双写；`9090/9093/9800` 仍只听 `127.0.0.1`；本地 21 条规则评估与通知投递互不影响。

## 2. 数据流向

| # | 流向 | 内容 | 频率 | 说明 |
|---|---|---|---|---|
| 1 | daemon → 本地 Prometheus | wecert 全部指标 | 30s 抓取 | 指标随 daemon 自起 |
| 2 | 本地 Prometheus →（自身规则评估器） | 21 条规则评估（**引擎 A**） | 30s | 评估器在 Prometheus 进程内——即使 Alertmanager 停用，评估照常（事件投递 :9093 会失败，日志可见、无实际影响） |
| 3 | 本地 Prometheus → 云端实例 | 指标样本 remote_write（Bearer token 鉴权，云端自动附加 `tcloud_region_name` 标签） | 随抓取（30s） | 验证：`prometheus_remote_storage_samples_failed` 恒为 0 |
| 4 | node exporter → 云端实例 | CVM 主机指标（CPU/内存/磁盘/网络，集成中心托管） | 平台托管 | 需 CVM 已装 TAT |
| 5 | 云端实例 → Grafana | 三面板查询 | 30s 刷新 | 数据源为实例自动关联的只读数据源 |
| 6 | 云端数据 → Grafana 告警引擎 | 21 条转录规则评估（**引擎 B**） | 60s | 状态在 Grafana Alerting 页可看 |
| 6b | 云端数据 → 实例自带告警 | 21 条规则评估（**引擎 C**，腾讯云原生） | 平台托管（分钟级） | 通知经腾讯云通知模板投递 |
| 7 | daemon → notify bridge → SMTP（B1 事件邮件） | 续期事件（验签后转发） | 每次真实续期 | bridge 为可选组件 |
| 8 | 【引擎 A 的通知层】本地 Alertmanager（:9093，独立服务）→ SMTP | B2 告警邮件（group 30s / repeat 3h / send_resolved） | 事件驱动 | 按 `systemctl` 启停 |
| 9 | 【引擎 B 的通知层】Grafana 内置 Alertmanager → email contact point | 云端告警邮件 | 事件驱动 | 根策略 receiver 决定投递或静默（静默时评估照常） |

**双写语义**：本地 TSDB 保留全部历史；云端从接入时刻起累积。本地停机不丢数据，云端是远程视图与面板/告警的数据源。

## 3. 三套告警体系与通知（勿混淆）

**三套互相独立的告警引擎，各自持有一份规则、各自评估、各自通知——一方的开关不影响另一方**。通知主通道建议**单选**（引擎 C 渠道最强，或引擎 B 最简）；引擎 B/C 可并行评估作互备，但同时开通知会双份邮件：

| 维度 | 引擎 A · 本地链路 | 引擎 B · Grafana 链路 | 引擎 C · 腾讯云原生链路 |
|---|---|---|---|
| 规则评估者 | 本地 Prometheus 2.53.1 自带评估器（30s/轮，在 Prometheus 进程内） | Grafana 统一告警引擎（60s/轮） | 云端实例自带告警（平台托管，分钟级） |
| 规则定义 | `/etc/prometheus/wecert-alerts.yml`（Prometheus 原生格式，**权威源**） | Grafana alert rules（**转录副本**；映射见 §4.5a） | 腾讯云告警规则组（**转录副本**；映射见 §4.5b） |
| 评估数据 | 本地直接抓取的 wecert /metrics | 云端实例（remote_write 转发上去的样本） | 云端实例（与 B 同一份数据，引擎各自独立） |
| 通知组件 | **本地 Alertmanager 0.27.0**（CVM 独立 systemd 服务，:9093） | **Grafana 内置 Alertmanager**（contact points + 通知策略） | **腾讯云告警通知模板**（云监控体系） |
| 通知渠道 | SMTP → `<RECIPIENT>` | email contact point → 同上 | **EMAIL（可随时加开短信/电话/微信，控制台即改）** |
| 启停/切换 | `systemctl enable --now alertmanager`（停：`disable --now`） | 根策略 receiver 切换（指向真实 contact point 或占位接收者） | 控制台改通知模板渠道 / 规则组状态 |

**容易混淆的点**：

1. remote_write **只转发指标样本**——不转发规则、不转发告警事件。引擎 B/C 能告警，是各自拿云端数据**自己重新评估**，不是"本地的告警被转发了上去"；
2. 引擎的"评估"与"通知"是**两个独立层面**：停通知组件/静默通知策略都不影响规则评估——三套引擎的规则评估始终与其通知开关无关；
3. B1 续期事件邮件（notify bridge）与三套引擎都无关——它是 daemon 的主动事件推送，不经过任何告警引擎；
4. **改规则时的同步责任**：`wecert-alerts.yml` 是权威源，B/C 是它的两个转录副本——上游变更需三处同步（本地热加载 / Grafana API / tccli `UpdatePrometheusAlertGroup` 全量替换）。

**通知渠道速查**：

| 事件 | 引擎/组件 | 渠道 | 启停方式 |
|---|---|---|---|
| 续期事件（B1） | daemon webhook（不经告警引擎） | bridge(9810) → SMTP → `<RECIPIENT>` | `systemctl enable/disable --now wecert-demo-receiver` |
| 本地告警（B2） | **引擎 A** | 本地 Alertmanager(9093) → SMTP → 同上 | `systemctl enable/disable --now alertmanager` |
| 云端告警（Grafana） | **引擎 B** | Grafana 内置 AM → email contact point → 同上 | 根策略 receiver 切换 |
| 云端告警（腾讯云） | **引擎 C** | 通知模板 → EMAIL（可加短信/电话/微信）→ 同上 | 控制台通知模板/规则组 |

## 4. 部署与对接完整步骤

### 4.1 前置：基础部署
仓库 `README.zh-CN.md`（安装节）：官方 `install.sh` 部署（含 `/metrics`）。metrics 端口随 daemon 自起，无需单独部署。

### 4.2 邮件通知（B1 + B2）

两条独立邮件通道（组件与端口见 §1 架构图）：**B1 续期事件邮件**（daemon webhook → notify bridge → SMTP，每次真实续期尝试后推送，HMAC 验签）；**B2 告警邮件**（本地 Prometheus 21 条规则 → Alertmanager → SMTP）。

**前置**：① wecert daemon 已运行（§4.1）；② SMTP 中继账号 + 授权码；③ 出站 587 可达（`timeout 5 bash -c "echo > /dev/tcp/<RELAY_HOST>/587"`）；④ 收件地址 `<RECIPIENT>`。所有 Web 界面仅监听 `127.0.0.1`，浏览器访问走 SSH 隧道。

#### 4.2.1 B1：续期事件通道

**① daemon 侧**（`/etc/wecert/config.yaml` 的 `webhook:` 段内追加）：

```yaml
webhook:
  # ……既有 listen / tokenFile / adminToken……
  notifyURL: http://127.0.0.1:9810/notify     # 指向本机 notify bridge
  notifyFormat: generic                        # RenewalEvent JSON + 可验签
  notifySecretFile: /etc/wecert/notify.secret  # HMAC 签名密钥（0600）
```

```bash
openssl rand -hex 32 > /etc/wecert/notify.secret
chown wecert:wecert /etc/wecert/notify.secret && chmod 600 /etc/wecert/notify.secret
systemctl restart wecert
```

**② notify bridge 部署**。SMTP 配置（`/etc/wecert-demo/smtp.json`，0600，属主 wecert）：

```json
{
  "host": "<RELAY_HOST>",
  "port": 587,
  "user": "<SMTP_USER>",
  "pass": "<SMTP_AUTH_CODE>",
  "from": "<SMTP_USER>",
  "from_display": "wecert (<品牌标识，可选>)",
  "to": "<RECIPIENT>"
}
```

服务本体 `/opt/wecert-demo/notify-receiver.py`（python3 标准库实现，无依赖）：
- `POST /notify`：先验签 `X-Wecert-Signature`（`sha256=<hex HMAC-SHA256(密钥, body)>`）；**验签通过才转邮件**，失败仅留痕不发信；
- `POST /alerts`：Alertmanager 投递留痕（邮件由 Alertmanager 自己发，此端点仅作可见性）；
- `GET /healthz`：存活检查。

systemd 单元（`/etc/systemd/system/wecert-demo-receiver.service`）：

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

**③ 启动与验证**：

```bash
systemctl enable --now wecert-demo-receiver
systemctl restart wecert        # 触发一轮真实事件（每次重启各证书各产生一条）
journalctl -u wecert-demo-receiver -f   # 期望：
# [NOTIFY] signature=verified body={"event":"renewal","cert":"...","result":"ok",...}
# [MAIL] relay accepted (<SMTP_USER> -> <RECIPIENT>)
```

#### 4.2.2 B2：告警通道（Prometheus + Alertmanager）

**① 安装**（linux-amd64 二进制；规则文件用仓库内 `deploy/prometheus/wecert-alerts.yml`，拷贝到 `/etc/prometheus/`）：

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

**② `/etc/prometheus/prometheus.yml`**：

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

**③ `/etc/alertmanager/alertmanager.yml`**（0600，属主 prometheus）：

```yaml
route:
  receiver: email
  group_by: ["alertname"]
  group_wait: 30s        # 同组告警聚齐后再发，避免单条轰炸
  group_interval: 1m
  repeat_interval: 3h    # 未处理的告警每 3 小时重发一次
receivers:
  - name: email
    email_configs:
      - to: "<RECIPIENT>"
        from: "<SMTP_USER>"
        smarthost: "<RELAY_HOST>:587"
        auth_username: "<SMTP_USER>"
        auth_password: "<SMTP_AUTH_CODE>"
        require_tls: true     # 587 STARTTLS
        send_resolved: true   # 告警恢复时也发一封 resolved
    webhook_configs:          # 同步留痕到本机 bridge（可选，仅作可见性）
      - url: "http://127.0.0.1:9810/alerts"
        send_resolved: true
```

**④ 两个 systemd 单元**：

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

**⑤ 启动与验证**：

```bash
systemctl daemon-reload
systemctl enable --now prometheus alertmanager

promtool check config /etc/prometheus/prometheus.yml
promtool check rules /etc/prometheus/wecert-alerts.yml
amtool check-config /etc/alertmanager/alertmanager.yml

curl -s http://127.0.0.1:9090/api/v1/targets | grep -o '"health":"[^"]*"'    # wecert → up
curl -s http://127.0.0.1:9090/api/v1/rules | python3 -c "import json,sys; print(sum(len(g['rules']) for g in json.load(sys.stdin)['data']['groups']))"  # 规则数（21）
journalctl -u alertmanager -f        # 出现 error/failed 行即邮件通道异常
```

#### 4.2.3 服务管理速查

| 操作 | 命令 |
|---|---|
| 启动全部 | `systemctl enable --now wecert wecert-demo-receiver prometheus alertmanager` |
| 状态 | `systemctl is-active <单元>`（四个单元：`wecert` / `wecert-demo-receiver` / `prometheus` / `alertmanager`） |
| 重启 | `systemctl restart <单元>`；仅改配置可 `systemctl kill -s HUP prometheus` / `alertmanager` |
| 日志 | `journalctl -u <单元> -f` |
| 事件/邮件留痕 | `journalctl -u wecert-demo-receiver -f`（grep `NOTIFY` / `MAIL` / `ALERTS`） |

#### 4.2.4 日常运维

- **凭据位置（仅两处，均 0600，不进任何 git 仓库）**：`/etc/wecert-demo/smtp.json`（属主 wecert）、`/etc/alertmanager/alertmanager.yml`（属主 prometheus）。轮换授权码时改这两处并重启对应单元；
- **notify.secret**（B1 签名密钥）：`/etc/wecert/notify.secret`（0600，wecert）。换密钥即同时换发信方与验签方（bridge 读同一文件），重启两个单元即可；
- **repeat_interval**：未处理告警每 3 小时重发；处理掉根源后自动停止；
- **升级顺序**：先升 wecert，再同步 `deploy/prometheus/wecert-alerts.yml` 到 `/etc/prometheus/` 并 `systemctl kill -s HUP prometheus`。

#### 4.2.5 FAQ：`501 Mail from address must be same as authorization user`

**现象**：把独立发件域（如 `wecert@<你的品牌域>`）填进 `from` 后邮件发不出去，中继返回 `501 Mail from address must be same as authorization user.`——B1 侧 bridge 日志 `[MAIL] failed: (501, ...)`；B2 侧 `journalctl -u alertmanager` 反复 `Notify attempt failed ... 501`。

**原因**：这类中继要求**信封发件地址（MAIL FROM）必须与认证账号一致**。"用自己的域作发件地址"在此类中继上不可行（个人/免费邮箱中继普遍如此，属平台策略而非账号配置）。

**解决方案（按成本从低到高）**：

| 方案 | 做法 | 适用 |
|---|---|---|
| **① 发件地址 = 中继账号地址**（本手册默认形态） | `from` 填中继账号地址；品牌信息放显示名（`from_display`） | 零成本，大多数场景够用 |
| **② 用支持"已验证发件地址"的邮箱** | 在邮箱后台把品牌地址登记为已验证发件人；或用**自己域名上的企业邮箱账号**（账号地址本身在品牌域上，"From = 认证账号"自然满足） | 服务商明确支持时；企业邮箱最干净 |
| **③ 换事务型邮件服务** | SendGrid / SES 等：先做域名归属验证（DNS），之后可用任意已验证域作发件地址，并配 SPF include + DKIM + DMARC | 需要真正以自有品牌域发信时 |

**确认方法**：对中继做一次真实发送测试（python `smtplib` 的 `send_message(..., from_addr=<品牌地址>)`），被拒且错误码 501 即本问题。注意：**真实发送**的返回才算数（`smtplib.SMTP.mail()` 不会因 5xx 抛错）。

### 4.3 云端对接：remote_write（约 10 分钟）

**① 控制台取凭据**：Prometheus 控制台 → 实例 `<PROM_INSTANCE_ID>` → 基本信息 → 服务地址卡片：**Remote Write 地址**（`<RW_URL>`，同 VPC 用内网地址）与 **Token**（`<RW_TOKEN>`）。

**② 网络预检**（CVM 上）：
```bash
curl -v -X POST <RW_URL>
# 期望 HTTP 401 Unauthorized：链路可达、只差鉴权即网络 OK
```

**③ Token 落 0600 文件**：
```bash
printf '%s' '<RW_TOKEN>' > /etc/prometheus/remote_write.token
chown prometheus:prometheus /etc/prometheus/remote_write.token && chmod 600 /etc/prometheus/remote_write.token
```

**④ 修改 prometheus.yml**（url 必须带双引号；指标量级小，默认队列参数即可）：
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

**⑤ 校验并热加载**：
```bash
promtool check config /etc/prometheus/prometheus.yml && systemctl kill -s HUP prometheus
```

**⑥ 验证**：
```bash
sleep 65   # 两个 scrape 周期
# prometheus_remote_* 是进程自身指标（本配置不自抓），从 /metrics 直读：
curl -s http://127.0.0.1:9090/metrics | grep -E '^prometheus_remote_storage_samples_(total|failed)'
# 期望 total 递增、failed 恒为 0
```
云端：Grafana → Explore（数据源 `<PROM_INSTANCE_ID>`）查 `up{job="wecert"}` = 1、`count(wecert_certificate_not_after_timestamp_seconds > 0)` = 证书数。

### 4.4 Grafana 面板导入（约 10 分钟）

**① 数据源**：托管 Grafana 创建时关联 Prometheus 实例则自动注入（默认、只读）；否则手动添加 Prometheus 数据源（URL 用实例服务地址中的查询地址 + Bearer Token）。验证：Explore 里 `node_uname_info` 有序列。

**② 服务器面板**：Import → 输入社区 ID **1860** → 数据源选实例。**必改一处**：若图表空白，把 `$job` 变量的 query 改为 `label_values(node_uname_info, job)`，选中集成中心的实际 job 名。验收：CPU/内存/磁盘/网络四类图有数据。

**③ wecert 面板**：Import → 上传本目录 `wecert-grafana-dashboard.json`（中文）或 `wecert-grafana-dashboard-en.json`（英文）→ 数据源选实例。两版查询/阈值/布局一致（六行 30 面板 27 查询，阈值对齐 21 条告警规则），导入后路径 `/d/wecert-overview` / `/d/wecert-overview-en`。

### 4.5 云端告警转录（两条路径，二选一或并行）

#### 4.5a. Grafana 统一告警（引擎 B）
通过 Grafana HTTP API（或 UI 手工）创建 21 条告警规则，folder 建议 `wecert alerts`，5 个 ruleGroup 保持原组名。**语义映射三要点**：
1. **PromQL 原样**（instant 查询）；Prometheus 的筛选语义"表达式返回非空序列 ⇒ 告警、每序列一个实例"用 threshold 表达式（值 > -1e12）复刻——任何返回序列即触发，标签保留为实例标签；
2. **noDataState=OK**：序列消失 = 条件不再满足（与 Prometheus 一致），不产生 NoData 噪音；
3. **模板改写**：`{{ $labels.X }}` → `{{ labels.X }}`、`{{ $value }}` → `{{ values.B }}`（Grafana 模板语法）。

通知：创建 email contact point（`<RECIPIENT>`）并设为根策略接收者，或指向占位接收者保持静默（评估照常、状态可看、不投递）。

#### 4.5b. 腾讯云原生告警（引擎 C，通知渠道更强）
1. **通知模板**：控制台 → 可观测平台 → 通知管理 → 通知模板 → 新建（建议初期仅 EMAIL，避免既有告警立刻触发短信/电话轮呼）。**接收人务必用页面下拉选择**（见 §6 坑 6/7），拿到 `<NOTICE_ID>`；
2. **告警规则组**：用本目录模板 `wecert-amp-alertgroup-payload.json`（21 条规则、RepeatInterval 3h）——先替换其中 `<PROM_INSTANCE_ID>` 与 `<NOTICE_ID>` 两个占位符，再执行：
   ```bash
   tccli monitor CreatePrometheusAlertGroup --region <region> --profile <TCCLI_PROFILE> \
       --cli-input-json file://wecert-amp-alertgroup-payload.json
   ```
   规则语义：`Expr` 为 PromQL 原样、`Duration` = `for`、`Labels` 带 severity（critical 8 / warning 13）、`Annotations` 用官方 `summary`/`description` key 且模板语法与 Prometheus 原生一致（`{{ $labels.x }}` / `{{ $value }}`）；
3. **验证**：创建一条临时恒真测试策略（Expr 如 `up{job="wecert"}`，无 Duration），确认 `<RECIPIENT>` 收到邮件后删除测试策略。

> 两条路径可并存（数据同源、引擎独立）；若同时开启通知会造成双份邮件，建议单一主通道（详见 §3）。

### 4.6 验收清单

| # | 检查项 | 方法 | 期望 |
|---|---|---|---|
| 1 | 发送计数增长 | `curl -s http://127.0.0.1:9090/metrics \| grep remote_storage_samples_total` | 30s 一跳 |
| 2 | 发送失败为 0 | 同上（failed） | 0 |
| 3 | 云端可见 | Explore `up{job="wecert"}` | 1 |
| 4 | 本地规则评估 | `curl -s http://127.0.0.1:9090/api/v1/rules \| grep -c '"health":"ok"'` | 21 |
| 5 | 服务器面板 | 1860 导入后 | CPU/内存有数据 |
| 6 | wecert 总览 | Row 1 八个 stat | 有值（证书数>0） |
| 7 | 到期明细表 | 行数 | = 证书数 |
| 8 | 云端告警 | 临时恒真测试策略 | 邮件送达后删测试 |

### 4.7 回滚

```bash
cp -a /etc/prometheus/prometheus.yml.bak-<日期> /etc/prometheus/prometheus.yml
systemctl kill -s HUP prometheus
rm /etc/prometheus/remote_write.token
```
云端已写入数据自然留存；Grafana 面板与告警规则组删除即回滚。

## 5. 面板与告警速览

**三个面板**（托管 Grafana，admin 登录）：

| 面板 | 入口（导入后路径） | 内容 |
|---|---|---|
| Node Exporter Full | `/d/node-exporter-full` | 服务器：CPU/内存/磁盘/网络/系统服务 |
| wecert Overview（中） | `/d/wecert-overview` | 六行：总览 8 stat / 到期明细表 / 线上验证 probe / 续期健康 / 期望状态与降级 / 基础保障 |
| wecert Overview (EN) | `/d/wecert-overview-en` | 同上，英文 |

**21 条告警**（**三处定义并存**，关系与同步责任见 §3）：本地 `wecert-alerts.yml`（权威源）/ Grafana（folder `wecert alerts`，Alerting 页可看）/ 腾讯云（告警规则组）。
分组：expiry 5（含 3 个到期档：classic 22.5d / tlsserver 11.25d / shortlived 40h）· convergence 6 · integrity 7 · dns-cleanup 1 · binding-patrol 2；severity：critical 8 / warning 13。

**两个"看起来异常但正确"的展示语义**（别当 bug 修）：
1. 时间戳类指标已显式减 `time()` 换算为天/小时——别用原始值重画；
2. **absent 即信号**：`probe_trusted` / `probe_not_after` 等序列消失 = "探针未完成握手（无答案）"，面板 No data 是正确行为；检查型 stat 已用 `or vector(0)` 显式补 0。

**测试环境的预期状态**：若探针目标域名本就不对外服务（无 DNS 解析 / 443 不通），`WecertServedCertificateIsNotTheDeployedOne` 会持续 critical——这是"探针无法验证"而非"出示了错误证书"；域名真实服务上线后告警自动 resolved、两个 No data 面板自动出数。降噪可对该告警加 Silence 或关闭 `probe.enabled`。

## 6. 注意事项与已知坑（按主题分组）

**服务与验证**
1. 对接前先核对三个本地单元状态（`systemctl is-active prometheus alertmanager wecert-demo-receiver`）——长期无人维护的环境里它们常处于 disabled+stopped；恢复用 `enable --now`；
2. `prometheus_remote_*` 是 Prometheus 进程自身指标，若配置未自抓（只抓 wecert），验证须从 `/metrics` 端点直读而非 `/api/v1/query`；
3. 云端查询自动附加 `tcloud_region_id` / `tcloud_region_name` 标签，跨端对比 PromQL 结果时注意。

**Grafana**
4. 1860 面板导入后图表空白通常是 `$job` 变量与实际 job 名不匹配（集成中心的 job 名以 `label_values(node_uname_info, job)` 实测为准）；
5. 托管 Grafana 的数据源若为实例自动关联（readOnly），不要尝试 API 改写；Grafana 告警的 v2 alerts 测试注入接口可能被托管平台拒绝，通知验证用真实告警或 UI。

**腾讯云通知体系（最集中的坑）**
6. **接收人 ID 有三套互不相同的体系**：CAM 子账号/协作者 Uin、主账号 OwnerUin、**通知体系 Uin**——通知模板 API（`CreateAlarmNotice` 的 `UserIds`）只认第三套；用错前两套会被拒（`users [...] do not belong to owner`），但抄用其他模板的"通知 Uin"也可能因**该 Uin 的邮箱联系方式未在消息中心验证**而静默失败（API 创建成功、通知不发、无任何报错）——**改接收人直接在控制台通知模板页下拉选人**，让平台落正确 ID；
7. `DescribeAlarmHistories` **不收录 AMP（Prometheus）告警记录**——多地域查询恒为空但告警实际已触发，排查 AMP 告警勿依赖该 API，以**邮件实收 / 控制台告警事件页**为准；
8. 通知模板初期只配 EMAIL：若已有 active 告警（如测试环境探针不可达类），开短信/电话会立即轮呼；短信/电话/微信确认链路后再在模板上加开。

**tccli**
9. `--cli-input-json` 必须用 **`file://` 前缀**，内联 JSON 字符串会被拒；
10. 新建 profile 无需交互式 configure：复制任一现有 `.configure` + 新写 `.credential`（`{"secretId","secretKey","token":""}`，chmod 600）；
11. `UpdatePrometheusAlertGroup` 是**全量替换**语义（须带 GroupName 与完整 Rules，仅传想改的字段会报 `group name cant empty` / `alert rules cant empty`）；
12. CAM 列子账号的 `DescribeSubAccounts` 必须按 `--FilterSubAccountUin` 逐个查，无法全量列举。

**语义与展示（不是 bug，别"修"）**
13. 见 §5 两个展示语义；
14. 测试环境探针目标不可达时 `WecertServedCertificateIsNotTheDeployedOne` 持续 critical 属预期（见 §5）。

## 7. 凭据与安全纪律

- 凭据只存 0600 文件：CVM 上 `/etc/alertmanager/alertmanager.yml`、`/etc/prometheus/remote_write.token`、`/etc/wecert-demo/smtp.json`、`/etc/wecert/notify.secret`；操作机 `~/.tccli/<TCCLI_PROFILE>.credential`（云端 API 密钥）；均不进任何 git 仓库、不入任何文档实本；
- 所有本地端口仅监听 `127.0.0.1`（浏览器访问走 SSH 隧道）；remote_write 为唯一新增出站请求；
- Grafana/控制台凭据走腾讯云账号体系。

## 8. 交付物与关联文档

**本目录交付物**：

| 文件 | 用途 |
|---|---|
| `wecert-observability-overview-zh.md` / `-en.md` | 本文档（总览 + 完整手册，中/英） |
| `wecert-grafana-dashboard.json` / `-en.json` | wecert 面板导入文件（中/英，Grafana Import，数据源选实例） |
| `wecert-amp-alertgroup-payload.json` | 腾讯云告警规则组导入模板（21 条；替换 `<PROM_INSTANCE_ID>` / `<NOTICE_ID>` 后 tccli `--cli-input-json file://` 即用；规则变更时直接编辑此 JSON） |
| `deploy/prometheus/wecert-alerts.yml` | 21 条告警规则原文（PromQL 权威来源，本地部署与云端转录的逐条对齐基准；随 wecert 一起升级） |

**关联文档**：

| 文档 | 内容 |
|---|---|
| `README.zh-CN.md` / `README.md`（安装节） | daemon 基础部署 `install.sh`（§4.1 的细节；§4.2 起本手册自包含） |
