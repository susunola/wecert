<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img src="docs/logo.png" alt="wecert" width="100">
  </picture>
</p>

<p align="center">
  <a href="README.md">English</a> &nbsp;·&nbsp; <b>简体中文</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white" alt="Go 1.26+">
  <img src="https://img.shields.io/badge/ACME-DNS--01-brightgreen" alt="ACME DNS-01">
  <img src="https://img.shields.io/badge/renewal-ARI%20(RFC%209773)-blueviolet" alt="ARI (RFC 9773)">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <a href="https://github.com/susunola/wecert/actions/workflows/ci.yml"><img src="https://github.com/susunola/wecert/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# wecert

一个 cert-manager 风格的 ACME 证书自动续期器，面向 **TLS 在腾讯云 CLB 终结** 的部署形态。

一个二进制、一个 SQLite 文件。因为解密发生在 CLB，整套系统**不需要节点 agent，也不需要分发证书文件** —— 整个部署动作就是几次腾讯云 API 调用。

## 安装

编译需要 Go 1.26+。

```bash
git clone https://github.com/susunola/wecert.git
cd wecert
make build          # → bin/wecert
make tools          # → bin/wecert-preflight, bin/wecert-clbverify
```

三个平台的静态产物：

```bash
make release        # → dist/ + SHA256SUMS
```

在目标 CVM 上，`install.sh` 会创建 `wecert` 用户、装到 `/usr/local/bin/wecert`、准备 `/etc/wecert/` 并写入 systemd unit：

```bash
sudo ./install.sh ./dist/wecert_linux_amd64
```

> module 路径与仓库地址一致，`git clone` 后 `make build` 和 `go install github.com/susunola/wecert/cmd/wecert@latest` 都可以用。

> **注意：程序的日志与错误信息是英文的。** 本文档保留中文说明，但所有
> 日志、CLI 帮助和错误文本都直接用程序的实际输出（英文），以免文档与实现不一致。


## 快速开始

**1. 先检查凭证、DNS 归属和 NS 委派** —— 全部只读：

```bash
export TENCENTCLOUD_SECRET_ID="<secret-id>"
export TENCENTCLOUD_SECRET_KEY="<secret-key>"
./bin/wecert-preflight -domain example.com
```

**2. 配置。** `config.example.yaml` 自带注释，且 `acme.directory` 默认指向 Let's Encrypt **staging** —— 因为 `install.sh` 会把这份文件直接装成生产配置，默认值必须是安全的那个。

```bash
sudo cp config.example.yaml /etc/wecert/config.yaml
sudo chown root:wecert /etc/wecert/config.yaml && sudo chmod 640 /etc/wecert/config.yaml
sudo -u wecert ./bin/wecert -config /etc/wecert/config.yaml -dry-run
```

**3. 启动。** staging 全流程跑通后，把 `acme.directory` 切到生产，然后：

```bash
sudo systemctl enable --now wecert                      # 守护模式，每小时收敛
# 或者：sudo systemctl enable --now wecert-once.timer     # 定时模式，每小时跑一次
```

两种模式**每台机器只能启用一个**。它们共用一个状态库，而"每张证书最多一个在飞订单"这条保证只在单进程内成立。

**4. 人工绑定一次。** 首次签发时腾讯云侧还没有"旧证书 → 云资源"的绑定关系可查，所以 wecert 只会上传证书：

```
certificate uploaded; waiting for a one-time manual bind in the CLB console cert=example-com uploadedCertId=xxxxxxxx
```

去 CLB 控制台绑一次即可。之后每次续期全自动 —— `UpdateCertificateInstance` 会让腾讯云自己去找绑定了旧证书的监听器并换掉。**这里不需要维护监听器清单**，同一监听器上的 SNI 多证书也不会被误覆盖。

## 工作原理

四条不变量。之所以这么设计，是因为真正要命的限额是**关于状态与 identifier 的**，而不是 SAN 上限 —— **New Certificates per Exact Set of Identifiers 是 5 / 7 天且无 override**，而 ARI 协调的续期豁免全部限额。所以丢掉状态库的代价远高于重签一次。

1. **每张证书任何时刻最多一个进行中的订单，且 order URL 必须落盘。** 重启会接着推进同一张订单，而不是重新下单。私钥挂在订单上、绝不覆盖生效私钥，所以部署失败时仍然留有回滚的资本。
2. **ARI 优先，且下单必须带 `replaces`。** 不带就拿不到速率豁免。
3. **wildcard 与 apex 会写到同一个 `_acme-challenge` 名字上**，所以必须 *全部写入 → 全部验证 → 才统一清理*，绝不能一条一条来。
4. **期望状态是 `domains`，不是时间。** 生效证书的 SAN 与配置不一致就立刻重签，而不是等续期窗口。否则往一张 90 天的证书里加域名，最长要 60 天才生效 —— 而且是静默的。

lego 高层的 `certificate.Obtain` 是刻意不用的：它在内部自己 `newOrder`，无法把 order URL 持久化。用低层 `acme/api` 自己掌控状态机。

完整论证见[域名随时会改](README.reference.zh-CN.md#域名随时会改)与[实测踩过的坑](README.reference.zh-CN.md#实测踩过的坑)。

## 证书生命周期

所有设计都从一条纪律出发：**wecert 永远不推断。** 由另一个东西负责算出应该有什么、并把它写下来，wecert 只读那份文档做收敛。判断只推断一次、以 diff 的形式被 review，而证书生命周期保持稳定。

### 0. 部署形态：免费证书在 CLB 上自动轮转

![wecert 的部署形态：免费证书由 Let's Encrypt 自动轮转（免费签发 → 自动换绑 → 服务 90 天 → 到期前自动再签）；选它而不是腾讯云自带的免费 DV，是因为后者单域名、不支持 SAN 也不支持通配符](docs/diagrams/zh/00-deployment-shape.png)

这套系统要解决的场景就是最上面那条带子：**Let's Encrypt 的证书不花钱，代价是有效期只有 90 天** —— 一年至少要轮 4 次，靠人记着做迟早会漏。

腾讯云自带的免费 DV 并不能替代它：**那是单域名证书，不支持 SAN，也不支持通配符**。手上只要有几个域名，就得每个域名一张证书、每条证书各自维护一条轮转。而 Let's Encrypt 一张证书最多能装 100 个名字、还支持通配符，几个域名（含 `*.example.com`）可以合成一张证书、只轮转一条 —— 下面画的那张多 SAN 证书能成立，前提就在这里。

所以重点不是"wecert 能签发"，而是"到期前它已经自己换好了，全程不用人管"。

请求带着 SNI 到 CLB。CLB 按客户端给的名字去 `multi_cert_info` 里挑证书，七层规则再按域名分流到后端 RS 池。`wecert` 就跑在其中一台 CVM 上：读 DNSPod 里的 `_wecert.*` 声明、写 `_acme-challenge` 记录、向 Let's Encrypt 取证书、上传到腾讯云 SSL 并换绑监听器。

这个形态里有两件容易被忽略的事：

- **后端 RS 完全不参与 TLS。** 解密发生在 CLB，所以证书是一份*云端资源*而不是几个文件。把 certbot 装在每台 RS 上拿不到任何好处，而假设"证书最终写进一个 Secret"的工具在这里也没有落点。
- **共用一张证书的域名生死与共。** SNI 只决定*用哪一张*，真正决定"能不能服务这个域名"的是那张证书的 SAN。所以 `a.example.com` 和 `b.example.com` 一旦进了同一张证书，其中一个的 DNS 出问题就会把另一个一起拖下水。

第二条是其余一切设计的出发点 —— 通配符优先分组、期望状态、以及到期前降级，都是因为它。

### 1. 系统全景：谁拥有什么、谁只读什么

![wecert 系统全景：声明层、推断层、契约、执行层与外部服务](docs/diagrams/zh/01-system-map.png)

从左到右是权限的传递：**意图**（人写，就是 `_wecert` TXT 记录）→ **推断**（`wecert-onboard`，可丢弃）→ **契约**（机器写的期望状态文档）→ **执行**（`wecert`，必须稳）→ **外部服务**。

这么切分是关于失败模式的。如果让 wecert 自己去枚举 DNS 和 CLB，一次接口抖动返回空就可能被读成"这些域名都没了"，于是重签一张不含它们的证书 —— 线上立刻握手失败。中间插一份文档之后，来源故障的后果变成*期望状态不更新*，那是安全的。

### 2. 意图 → 契约：推断侧流水线

![wecert-onboard 流水线：枚举声明、解析与过滤、分组与覆盖、门禁、组装、原子写盘](docs/diagrams/zh/02-intent-to-contract.png)

红色只挂在真正会冻结的地方。单条声明写错只排除那一条；某组超过 SAN 上限只保留该组上一版。**两者都不冻结整轮** —— 一个手误不该让所有证书停止更新。

**通配符优先省下的是配额。** 声明了 `*.example.com` 之后，加 `foo.example.com` 的成本是 **0 次签发**，因为 SAN 集合根本不变；批量导入 50 个子域也是 0 次，而没有通配符时那会花掉整整一周的配额。但通配符不会被凭空造出来 —— 声明 `*.example.com` 意味着证书能对*任意*子域完成握手，那必须是一个显式的决定，不能由分组逻辑替人做。

### 3. 收敛决策

![wecert 每轮对每张证书做的五个有序判断](docs/diagrams/zh/03-reconcile-decisions.png)

判断是**有序**的。第一个命中的分支决定这一轮做什么，全都不命中就是"什么都不做" —— 而那是绝大多数轮次的正常结果。

三条不变量决定了这个顺序：每张证书最多一个在途订单、且 order URL 先落盘；续期一律 ARI 优先并带 `replaces`；通配符与顶点一起写、一起验、一起清。违反任何一条都会直接撞上 *5 certificates per exact set of identifiers / 7 days*，而那条限速没有 override。

### 4. 订单状态机

![ACME 订单状态机，以及每个状态对应 state.db 里哪几个字段](docs/diagrams/zh/04-order-state-machine.png)

这个状态机的全部意义是**让进程随时可以被杀掉**。每个状态都在 `state.db` 里有对应字段，重启之后靠它们决定"接着跑"还是"重新下单"。

order URL 必须在 `newOrder` 返回之后立刻落盘，在任何别的事情之前 —— 这就是崩溃安全的全部依赖。没有它，进程在 DNS 传播那几分钟里被杀掉就会再下一单，而那一单的 identifier 集合与前一单完全相同，直接撞上 exact-set 限速。

### 5. DNS-01：通配符和顶点共用一个 TXT 名字

![DNS-01 时序，展示"全写、全验、一起清"的形状](docs/diagrams/zh/05-dns01-sequence.png)

`example.com` 和 `*.example.com` 的挑战记录都叫 `_acme-challenge.example.com` —— 同一个名字、两个值。按 identifier 逐个处理会在轮到另一个之前把值清掉或覆盖，所以必须是*全写 → 全验 → 一起清*。

传播检查用 quorum 而不是"全部权威 NS 可达"：实测 9 个里总有 1 个不可达，要求全部可达会让验证永远通不过。

### 6. 一张证书的一生

![证书生命周期时间轴：首次签发、部署、ARI 窗口、renewBefore 兜底、到期](docs/diagrams/zh/06-certificate-lifetime.png)

时间轴按 `classic` 的 90 天画。真正决定续期时刻的是 ARI 的 `suggestedWindow`；`renewBefore` 只是 ARI 拿不到时的兜底。

ARI 协调的续期**豁免 Let's Encrypt 的全部限速** —— 但前提是 identifier 集合不变。这正是通配符优先不只是优化的原因，也是"加一个域名"的成本必须被压到接近零的原因。

这些图背后的三张表 —— 数据所有权、失败语义、限速算术 —— 在[证书生命周期](README.reference.zh-CN.md#证书生命周期)，同样七张图也在那里。另有一份可交互页面：[docs/certificate-lifecycle.html](docs/certificate-lifecycle.html)，图之间有可点的跳转，还有一个打印/存 PDF 的按钮。

## 事件驱动

默认情况下 wecert 按定时器收敛。配上 `webhook` 之后也可以按需触发 ——
比如域名刚加完由 CI 直接调一次，不必等下一个整点：

```bash
curl -X POST https://wecert.internal:9801/hook/reconcile \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"cert":"example-com"}'
```

它返回 `202 Accepted`，收敛在后台跑；结果靠 `GET /hook/status` 轮询。
定时器和事件触发可能在同一时刻落到同一张证书上，所以占位是**同步**做的，
第二个调用方拿到的是 `skipped`，而不是下一个重复订单 ——
那会直接撞上"每 7 天、每个 identifier 集合 5 张"的限制。

这个端点会真实签发并消耗速率限制配额，所以 token 是必填的，且至少 16 字符；
更短会在配置加载阶段被拒。

详见[配置参考 → `webhook`](README.reference.zh-CN.md#webhook)。

## Profile

"每个 SAN 最多 100 个域名"是 profile 相关的，不是固定值：

| profile | 有效期 | Max Names |
|---|---|---|
| `classic`（默认） | 90 天 | 100 |
| `tlsserver` | 45 天 | 25 |
| `shortlived` | 160 小时 | 25 |

CA/Browser Forum 已排期 **2027-03-15 起证书 ≤100 天，2029-03-15 起 ≤47 天**，所以"90 天证书 + 人工兜底"这条路两年内就没有了。建议**每张证书不超过 25 个域名**：既对齐 `tlsserver`，也控制住爆炸半径 —— 同一张证书里的域名是"生死与共"的，会一起成功、一起失败、一起过期。

> 增删域名会让这次签发变成一张新证书，因此要走 **Certificates per Registered Domain（50 / 7 天）**，而不是享受 ARI 豁免。

### 当域名由别处声明时

如果域名是由其他人或其他系统加进来的，`wecert-onboard` 可以把这份判断完全从 wecert 里拿出去。域名以 `_wecert` TXT 记录的形式声明在 DNS zone 里，由这个二进制把它们变成一份可评审的期望状态文档，而 **wecert 只读这份文档 —— 它自己绝不推断任何东西**。

回报就在上面的配额算术里。声明了 `*.example.com` 之后，再加一个 `foo.example.com` 的签发成本是**零**；如果没有通配符、直接导入 50 个子域，代价是 50 次重新签发。

删除被刻意设计得比新增保守一个数量级，而且整套东西可以先跑只读的 `observe` 模式。从[期望状态](docs/desired-state.md)开始读。

## 文档

- [完整参考](README.reference.zh-CN.md) —— 架构、收敛状态机、状态库结构、逐字段配置说明、运维，以及实测踩过的坑。
- [为什么是这么设计的](README.reference.zh-CN.md#为什么是这么设计的) —— 是哪些速率限制决定了这套设计。
- [配置参考](README.reference.zh-CN.md#配置参考) · [运维](README.reference.zh-CN.md#运维) · [监控与告警](README.reference.zh-CN.md#监控与告警)。
- [实测踩过的坑](README.reference.zh-CN.md#实测踩过的坑) —— CLB 的 SNI 陷阱、`DescribeListeners` 不回读绑定、DNSPod 的 TTL 下限、lego 的 API 陷阱。
- [期望状态](docs/desired-state.md) —— 用 `_wecert` DNS 声明域名、生成期望状态文档、以及把 wecert 切过去。设计取舍见 [desired-state-providers.md](docs/desired-state-providers.md)。
- [证书生命周期](README.reference.zh-CN.md#证书生命周期) —— 七张图，从"它要解决什么问题"一路画到旧证书退役，另附数据所有权、失败语义和限速算术。可交互版本：[docs/certificate-lifecycle.html](docs/certificate-lifecycle.html)。
- [证书全生命周期验收用例](docs/lifecycle-acceptance.md) —— 可执行的验收清单：在真实 DNSPod + Let's Encrypt **staging** 上，从首签、SAN 增删、wildcard 与 apex 共享 TXT 名、并发双证书，到 ARI 与回退两条续期路径、中断自愈，以及声明 → 期望状态文档 → enforce 的交接，逐阶段给出可观测判据。
- [现状与下一步](README.reference.zh-CN.md#现状与下一步) · [开发](README.reference.zh-CN.md#开发)。

<details>
<summary>命令行参考</summary>

### `wecert`

| 参数 | 默认 | 说明 |
|---|---|---|
| `-config` | `config.yaml` | 配置文件路径 |
| `-state` | — | 覆盖 `statePath`（便于测试） |
| `-once` | `false` | 只跑一轮就退出（配合 systemd timer / cron） |
| `-interval` | `1h` | 守护模式下的收敛间隔 |
| `-log-level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `-dry-run` | `false` | 只校验配置并初始化 ACME 账号，不签发也不部署 |
| `-version` | `false` | 打印版本后退出 |

### `wecert-onboard`（期望状态生成器）

把 DNS 里的 `_wecert` 声明变成 `wecert` 读的那份期望状态文档。一次性进程，
由 systemd timer 驱动，跑完就退出。只有 `desiredState.mode` 离开 `static` 之后才需要它。
完整说明见 [期望状态](docs/desired-state.md)。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-config` | — | **必填。** 与 `wecert` 同一份配置；策略在 `onboarding` 那一节 |
| `-out` | `desiredState.path` | 期望状态文档的写入路径 |
| `-state` | `<out>.state.json` | 宽限期与配额预算的账本 |
| `-report` / `-no-report` | `<out>.report.json` | 逐 hostname 的决策报告 |
| `-zones` | 所有可见 zone | 要枚举的 DNS zone，逗号分隔 |
| `-require-clb` | `true` | 守卫 1：声明必须同时有 CLB 规则才生效 |
| `-allow` | — | 允许签发证书的注册域，逗号分隔 |
| `-max-names` | `25` | 单证书 SAN 上限 |
| `-grace` | `24h` | 确认缺失多久之后才允许移除 |
| `-budget` / `-budget-window` | `25` / `168h` | 窗口内允许的集合变更次数 |
| `-drop-threshold` | `0.30` | 集合缩小超过这个比例就冻结 |
| `-force` | `false` | 跳过骤变保险丝、删除宽限期、配额预算**以及 CLB 引用检查**（跳过不了「来源读不出来就冻结」）；只用于你确认过的那次变更 |
| `-dry-run` | `false` | 只算不写 |
| `-json` | `false` | 报告以 JSON 输出 |

退出码：`0` 已写出（或与上一版相同）、`1` 程序自身出错、`2` **有意冻结** —— 去看报告。

```bash
./bin/wecert-onboard -config /etc/wecert/config.yaml -dry-run   # 先看会改什么
./bin/wecert-onboard -config /etc/wecert/config.yaml            # 落盘
```

### `wecert-preflight`（只读）

| 参数 | 说明 |
|---|---|
| `-domain` | 验证 SSL 读权限、DNSPod 归属、NS 委派与 `_acme-challenge` 残留 |
| `-list-certs` | 列出账号下的 SSL 证书 |
| `-prune-certs` | 删除 wecert 上传的证书（别名前缀 `wecert/`） |
| `-yes` | 跳过 `-prune-certs` 的交互确认 |

> `-prune-certs` 的判据是别名前缀 `wecert/`，而 wecert 对**所有**它上传的证书都用这个前缀 —— 包括当前正在服务的那张。命令会先打印清单并要求确认，非交互 stdin 按拒绝处理。

### `wecert-probe`（网络侧取证）

拨一个真实的 TLS 连接，读回对端实际出示的证书。这是 wecert 里**不**信任云控制面的那一部分：重绑定是异步的，SNI 上也可能有另一张证书在赢 —— 这两件事控制面都看不出来。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-host` | — | **必填。** 要拨的名字，逗号分隔 |
| `-port` | `443` | 要拨的端口 |
| `-timeout` | `10s` | 单次超时 |
| `-min-valid` | `0` | 服务中的证书剩余有效期少于它就判失败，例如 `168h` |
| `-expect-san` | — | 部署下去的 SAN 集合，必须完全一致 |
| `-expect-not-after` | — | 部署那张证书的 `notAfter`（RFC3339），用来抓"换绑没生效" |
| `-wait` | `0` | 轮询到通过或超时，例如 `90s` —— 刚换完绑时有用 |
| `-json` | `false` | 以 JSON 输出原始结果 |

退出码：`0` 与预期一致 · `1` 探测根本没跑成 · `2` 探测跑成了，但服务的是错的证书。

```bash
./bin/wecert-probe -host www.example.com -min-valid 168h
./bin/wecert-probe -host www.example.com -wait 90s        # 刚换完绑
```

> 它拨不了通配符 —— `*.example.com` 没有自己的地址。请拨同一张证书覆盖的某个具体名字。

### `wecert-clbverify`（独立取证）

| 参数 | 说明 |
|---|---|
| `-region` / `-clb` / `-listener` | 目标监听器；`-listener` 省略则取该 CLB 下的第一个 |
| `-expect` / `-not-expect` | 断言主证书 ID 等于 / 不等于 |
| `-wait` | 轮询等待重绑定的最长时间（异步，实测约 15s） |
| `-raw` | 原样打印 `DescribeListeners` 的 JSON |

```bash
./bin/wecert-clbverify -region ap-guangzhou -clb lb-xxxx -listener lbl-yyyy \
  -expect apJdfyPa -not-expect apJRqDsC -wait 90s
```

</details>

## License

[MIT](LICENSE)
