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

![wecert 系统全景：声明层、推断层、契约、执行层与外部服务](docs/diagrams/01-system-map.png)

从左到右是权限的传递：**意图**（人写，就是 `_wecert` TXT 记录）→ **推断**（`wecert-onboard`，可丢弃）→ **契约**（机器写的期望状态文档）→ **执行**（`wecert`，必须稳）→ **外部服务**。

这么切分是关于失败模式的。如果让 wecert 自己去枚举 DNS 和 CLB，一次接口抖动返回空就可能被读成"这些域名都没了"，于是重签一张不含它们的证书 —— 线上立刻握手失败。中间插一份文档之后，来源故障的后果变成*期望状态不更新*，那是安全的。

![证书生命周期时间轴：首次签发、部署、ARI 窗口、renewBefore 兜底、到期](docs/diagrams/06-certificate-lifetime.png)

每一轮问的都是同样五个有序的问题，而绝大多数轮次的答案是"什么都不做"。续期一律 ARI 优先并带 `replaces`，因为 ARI 协调的续期**豁免 Let's Encrypt 的全部限速** —— 而域名集合一变，这次签发就是一张全新证书，豁免随之失效。这正是通配符优先不只是优化的原因：声明了 `*.example.com` 之后，加 `foo.example.com` 的成本是 **0 次签发**。

完整的故事 —— 六张图，加上数据所有权、失败语义和限速算术 —— 在[证书生命周期](README.reference.zh-CN.md#证书生命周期)。另有一份可交互页面：[docs/certificate-lifecycle.html](docs/certificate-lifecycle.html)，图之间有可点的跳转，还有一个打印/存 PDF 的按钮。

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

## 文档

- [完整参考](README.reference.zh-CN.md) —— 架构、收敛状态机、状态库结构、逐字段配置说明、运维，以及实测踩过的坑。
- [为什么是这么设计的](README.reference.zh-CN.md#为什么是这么设计的) —— 是哪些速率限制决定了这套设计。
- [配置参考](README.reference.zh-CN.md#配置参考) · [运维](README.reference.zh-CN.md#运维) · [监控与告警](README.reference.zh-CN.md#监控与告警)。
- [实测踩过的坑](README.reference.zh-CN.md#实测踩过的坑) —— CLB 的 SNI 陷阱、`DescribeListeners` 不回读绑定、DNSPod 的 TTL 下限、lego 的 API 陷阱。
- [期望状态](docs/desired-state.md) —— 用 `_wecert` DNS 声明域名、生成期望状态文档、以及把 wecert 切过去。设计取舍见 [desired-state-providers.md](docs/desired-state-providers.md)。
- [证书生命周期](README.reference.zh-CN.md#证书生命周期) —— 六张图，从 DNS 声明一路画到旧证书退役，另附数据所有权、失败语义和限速算术。可交互版本：[docs/certificate-lifecycle.html](docs/certificate-lifecycle.html)。
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
| `-force` | `false` | 跳过全部熔断；只用于你确认过的那次变更 |
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

仓库里没有 LICENSE 文件，默认即"保留所有权利"。**对外分发或接受外部贡献之前应当先补一个。**
