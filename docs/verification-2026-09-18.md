# 未验证项的实测核查（2026-09-18）

前十一轮 review 的每一份报告末尾都有一节「仍然未验证」。这份文件把那些条目**逐条拿去实测**：能在这里验的给出证据，验出来的缺陷修掉并留下会变红的用例，验不了的写清楚卡在哪里 —— 而不是继续写着"未验证"。

配套阅读：第十一轮报告 [code-review-round11-2026-09-18.md](code-review-round11-2026-09-18.md)（三个视角与 29 条修复）、带凭据云上报告 [e2e-run-2026-09-18-credentialed.md](e2e-run-2026-09-18-credentialed.md)。

---

## 0. 一句话结论

**101 条"未验证"里，69 条本机可验**：这一轮把其中最有分量的一批真跑了 —— 真实 Let's Encrypt **生产**签发与 ARI 驱动的续期、真实 DNSPod 的记录名形态、真实端点的探针三态、Linux 容器里的 `install.sh` 全流程与 145 次 SIGKILL 崩溃安全、完整恢复演练、老二进制读新 schema —— 并且**实测又找出 10 个缺陷**（全部已修、全部有会变红的用例）。剩下 13 条本机做不到、7 条**本质上无法验证**（例如"真实断电"和"90 天自然到期"），逐条写在 §4。

---

## 1. 执行通道

| 通道 | 用到的真实东西 | 覆盖的典型条目 |
|---|---|---|
| A · 真实 Let's Encrypt **生产** | `acme-v02`，真实 DNSPod zone `atomwangnus.com`，CAM 凭据，独立 state 目录 | 生产签发、生产 ARI、ARI 驱动续期（`replaces`）、续期时的 authz 复用、TXT 回收自愈 |
| B · 真实 DNSPod API | DNSPod v20210323 SDK + lego 的 `tencentcloud` provider + 仓库自己的 `internal/onboarding` | 记录名的尾点/相对名/大小写三种形态、同名多值、一次 CleanUp 的删除范围 |
| C · 真实 TLS 端点 | 公网 IPv4-only 端点 + 该账号 CLB 上的真实监听 | `wecert-probe` 的正例/反例/覆盖不符/部分地址不可达 |
| D · 容器化 Linux | `docker`（colima）+ ubuntu:24.04 + 真实 `systemd-analyze` | `install.sh` 全流程、`-once`/守护进程的崩溃与 I/O 故障注入 |
| E · 本机 | 真实二进制 + 真实 state 目录 | 恢复演练 §7、降级兼容、文档断言 |

所有对云账号的操作都只碰本轮自己创建的对象（按 ID 删除），**没有**运行 `wecert-preflight -prune-certs`，DNSPod 上只创建/删除了 18 条 `wecert-verify-r11*` 记录并逐条核对清零。

---

## 2. 已证实（逐条 + 证据）

### 2.1 真实生产 Let's Encrypt（U2，十一轮都写着"未验证"）

```
level=INFO msg="ACME order created" cert=round11-prod status=pending profile=classic replacesRequested=false
level=INFO msg="TXT presented" identifier=round11-prod.atomwangnus.com name=_acme-challenge.round11-prod.atomwangnus.com.
level=INFO msg="TXT propagated" zone=atomwangnus.com. nameservers=10 records=1
    evidence="_acme-challenge... = 5aS-1uF5Dmv9kxTdopjwwJOjFKrgzTbnPEYrfdS9YJU (confirmed 3/3 server(s) / denied 0 / non-authoritative 0 / unreachable 5 (of 10 addresses))"
level=INFO msg="certificate issued and recorded locally (cloud deploy is off)" notAfter=2026-12-17T07:25:32.000Z daysLeft=90
```

生产签发（`profile: classic`，90 天）在**没有任何人工干预**的情况下完成：真实 order、真实 TXT 写入、真实权威传播确认（3/3 确认、0 否认、10 个地址里 5 个不可达）、真实签发与下载。**没有使用 staging。**

**生产 ARI**（第一次签发后的下一轮）：

```
level=INFO msg="ARI window refreshed" cert=round11-prod start=2026-11-16T10:09:37.000Z end=2026-11-18T05:20:27.000Z retryAfter=5h56m27s
```

**ARI 驱动的续期 + `replaces`**（把 ARI 窗口按仓库自己的文档推到过去后跑一轮）：

```
level=INFO msg="starting renewal" cert=round11-prod notAfter=2026-12-17T07:25:32.000Z renewAt=2026-09-17T05:47:46.510Z ariReplaces=true
level=INFO msg="ACME order created" cert=round11-prod status=ready expiresAt=2026-09-25T08:29:36.000Z names=1 replacesRequested=true
level=INFO msg="certificate issued and recorded locally (cloud deploy is off)" notAfter=2026-12-17T07:31:05.000Z daysLeft=90
```

两点值得单独记下来：订单**直接是 `ready` 状态**（CA 复用了仍有效的 authorization，所以续期这一轮**没有写任何 TXT**）—— 这是"续期不消耗 DNS 写入、也不消耗授权失败额度"的实证；`replacesRequested=true` 说明 ARI 豁免的前提（与被替换证书共享标识符）在真实 CA 上被接受，**没有**报错。

**TXT 回收是自愈的**（第一轮的 WARN 是刻意保留，不是失败；见 §3.2）：

```
第 2 轮（挑战后 3m38s，仍在 5m 传播窗口内）：
level=INFO msg="an unpresented row's record was denied, but its challenge is newer than the propagation window; keeping the row ..." preparedAgo=3m38s window=5m0s
第 4 轮（窗口之后）：无任何 WARN，authorizations 行数 0，三个权威上均查不到该 TXT
```

**这次生产运行的真实成本（如实记账）**：为了验证，生产目录上注册了 1 个新的 ACME 账号（LE 限额：每 IP 每 3 小时 10 个），签发了 1 张新证书（`round11-prod.atomwangnus.com`，属于全新的 exact-set，占 5/7 天里的 1 张），并用一次 ARI 豁免的续期换掉了它（`replaces=true`，按 LE 的规则不计入 exact-set 额度）。这些都在本账号的常规额度内，且全部发生在测试域名下。

### 2.2 真实 DNSPod 的记录名形态（U10）

18 条记录、逐条按 RecordId 删除，最终 `wecert-verify-r11` 匹配 0 条（zone 里只剩预先存在的 `_dmarc`）。字节级观测：

| 实验 | 写入 | 读回 | 结论 |
|---|---|---|---|
| 完整主机名 | `SubDomain="_wecert-verify-r11.atomwangnus.com"` | 同样字节，无尾点 | API **原样返回**，不会"相对化" |
| 相对名 | `"_wecert-verify-r11"` | 同样字节 | 原样往返 |
| 尾点 | `"_wecert-verify-r11."` | **拒绝**：`InvalidParameter.SubdomainInvalid` | 这种写法根本存不进去 |
| 大小写 | `"_WeCert-Verify-R11"` | 存为小写 | 写读唯一真实差异；查询大小写不敏感且**精确**（兄弟名 `...-b` 不会被误命中） |
| 同名多值 | 同一名下 2–3 条 TXT | 全部返回，各有 RecordId | 不会被折叠成一条 |
| lego 往返 | `Present` → `CleanUp` | 写读字节一致；**一次 CleanUp 删掉同名两条** | 证实 `challengeLeases` 的 delete-all 前提 |

**结论：清理与去重对这三种形态都能正确处理**（清理路径从不回读 API 返回的 Name，而是用本地推导的 FQDN 建键；大小写在 config 归一化阶段就已经统一）。但同一批实验暴露了一个**声明枚举路径**的真实缺陷，见 §3.1。

### 2.3 真实端点的探针三态（U84）

| 场景 | 真实对象 | 结果 |
|---|---|---|
| 正例（带全部断言） | `www.forevernine.net`（该账号 CLB 上的真实监听，IPv4-only） | `verdict ok`，**exit 0**（`-expect-not-after` + `-expect-san` + `-min-valid 24h`） |
| 反例（期望值错） | 同上，`-expect-not-after` 写错 | **exit 2**，诊断正确："the served certificate expires at 2026-11-25T23:59:59Z but the deployed one expires at 2026-12-31T00:00:00Z（the rebind did not take effect, or another certificate is winning SNI）" |
| 覆盖不符 | `test.alpha.atomwangnus.com`（解析到 119.91.16.17，实际服务的是 `*.forevernine.net`） | 明确指出"服务的证书不覆盖这个名字"，并列出它实际覆盖的 SAN |
| 部分地址不可达 | `www.cloudflare.com` / `www.python.org`（双栈，本机无 IPv6 路由） | **exit 1**，"some resolved addresses could not be probed"，正是文档里"`probe_match=0` 也可能是环境问题"的那条 |

### 2.4 Linux 容器：`install.sh` 全流程（U89）

14 条断言全部成立（都是真实执行，不是读代码）：建 `wecert` 用户（uid 997、nologin）；二进制装到 `/usr/local/bin/wecert` 且 sha256 与 `dist/` 一致；**`wecert-onboard` 从 release 命名那份装过去**（第十一轮的修法在真实容器里成立）；`/etc/wecert` 0750 root:wecert、`/var/lib/wecert` 0700 wecert:wecert；`config.example.yaml` 逐字节一致地装成 `/etc/wecert/config.yaml` 且**第二次运行不覆盖**（哨兵行仍在）；三个 unit 逐字节一致；SHA256SUMS 缺失→警告+继续、不匹配→拒绝且什么都不装、未列出→拒绝；unit 缺失→非零退出；打印的校验命令确实能跑（只在校验时停在文档化的 `ops@example.com` 前置条件上）；**什么都没启动**（stub `systemctl` 只收到一次 `daemon-reload`）；`-version`/`-h` 退出码正确；`systemd-analyze verify`（systemd 255）对三个 unit 全部 0 退出、无输出。

### 2.5 Linux 容器：崩溃与 I/O 故障（U11、U45、U50）

- **145 次 SIGKILL**（随机时点 60 次、快照临时文件出现时 25 次、临时文件真写到 8–15 MiB 时 20 次、48 MiB 库上 5–150ms 时点 40 次）：`quick_check` 失败 **0**、schema 失败 **0**、**已安装的快照**损坏 **0**、数据库丢失 **0**。被杀的快照只有 `.snapshot-*.tmp` 残留，**从不**以快照名出现。
- **fsync / rename EIO 注入**（静态 Go 二进制无法 LD_PRELOAD，改用 strace 在原生 arm64 上按系统调用注入）：进程每次都如实报 `state database snapshot failed`，从不声称成功；注入后 `state.db` sha256 **未变**、`quick_check` ok、schema 与行完好、此前安装的快照仍可用；rename 注入失败时没有装出快照、临时文件被清掉。
- **运行中 `rm -rf` 状态目录**：每一轮都打 ERROR，逐字包含"is no longer at that path ... this process is still writing to the file it opened"与锁文件丢失的伴随问题；守护进程不退出；把 `state.db` 原地替换（inode 变了）则报"has been replaced since this process opened it"。
- **守护进程持锁时 `-restore`**：exit 1，报文点名锁文件并让人先停服务；状态目录里**没有任何文件被改动**，守护进程继续运行。

### 2.6 恢复演练（staging-checklist §7，U46）

用真实二进制在真实目录上跑完整套：删掉 `state.db` → `-restore latest` 选中最新的快照、打印快照日期/内容/`caveatUntil`；落盘后 `state.db`（0600）+ `state.db.restored`，**没有** `-wal`/`-shm`；恢复出来的内容正是快照时刻的状态（快照之后的写入没有回来）；再恢复一次时被替换的库保留为 `state.db.replaced-<stamp>`、内容完好；下一次启动打出"this state database was restored from a snapshot …"的 WARN（含 restoredAt/dataFrom/caveatUntil）；`mv` 回被替换的库即可回到较新的状态。

### 2.7 降级：老二进制读新 schema（U62）

`v0.4.2` 标签构建出的二进制打开当前 HEAD 建出的状态库（库里已包含新表 `revoke_requests`、`rate_buckets` 及其数据）：`-dry-run` **exit 0**，日志中 `duplicate column` / `no such column` / `needs a schema update` / `no such table` 出现 **0 次**，九张表与两行新数据原样保留。附加迁移确实只增不减，回滚到旧版本不会破坏状态库。

### 2.8 生命周期文档的 63 条断言（U18）

`docs/certificate-lifecycle.html` 逐条对照代码：**8 条是错的，已改**（ARI 豁免前提、DNS-01 传播 quorum、`DescribeListeners` 不回读绑定、failureFallback 的自愈时点、Go 版本），**50 条成立**，5 条无法判定（腾讯云免费 DV 的单域名说法、CLB 健康检查源地址、ARI 窗口约 2/3 处等页面独有或 CA 侧的事实）。英文页面与两张图随之重新生成（生成脚本硬性要求中文改动在翻译表里有对应项，因此 `scripts/diagram_i18n.py` 一并更新），"当前版本 v0.5.0"这种不存在的版本号也改成 `v0.4.2 + 未发布改动`。

---

## 3. 实测发现的缺陷（10 条，全部已修 + 会变红的用例）

| # | 位置 | 缺陷 | 怎么发现的 | 修法 |
|---|---|---|---|---|
| 1 | `internal/onboarding/tencent.go` | 声明枚举把 API 返回的完整主机名再拼一次 zone：`_wecert.x.atomwangnus.com` → `…com.atomwangnus.com`，而 `ParseDeclaration` **接受**了它，于是期望状态里多出一个根本不属于该 zone 的名字（订单只能验证失败，白烧每标识符的授权失败额度） | DNSPod 实测发现 API 会原样返回完整主机名（旧注释假设"DNSPod 只返回相对名"，那条假设本身还写在一个测试用例里） | 按标签边界去重（`_wecert.notexample.com` 仍算 `example.com` 内部的名字）；把钉住旧假设的用例改成记录这次反驳 |
| 2 | `internal/acme/manager_flow.go` | 传播窗口内的"刻意保留"被算进"无法自动回收"，于是**任何**在签发后 5 分钟内跑的 pass 都会打一条 WARN —— 而记录其实已经确认不在 DNS 里了 | 生产首签那一轮就打了这条 WARN，第 4 轮却干净地删掉了行 | `reclaimUnpresentedTXT` 改为三态枚举，调用方分开计数：刻意等待只留 Info，WARN 只留给"查不出来" |
| 3 | `install.sh` | `systemctl daemon-reload` 未加保护，在容器/WSL（systemd 不是 PID 1）或没有 systemctl 的机器上让脚本**在装完一切之后、打印完成块之前**退出（1 或 127），运维会把成功安装读成失败 | 容器实测 | 加守卫，并提示"到真正跑 unit 的机器上再 daemon-reload" |
| 4 | `install.sh` | 只校验 wecert 二进制的 sha256；`wecert-onboard` 同样以 root 安装、0755、由 timer 执行，而 `make release` 明明把它的校验和写进了同一个 SHA256SUMS | 容器实测（把 onboard 的校验和改坏，脚本照样装） | 用同一份 sums 校验 onboard，不匹配即拒绝、未列出则警告 |
| 5 | `install.sh` | unit 缺失的分支在报错之后**仍然**打印"Installation complete … 3) Start the service" | 容器实测 | 该分支不再打印成功横幅（非零退出保留） |
| 6 | `internal/state/state.go` | 创建数据库时 I/O 出错会留下一个 **0 字节**的 `state.db`，下一次健康启动把它当全新库静默迁移 —— "数据库被删/丢了"的警告只在文件**不存在**而锁文件存在时才触发 | 注入 fsync EIO 实测 | 0 字节 + 锁文件存在同样触发那条警告 |
| 7 | `internal/state/backup.go` | 崩溃留下的快照临时文件要等满 1 小时才被清理，而且 SQLite 在旁边写的 `-journal` 根本不在清理模式里；48 MiB 的库每次崩溃能留下几十 MiB 私钥副本 | 快照写到一半时杀进程实测 | 临时文件名带上本 store 的 base，属于**本 store** 的临时文件（含 `-journal`）在加锁的那一轮快照里立即清理；别家部署的文件仍走 1 小时阈值 |
| 8 | `cmd/wecert/main.go` | `-once` 的立即快照失败只留一条后台 goroutine 的 ERROR，退出码仍是 0 —— 而 timer 模式的 unit 状态是唯一报警通道，于是"备份路径坏了"这件事永远不报警 | 注入 fsync EIO 实测（pass 收敛、exit 0） | 立即快照的结果送进一次性运行的退出码判断；措辞上把"这一轮没收敛"和"收敛了但没有备份"分开；守护进程仍不因一次快照失败退出（下一轮会重试并记账） |
| 9 | `cmd/clbverify/main.go` | **本轮自己引入的回归**：第十一轮把这个工具改成自己的 `FlagSet`（为了 64 退出码约定）时改掉了 region/listener/expect/domain/not-expect/raw/wait，**漏了 `-clb`**，它还挂在 `flag.CommandLine` 上从未被解析 —— 于是 `docs/staging-checklist.md` 1.5/4.2 里那条命令必退 64（`flag provided but not defined: -clb`） | 真实账号里按文档验证换绑时发现：换绑本身成功了（规则的 CertId 从 `atcRHVHh` 变成 `atcuQ0dm`，deployRecord 15612、`boundResources=1`），而"用来证明它"的工具根本跑不起来 | 改成 `fs.String`；`-clb` 至少能走到凭据检查（exit 1）而不是用法错误 |
| 10 | `internal/deploy/tencent.go` | `Delete` 在 `DeleteResult == false` 时直接返回"API 拒绝了删除"、**从不轮询异步任务**。而真实 API 在 `IsCheckResource=true` 时**两种结果都返回 false**：绑定中 → 任务 status 4（"There are unbound cloud resources: clb, that cannot be deleted."），已解绑 → 任务 status 1 且证书真的被删。后果是双向的：**已经删掉的证书被报成"被拒绝"**（`retired_certificates` 行永远清不掉、每轮都再警告一次，staging-checklist §2.2 永不成立），而**status 4 这个"服务端还在引用"的信号从来没被报出来过** | 真实账号实测（旧二进制 + 产品自己的 `ReapRetired` 路径：日志说"the API refused the delete"，而 `DescribeCertificate` 已经 `CertificateNotFound`，行仍在） | `false` 只在**没有任务 ID** 时才算拒绝；有任务就轮询并按下文状态判定（1 成功 / 4 拒绝 / 其它照实报）。用例改成模拟**真实**语义（`false` + status 1 = 成功、`false` + status 4 = 拒绝、`false` 且无任务 = 拒绝）—— 原来 10 个用例全用 `DeleteResult=true`，等于把不存在的 API 写进了假客户端 |

另外顺手修掉两处同批发现的措辞/行为问题：`Tx.AddRetiredCert` 缺空 id 守卫（第 10 轮记为待办，现已与 `Store.AddRetiredCert` 一致，附会变红的用例）；`-restore latest` 在快照目录**不存在**时打的是 `open(2)` 原始错误，而不是"这个库里没有快照"。

---

## 4. 仍然无法在这里验证的（逐条写清卡点）

### 4.1 本质上无法验证（7 条）

| 条目 | 为什么 |
|---|---|
| **自然到期续期（真实 30–90 天时间轴）** | 生产证书 90 天、staging 最长 6 天，会话里等不到。这一轮用**压缩时间**做了最接近的两件事：真实生产 ARI 窗口 + `replaces` 的续期（把窗口推到过去，其余全部真实），以及容器里 pebble 短有效期 profile + **真实墙钟**等待 ARI 窗口自行打开的续期（见 §5）。它们证明"续期由 ARI 窗口驱动、订单带 replaces"，但"在真实 CA 上等 60 天自然到期"只能靠时间 |
| **CA 会不会在同一个 authz URL 上换挑战** | 需要 CA 侧行为，且无法诱发。可做的方式（自己搭权威 DNS 并把子域委派给它、让 CA 查到"变化中的答案"）需要一台有公网 53 端口、且被真实 CA 查询的机器 |
| **真实断电 / 掉页** | 容器里只有 SIGKILL：进程死了，页缓存仍由内核刷盘。这一轮用 strace 注入 fsync/rename EIO 覆盖了"持久化调用失败"这一半，另一半（扇区级损坏、页缓存丢失）需要 dm-flakey/loop 设备或虚机级断电 |
| **逗号 SAN** | 需要 CA 签发一个 SAN 里带逗号的证书，公共 CA 不会 |
| **形式化验证** | 仓库里没有模型可对照 |
| **工具证据的边界（"没有证据"≠"不存在"）** | 方法论问题：任何工具都只能证明它检查过的东西 |
| **真实生产运行履历** | 需要别人的 fleet 跑上一年 |

### 4.2 本机条件做不到（13 条，各带卡点）

- **Stage C（CVM + systemd + 实例角色）的"首次绑定→自动换绑"重跑**（U6/U79/U82）：需要新建一台带公网 IP 的 CVM（有费用）。09-18 的带凭据报告已经在真机上跑过一遍（TAT 驱动、角色取证、磁盘无凭据）；这一轮没有重复付费。
- **SNI 多证书 / `e2e-sni.sh` 全流程**（U43/U98）：这一轮的云上任务建了带 SNI 规则的真实 CLB 并做了真实换绑（§5），但**本账号完全忽略监听器级绑定**（`extCertIds` 恒空），所以"两个证书挂在一个监听器上"的那条路径在这里没有被真实数据走到。
- **`wecert-preflight -prune-certs` 非交互 stdin 视为 no**（U90）：**故意不跑** —— 共享账号里它一旦行为不符会删掉别人正在服务的证书。要验只能在一次性账号上。
- **CAM 策略的"最小且充分"在真实账号上生效**（U42）：静态检查（`check-cam-policies.py`，10 个 API 全覆盖）已通过；"用这套策略真的能跑通、且多一个 API 会被拒"需要在子账号上挂策略实测。
- **真机 systemd 启动 unit**（U45 的最后一米）：容器里只做了 `systemd-analyze verify`，没有让 systemd 真正拉起服务。
- **`run-stage-ab.sh` 全流程**（U101）：需要 terraform apply 出一台 CLB/CVM；脚本的 plan-only 分支与校验逻辑已在静态检查里覆盖。
- **多注册域 / 第二个 zone**（U49）：账号里只有一个可写 zone（`atomwangnus.com`），跨域配额行为无法实测。
- **负载与浸泡**（U47）：需要长时间高并发与真实 DNS/CA 压力；这一轮只做了合成规模的单轮测量（第十一轮规模视角）。
- **`-once` 与 webhook 同机并发的真实竞态频率**（U12）：需要长时间真实流量才能给出频率，代码路径本身有单测。
- **DNSPod 控制台对"主机记录里带 zone"的行为**（U10 的残留问题）：无控制台访问权限，只证明了 API 侧行为。
- **本地 pebble 直连 CLI**（U85）：macOS 上 Go 不认 `SSL_CERT_FILE`，而产品没有 CA 覆盖开关；容器里可以（§5）。
- **真实 CA 侧的 DNS-01 校验**（U86/U87）：本机 53 端口被占时 `make e2e` 会 SKIP（按第十一轮语义即失败）；容器里用 `--cap-add=NET_BIND_SERVICE` 可以真跑（§5）。

---

## 5. 真实 CLB 的结果（U8/U40/U41）

在真实账号里新建内网 CLB + HTTPS 监听与 SNI 规则、上传并绑定证书、跑真实换绑、并用产品自己的删除路径做对照。三条结论：

| 断言 | 结果 | 证据 |
|---|---|---|
| **C1 · 云端 `IsCheckResource` 语义** | **云端行为成立、产品消费它的方式不成立（已修，见 §3 第 10 条）** | 绑定中：`DeleteResult=false` + 任务 status **4**（"There are unbound cloud resources: clb, that cannot be deleted."），证书与规则都还在；解绑后同一次调用：任务 status **1**，证书真的消失；绑定中改用 `IsCheckResource=false`：同步 `DeleteResult=true`，证书被删掉而规则仍引用它 —— 这正是 `-prune-certs` 那条"服务端不会保护你"的告警所描述的危险 |
| **C2 · 真实换绑** | **换绑本身成立；用来验证它的工具坏了（已修，见 §3 第 9 条）** | 强制续期后 LE staging 证书 `atcuQ0dm` 上传成功，`UpdateCertificateInstance(old=atcRHVHh, new=atcuQ0dm)` 返回 deployRecord 15612 / success=1，日志"verified the adopted update task … boundResources=1"，`DescribeListeners` 显示规则 `loc-27xgx4tq` 的 certId 已从 `atcRHVHh` 变为 `atcuQ0dm` |
| **C3 · 真实端点探针** | **本机不可验证** | CLB 是内网（`vips=[10.99.1.16]`，无公网域名），名字在公网 DNS 上是 NXDOMAIN；本机 VPN 路由又吞掉所有端口（`connect` 成功但 TLS 回 `WRONG_VERSION_NUMBER`）。需要一台 VPC 内的机器（= 公网 CVM 的费用）才能做真实握手。**公网端点的探针三态已在 §2.3 用真实清单验证** |

附带的事实（值得记进文档）：这个账号**完全忽略监听器级别的证书绑定**，SNI 证书落在规则的 primary `CertId` 上，`extCertIds` 始终为空 —— 所以 `docs/staging-checklist.md` 里"SNI 监听器需要 `multi_cert_info`"那段在本账号上不成立（真机行为以账号而定，规则级 CertId 才是唯一入口）。

清理已核对：本轮创建的 5 张证书、2 台 CLB、规则/VPC/子网/安全组全部按 ID 删除，terraform state 为空，DNSPod zone 仍是 11 条记录且 0 条 `r11`/`_acme-challenge`，账号里原有 36 张证书**逐张完好**；`-prune-certs` 从未运行。

---

## 6. 容器里的真实 DNS-01 与自然墙钟续期

### 6.1 "真实 DNS-01 套件在本机永远跑不起来"—— **被反驳**

那条结论（十一轮都写着 U86/U87）成立的前提是"53 端口在 macOS 上被占"，而**换到 Linux 容器里用 `--cap-add=NET_BIND_SERVICE` 就能真跑**。实测（ubuntu:24.04 + Go 1.26.8 + pebble v2.10.1，仓库只读挂载后 `diff -r` 核对过字节一致）：

```
make e2e → 三个套件全过、exit 0（23s / 6s / 22s）
套件 1（真实 DNS-01）RUN 而不是 SKIP，18.49s，7 个子用例全 PASS：
  e2e_dns_test.go:619: pebble https://127.0.0.1:14000/dir;
  validation: real validation: the CA read the challenge record from the authority itself
证据（套件自己记的权威查询日志，也在 HTML 报告的 UDP/TCP 表里）：
  "propagation probe queried TXT _acme-challenge.a.e2e.example.com over UDP"
  "the CA's validator queried TXT _acme-challenge.a.e2e.example.com over TCP"     （.b 同名一对）
  合计 40 次 TCP TXT 查询 / 381 次 UDP；transports: authority answered over udp,tcp（没有不可达）
签发："issued 2026-09-18T08:33:21Z..2026-12-17T08:33:20Z, 2 SAN(s)"，issuer "Pebble Intermediate CA 5501c2"
make test-pebble → pass，exit 0
```

这是整份清单里最重要的一条：**CA 侧真的读到了我们写下的 TXT**（而且探针走 UDP、CA 的验证器走 TCP，两条路径都被真实查询过），不再只是"我们的传播检查说它看见了"。

### 6.2 自然墙钟续期（压缩时间，但时钟是真的）

用 pebble 的 `shortlived` profile（`validityPeriod: 900` 秒）让守护进程按**真实时间**等 ARI 窗口自己打开：

```
run 1（-once）签发 shortlived 证书：notAfter 2026-09-18T08:52:09Z（pebble 该 profile 钉死 900 秒）
守护进程（-interval 30s，真实时钟，没人改状态、没人改时钟）：
  "ARI window refreshed" start=08:37:10Z end=08:52:09Z retryAfter=6h0m0s
  每轮 "not yet due for renewal" renewAt=2026-09-18T08:46:08.836Z —— 一直等到这个时刻
  "starting renewal" renewAt=2026-09-18T08:46:08.836Z ariReplaces=true      （签发后 536 秒）
  "ACME order created" status=pending … replacesRequested=true
  "certificate issued and recorded locally" notAfter=2026-09-18T09:01:08.000Z
pebble 侧："ARI: order "GPKy…" is a replacement of "UxHM…""；权威侧 3 次 TCP TXT 查询
关停：SIGTERM → "daemon exited after SIGTERM (exit=0)"
状态库前后（第三个快照对照过的轮次）：not_after 09:18:30 → 09:26:33、ari_cert_id 的序列号部分
  由 …H87DwFTMN6g 变为 …YezV8r2Nw6c；期间只有 cp、grep 轮询、守护进程自己的写入与 kill -TERM
```

三个让它站得住的细节：**签发时 `renewBefore=1h` 已经过期**（回退阈值在签发那一刻就是过去时，回退逻辑第一轮就会续期），所以这次续期的时点**只能由 CA 给的 ARI 窗口决定**；守护进程报出的 `renewAt` 与**独立重实现的 `internal/acme/ari.go RenewalTime`** 逐位一致（`2026-09-18T08:46:08.836Z`）；pebble 自己确认了"这是一次 replacement"。

顺带两条真实观察：**CA 的 authz 复用真的会发生**（三轮里有一轮 pebble 直接说 `Order … is fully authorized`，那一轮续期没有写任何 TXT —— 与生产续期观察到的现象一致），以及短有效期证书每轮都会打 `certificate approaching expiry … daysLeft=1`（正确行为，不是缺陷）。

**这条的边界**：续期实验里的 DNS 层是**桩**（容器内自建权威服务器 + lego 的 `httpreq` provider），因为容器里没有公网域名；不被打桩的是**续期时点本身** —— 真实守护进程、真实 ARI 客户端、真实 15 分钟 CA 有效期、真实墙钟。

顺带一条环境观察：容器里跑第一次 `make e2e` 时编译失败（`cleanup_test.go:450:11: undefined: bytes`），原因是**我本人正在同时编辑那棵树**（那次提交把 `bytes` 的 import 补上之前的一瞬间被拷走），不是仓库缺陷；重新拷贝后一次通过。

---

## 7. 精度说明

- **"验证过"的标准**：本文件里每一条"已证实"都配了可复现的命令与原始输出（长日志在 `/tmp/wv-verify/`、`/tmp/wcert-verify/`、`/tmp/drill/`、`/tmp/verify-*.json`）；凭"读代码觉得对"的一律不算。
- **注入式验证的边界**：fsync/rename EIO 是**系统调用级注入**，不是真实断电；SIGKILL 是进程级杀灭，不是掉电。两者覆盖了产品代码里所有"持久化调用失败"的分支，但不覆盖文件系统自身的原子性保证。
- **这一轮改动了产品代码**（8 条缺陷 + 2 处措辞），全部走完整门禁：`gofmt`、`go vet`（两套 tag）、`staticcheck`、`check-english`、`check-alerts`、`check-cam-policies`、`go test -race`（20/20 包）。
- **顺带补跑的门禁**：`make fuzz`（4 个目标 × 20 秒）也跑了一遍 —— 其中 `FuzzParseRetryAfter` 单个目标 20 秒内执行 **833 万次**、无新失败、语料仍 26 条；这条门禁 CI 里没有，属于"谁推谁跑"的那一类。
- **仍然没有验证的"人对人的东西"**：`docs/staging-checklist.md` 的第 1 节（控制台里手工绑定）与第 3 节（CAM 策略在真实子账号上的最小性）需要一个人坐在控制台前，这一轮没有替代方案。
