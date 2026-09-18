# 未验证项的实测核查（2026-09-18）

前十一轮 review 的每一份报告末尾都有一节「仍然未验证」。这份文件把那些条目**逐条拿去实测**：能在这里验的给出证据，验出来的缺陷修掉并留下会变红的用例，验不了的写清楚卡在哪里 —— 而不是继续写着"未验证"。

配套阅读：第十一轮报告 [code-review-round11-2026-09-18.md](code-review-round11-2026-09-18.md)（三个视角与 29 条修复）、带凭据云上报告 [e2e-run-2026-09-18-credentialed.md](e2e-run-2026-09-18-credentialed.md)。

---

## 0. 一句话结论

**101 条"未验证"里，69 条本机可验**：这一轮把其中最有分量的一批真跑了 —— 真实 Let's Encrypt **生产**签发与 ARI 驱动的续期、真实 DNSPod 的记录名形态、真实端点的探针三态、Linux 容器里的 `install.sh` 全流程与 145 次 SIGKILL 崩溃安全、完整恢复演练、老二进制读新 schema —— 并且**实测又找出 8 个缺陷**（全部已修、全部有会变红的用例）。剩下 13 条本机做不到、7 条**本质上无法验证**（例如"真实断电"和"90 天自然到期"），逐条写在 §4。

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

## 3. 实测发现的缺陷（8 条，全部已修 + 会变红的用例）

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
- **`IsCheckResource=true` 的真实删除拒绝（状态 4）+ 真实换绑 + SNI 多证书**（U8/U41/U43/U98）：需要一台真实 CLB 与一张绑定中的证书。这一轮交给独立的云上子任务执行（见 §5 的结果），本报告不预判。
- **`wecert-preflight -prune-certs` 非交互 stdin 视为 no**（U90）：**故意不跑** —— 共享账号里它一旦行为不符会删掉别人正在服务的证书。要验只能在一次性账号上。
- **CAM 策略的"最小且充分"在真实账号上生效**（U42）：静态检查（`check-cam-policies.py`，10 个 API 全覆盖）已通过；"用这套策略真的能跑通、且多一个 API 会被拒"需要在子账号上挂策略实测。
- **`e2e-sni.sh` 的全流程**（U98）：同上，要真实 CLB + SNI 监听。
- **真机 systemd 启动 unit**（U45 的最后一米）：容器里只做了 `systemd-analyze verify`，没有让 systemd 真正拉起服务。
- **`run-stage-ab.sh` 全流程**（U101）：需要 terraform apply 出一台 CLB/CVM；脚本的 plan-only 分支与校验逻辑已在静态检查里覆盖。
- **多注册域 / 第二个 zone**（U49）：账号里只有一个可写 zone（`atomwangnus.com`），跨域配额行为无法实测。
- **负载与浸泡**（U47）：需要长时间高并发与真实 DNS/CA 压力；这一轮只做了合成规模的单轮测量（第十一轮规模视角）。
- **`-once` 与 webhook 同机并发的真实竞态频率**（U12）：需要长时间真实流量才能给出频率，代码路径本身有单测。
- **DNSPod 控制台对"主机记录里带 zone"的行为**（U10 的残留问题）：无控制台访问权限，只证明了 API 侧行为。
- **本地 pebble 直连 CLI**（U85）：macOS 上 Go 不认 `SSL_CERT_FILE`，而产品没有 CA 覆盖开关；容器里可以（§5）。
- **真实 CA 侧的 DNS-01 校验**（U86/U87）：本机 53 端口被占时 `make e2e` 会 SKIP（按第十一轮语义即失败）；容器里用 `--cap-add=NET_BIND_SERVICE` 可以真跑（§5）。

---

## 5. 这一轮尚未收尾的两条（在独立的容器/云任务里执行）

- **真实 DNS-01 的 CA 侧校验 + 自然墙钟续期**：在 Linux 容器里（53 端口可用）重跑 `make e2e` 与 `make test-pebble`，并用 pebble 的短有效期 profile 让守护进程**按真实时间**等到 ARI 窗口打开后自行续期。结果记入本节。
- **真实 CLB：`IsCheckResource` 拒绝、真实换绑、`wecert-clbverify` 观察**：在真实账号里新建一台内网 CLB、上传并绑定证书、用产品自己的删除路径对比 `IsCheckResource=true/false`，最后按 ID 清理。结果记入本节。

*(这两条返回后补齐：通过 / 缺陷 / 卡点。)*

---

## 6. 精度说明

- **"验证过"的标准**：本文件里每一条"已证实"都配了可复现的命令与原始输出（长日志在 `/tmp/wv-verify/`、`/tmp/wcert-verify/`、`/tmp/drill/`、`/tmp/verify-*.json`）；凭"读代码觉得对"的一律不算。
- **注入式验证的边界**：fsync/rename EIO 是**系统调用级注入**，不是真实断电；SIGKILL 是进程级杀灭，不是掉电。两者覆盖了产品代码里所有"持久化调用失败"的分支，但不覆盖文件系统自身的原子性保证。
- **这一轮改动了产品代码**（8 条缺陷 + 2 处措辞），全部走完整门禁：`gofmt`、`go vet`（两套 tag）、`staticcheck`、`check-english`、`check-alerts`、`check-cam-policies`、`go test -race`（20/20 包）。
- **仍然没有验证的"人对人的东西"**：`docs/staging-checklist.md` 的第 1 节（控制台里手工绑定）与第 3 节（CAM 策略在真实子账号上的最小性）需要一个人坐在控制台前，这一轮没有替代方案。
