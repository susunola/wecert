# wecert 测试计划

> 基线：`c6d6a51`（v0.4.2）。本文所有数字都是**实测值**，不是估计值。
>
> 配套文档，各管一层，不要互相替代：
>
> | 文档 | 管什么 |
> |---|---|
> | 本文 | 分层策略、覆盖基线、缺口优先级、发布判据 |
> | [`docs/lifecycle-acceptance.md`](lifecycle-acceptance.md) | 端到端验收用例 TC-LIFECYCLE-01（Part A 生命周期 A0–A9 / Part B 声明层 B0–B5b） |
> | [`testenv/README.md`](../testenv/README.md) | 部署侧 Stage A / B / B2 / B3 / C，含真实 CLB 与 SNI |

---

## 1. 为什么这个项目的测试重点不是"功能覆盖"

先看清楚失效的代价分布，测试资源才知道往哪放。

| 失效形态 | 后果 | 可恢复性 |
|---|---|---|
| 状态库被丢/被重建 | 重新下单，撞 **5 certificates per exact set of identifiers / 7 天**（无 override） | **不可恢复**，只能等 |
| 授权验证失败重试过多 | 撞 **5 authorization failures per identifier / 小时** | 不可恢复，只能等 |
| 域名集合与配置不一致但没重签 | 某个域名**静默失去覆盖**，直到下一个续期窗口 | 可恢复但发现得很晚 |
| DNS 里留下垃圾 TXT | 记录配额被慢性占满 | 可恢复，需人工翻后台 |
| 云端上传证书漏成孤儿 | 撞账号上传证书配额，最终**无法续期** | 可恢复，需人工删 |
| 部署失败但指标显示已部署 | 到期告警**沉默**，证书真的过期 | 后果最重 |

所以测试投资的第一优先级是：**状态持久化、限额相关行为、覆盖范围正确性、"告警本身是否可信"**。功能分支的常规覆盖反而排在后面 —— 这也是为什么下面的 P0 里有两条是给**验证工具本身**加测试（`wecert-probe`、`tatrun`）。

---

## 2. 测试层级

| 层级 | 目标 | 现有资产 | 运行位置 | 频率 |
|---|---|---|---|---|
| **L0 静态门禁** | 格式、静态错误、已知 CVE、英文源码、图表不过期 | `gofmt`、`go vet`、`govulncheck`、`scripts/check-english.py`、`scripts/check-diagram-fit.py` | CI | 每次 push / PR |
| **L1 单元** | 纯逻辑：集合运算、状态迁移、解析、退避 | 76 个测试文件、787 个测试函数（`go test ./... -list 'Test.*' \| grep -c '^Test'`） | CI（`-race`） | 每次 push / PR |
| **L2 集成（注入替身）** | 跨组件编排：订单状态机、DNS 传播、清理、收敛循环 | 注入式 exchange 函数、假状态库、`httptest` | CI | 每次 push / PR |
| **L2.5 真实 DNS-01 端到端（本地，无需云凭证）** | 真 ACME 服务端 + 真权威 DNS（53 端口）+ 真 solver 写记录 + 真传播检查回读 + 真签发 | `internal/acme/e2e_dns_test.go`、`make e2e`、[实跑报告](e2e-run-2026-09-17.html) | 本地 / CI（Linux 需 `CAP_NET_BIND_SERVICE`） | 改动触及签发、DNS 或状态机时 |
| **L3 端到端（staging）** | 真实 ACME + 真实 DNSPod 的全流程 | `docs/lifecycle-acceptance.md`、`scripts/e2e-test.sh` | 本地，人工 | 发版前 / 改动触及状态机时 |
| **L3 端到端（staging，自动化）** | 同上，但由 `wecert-onboard` 驱动声明、`wecert-probe` 独立佐证 | `scripts/e2e.sh` 输出的 [实跑报告](e2e-run-2026-09-17.html) | 本地，人工 | 同上 |
| **L4 部署验收** | 真实 CLB 绑定、SNI、TLS 实际握手、CVM 角色 | `testenv/`（Terraform）、`scripts/run-stage-ab.sh`、`scripts/validate-cloudinit.py` | 腾讯云测试账号，人工 | 发版前 / 改动触及部署时 |
| **L5 线上巡检** | 生产上"证书真的在服务" | `wecert-probe`、`tatrun`、Prometheus 指标 | 生产 | 持续 |

**L3/L4 是人工的，这不是偷懒，是结构性的** —— 见第 6 节。

**L2.5 是这一层里唯一"真到 DNS 线路上"的自动化层级**：它用一个真实的权威 DNS 服务器（0.0.0.0:53）、pebble 的真实校验、以及生产同一条 solver→传播检查代码路径，把"记录真的写进去了、真的能读回来、CA 真的签了"三件事分开断言。它不需要任何云凭证，所以能进 CI；跑不了的部分（云部署、staging）在报告里逐条列出并给出命令，而不是当作通过。

2026-09-17 追加两个用例，把"配置真的生效"和"续期真的自动"也放进这一层：

- `tlsserver-profile-issuance`：profile 名必须逐字出现在 new-order 请求里（记录请求本身，而不是只看有效期——pebble 对没带 profile 的订单**随机**挑一个，只看 45 天会三次里漏掉一次），并且签回来的证书有效期必须真是该 profile 的 3888000 秒，而不是 classic 的 90 天。
- `automatic-renewal-of-a-tlsserver-certificate`：先把管理器时钟拨到 CA 自己的 ARI 窗口所蕴含的那个确定时刻（`RenewalTime`），再一次 `Reconcile` 完成整轮续期——换发、挑战记录的写入与清理、订单携带 `replaces`。用例把 `renewBefore` 设成 24h：本地回退时刻因此落在 notAfter-24h（再加抖动），而 CA 窗口的末端是 notAfter-(有效期/3)+24h，对这个 profile 就是 notAfter-14d，两者至少相差 13 天，这样"续期发生在这个时刻"只可能由 CA 的窗口解释，而不是本地规则恰好也到期了；这个前提在用例里是断言，不是假设。

为了让第二条可判定，pebble 现在用 `PEBBLE_AUTHZREUSE=0` 启动：CA 沿用仍然有效的授权（RFC 8555 §7.5.2）会让订单直接 ready，整条 DNS-01 路径被跳过——而那正是这一层要跑的东西。用例仍然按 CA 实际返回的授权状态逐名断言（0 是"每次都新授权"，但 pebble 的掷骰是 `rand.Intn(100) > percent`，仍有百分之一的沿用概率）。

---

## 3. 覆盖基线（实测）

### 3.1 总量

| 指标 | 值 |
|---|---|
| Go 文件 / 代码行 | 83 / 26,116 |
| 测试文件 / 用例 | 39 / 384 |
| **总覆盖率** | **61.0%** |

### 3.2 分包含率

| 包 | 覆盖率 | 说明 |
|---|---|---|
| `internal/metrics` | 100.0% | |
| `internal/group` | 94.9% | 声明 → 证书分组 |
| `internal/config` | 89.7% | |
| `internal/reconcile` | 88.3% | |
| `internal/probe` | 83.3% | 网络侧"证书真的在服务" |
| `internal/webhook` | 80.3% | |
| `internal/state` | 77.4% | 持久化 |
| `internal/acme` | 67.9% | 状态机（核心） |
| `internal/spec` | 67.6% | 期望状态契约 |
| `internal/onboarding` | 63.1% | 声明推断 |
| `internal/deploy` | 62.0% | |
| `cmd/wecert-onboard` | 56.0% | |
| `cmd/preflight` | 12.4% | |
| `cmd/clbverify` | 3.2% | |
| `cmd/wecert` | 1.7% | |
| `cmd/wecert-probe` | **0.0%** | ❌ 无测试文件 |
| `cmd/tatrun` | **0.0%** | ❌ 无测试文件 |

### 3.3 零覆盖要分三类看，别一概当缺口

把零覆盖清单直接当 todo 会浪费大量精力，因为其中一类**本来就不该被覆盖**。

| 类别 | 例子 | 该不该追 |
|---|---|---|
| **A. 接缝（不该追）** | `internal/acme/api.go` 的 `coreAPI` 全部方法、`LazyTencentCLB` 的 `Deploy`/`Delete`/`Bindings` | ❌ **不追**。它们是一行转发：`return c.core.Orders.UpdateForCSR(...)`。存在的意义是**让替身可注入**，而正因为它们存在，`internal/acme` 才有 67.9% —— 逻辑在替身那一侧被测了，适配器本身只在真实 lego 上运行。为它们写测试只能测出"我调用了我自己" |
| **B. 真实缺口** | `internal/onboarding/tencent.go` 的 11 个函数、`Noop` 的三个方法 | ✅ **追**。见 P1-1、P1-2 |
| **C. 顶层编排** | `dns.go` 的 `WaitAll`/`waitZone`、`client.go` 的 `EnsureAccount` | ✅ 追，接缝已存在（见 P1-3） |

对照参考：**已经打满的可注入内层**（说明测试架构是健康的）：

| 位置 | 已覆盖 |
|---|---|
| `dns.go` | `probeRecords`、`probeRecordsWithExchange`、`probeTXTWithExchange`、`authoritativeExchange`、`newTXTLeases`、`lock`、`add` — 均 100% |
| `deploy/tencent.go` 核心 | `updateInstance` **96.2%**、`waitDeployRecord` **95.2%**、`describeDeployRecord` **90.9%**、`progressBoundCount` 100%、`resourceTypeRegions` 100% |
| `ari.go` | `CertID`、`RenewalTime`、`DeterministicTime` — 均 100% |

> `describeDeployRecord` 那 90.9% 覆盖的是本项目最微妙的一处：SDK 把每个 `TotalCount` 暴露成指针，**任务在服务端被 instrumented 之前它们是 null**。若把 null 解引用成 0，就会被 `progressBoundCount` 当成"没有任何资源绑定"这个**真实结论** —— 于是一次成功的更新被误判成失败。这一段已覆盖，说明"断言请求/响应形状"这条路是走得通的（P1-1 就按同样思路做）。

---

## 4. 缺口与优先级

### P0 — 不补就等于把"假绿灯"留在系统里

#### P0-1 · `cmd/wecert-probe` 零测试

**现象**：0 个用例、0.0% 覆盖。而它是**唯一**能发现"云 API 说绑好了、但实际服务出去的还是旧证书"的工具 —— 也就是 README 里点名的那个盲区，`internal/probe` 那 83.3% 覆盖的是它的库，**命令行入口没人测**。

**失败后果**：这个工具的整个价值是"不信控制面、只信实际握手"。它自己出错（SNI 没传对、读错了证书链里的一张、hostname 不匹配仍判通过、过期判断算错）就会**在最需要它的那一刻给出假绿灯** —— 告警本身失效，比没有告警更糟。

**怎么补**：用 `httptest.NewTLSServer` 起本地 TLS 桩，断言判定与退出码：

| 用例 | 期望 |
|---|---|
| 证书正常且在有效期内 | 通过，退出码 0 |
| 已过期 | 失败，退出码 ≠ 0 |
| `-min-valid` 大于剩余有效期 | 失败，退出码 ≠ 0 |
| 服务端返回的证书 SAN 不含 `-host` | 失败（**这条最容易漏**：只校验了"能握手"，没校验"是我要的那张"） |
| 需要 SNI 才拿到正确证书的桩 | 传对 `ServerName` 才通过 |
| 桩只提供链、叶子在链中位置不同 | 仍能正确取到叶子 |
| 连不上 / 超时 | 失败且信息可读，不能 panic |

**判据**：`go test ./cmd/wecert-probe/` 覆盖 ≥ 70%，且上面每条都有对应用例。

#### P0-2 · `cmd/tatrun` 零测试

**现象**：0 个用例、0.0%。作用是**在 CVM 上执行命令并回传输出**（不需要 SSH、不需要开公网入站），最典型的用途是从 VPC 内 curl CLB VIP 读回真实服务的证书。

**失败后果**：它是"取证工具"。如果远端命令失败了它却返回 0、或者输出被截断而没提示，那么"我在机器上验过了"这句话就是空的 —— 而它恰恰是用来推翻控制面结论的最后一道证据。

**怎么补**：把远端执行抽成可注入接口（如果还没抽），然后断言：

| 用例 | 期望 |
|---|---|
| 远端命令退出码非 0 | **必须冒泡为非 0**（不能只看 stdout） |
| 远端命令无输出但有错误 | 报错而不是"空结果=成功" |
| 输出超过上限 | 截断且有明确标记（不能悄悄丢） |
| 远端超时 | 报超时，且不挂死 |
| 正常输出 | 原样回传，不改写换行 |

**判据**：`go test ./cmd/tatrun/` 覆盖 ≥ 60%，"非 0 退出码必须冒泡"有用例。

#### P0-3 · CI 没有覆盖率下限

**现象**：`make cover` 只打印数字，CI 不设阈值。当前 61.0% 是**自发达成的**，不是被守住的 —— 下一次重构可以直接掉到 40% 而全绿。

**失败后果**：慢性的、无人察觉的测试腐化。半年后想加门槛时，面对的是一堆"历史遗留未覆盖"而不是"新增未覆盖"。

**怎么补**：CI 加一步（阈值取略低于当前值，之后只升不降）：

```bash
go test -coverprofile=cover.out ./...
total=$(go tool cover -func=cover.out | tail -1 | awk '{print $3}' | tr -d '%')
awk -v t="$total" 'BEGIN{ if (t+0 < 60.0) { print "coverage regressed: "t"% < 60%"; exit 1 } }'
```

同时对 `internal/` 里已 ≥ 60% 的包逐包设下限，防止"总量达标靠一个高覆盖包撑着"。

**判据**：故意删一个测试，CI 必须红。

#### P0-4 · 本地门禁 ≠ CI 门禁

**现象**：

```
make check   = check-english fmt-check vet test-race          （4 项）
CI 实际跑     = gofmt + check-english + vet + govulncheck
               + test -race + build + cross build             （7 项）
```

`govulncheck`、`make build`、`make release`（交叉编译）**只在 CI 跑**。本地全绿不等于 CI 会绿 —— 这正是历史上"改完提交才发现构建不过"的成因。

**怎么补**：让 `make check` 成为 CI 的超集（至少加 `build` 与 `release`；`govulncheck` 可选，因为它要联网拉漏洞库）。

**判据**：`make check` 通过 ⟹ CI 通过（对同一工作树）。

---

### P1 — 覆盖"系统的目的"，成本可控

#### P1-1 · `internal/onboarding/tencent.go` 的发现层 11 个函数全零覆盖

**现象**：`TencentSources`、`NewDNSPodDeclarations`、`client`、`ListDeclarations`、`listZones`、`listTXTRecords`、`joinRecordName`、`NewCLBRules`、`ListRuleDomains`、`listLoadBalancers`、`listRuleDomainsFor` —— 全部 0.0%。这是**"域名从哪来"的那一半**：从 DNS 读 `_wecert` 声明、从 CLB 监听器反推规则。

**为什么这是云侧最该先补的地方**（而不是 `deploy/`）：`deploy/` 的核心逻辑已经是 90% 以上；而发现层**一个函数都没测**。它错了不会报错，只会**推出一份错误的域名集合** —— 表现是某一整批域名静默失去覆盖，直到证书过期才被发现。这正是第 1 节里"发现得很晚"那一行的来源。

**请重点看这几个**（其余多为薄封装）：

| 函数 | 错了会怎样 |
|---|---|
| `joinRecordName` | 记录名拼接错 → 认不出声明，或把别的 TXT 当成声明 |
| `listTXTRecords` | 漏读/误读 TXT → 声明集合不完整 |
| `ListRuleDomains` / `listRuleDomainsFor` | CLB 规则里的域名解析错 → 期望状态少一批域名 |
| `listZones` | 漏 zone → 某些注册域下的声明**完全看不见** |

**怎么补**：与 P1-1（D）同样的手法 —— 腾讯云 SDK 的 endpoint 可覆盖（`profile.HttpProfile.Endpoint`）。把它指向 `httptest.Server`，用真实响应样本（含分页、含奇怪的记录值、含大小写与尾点差异）驱动，不需要云账号、不产生费用。

**判据**：`internal/onboarding` 里 `tencent.go` 的覆盖从 0% 起；`joinRecordName` 与 `listZones` 必须有边界用例（空 zone 列表、zone 名带尾点、多 zone 分页）。包整体覆盖 ≥ 75%。

#### P1-2 · `Noop` 的三个方法零覆盖，而其中一条是被明确设计过的行为

**现象**：`internal/deploy/deployer.go` 的 `Noop.Deploy` / `Noop.Delete` / `Noop.Bindings` 均 0.0%。

**为什么值得单独提**：这不是"转发代码"。`Noop.Delete` **刻意返回 `ErrDeploymentDisabled` 而不是 nil**，源码注释写明了理由 —— *返回 nil 会让回收器以为删掉了、从而忘掉队列项，而云证书其实还在，于是永久泄漏*。这是一个**有明确设计意图、错了就慢性泄漏**的行为，却没有任何单元测试看着它。

而且它的触发面很宽：`deploy.enabled: false` 时用的就是 `Noop` —— **验收用例 TC-LIFECYCLE-01 全程都是这个模式**，也就是说这条路径只有人工验收在跑，单元层完全空白。

**怎么补**（不需要网络，成本极低）：

| 用例 | 期望 |
|---|---|
| `Noop.Deploy` | 原样返回 `oldID`，不报错 |
| `Noop.Delete("")` | 返回 nil（空 ID 无事可做） |
| `Noop.Delete("<certID>")` | **必须返回 `ErrDeploymentDisabled`，不能是 nil**（回归用） |
| `Noop.Bindings` | 返回 0 且不报错 |

**判据**：`internal/deploy` 里 `Noop` 的覆盖 100%；`Noop.Delete` 的返回值断言必须存在。

#### P1-3 · `WaitAll` / `waitZone` 的顶层编排未覆盖

**现象**：`probeRecords`（并发探测）100% 覆盖，但 `WaitAll` 与 `waitZone` 是 0.0% —— 也就是**按 zone 分组、共享 deadline、多记录并发、超时报错内容**这段编排没人测。

**为什么重要**：这一段正是"多 SAN 时传播等待是否会退化"的关键，历史上出过"报错摘要张冠李戴"和"deadline 共享导致后面的 zone 白报"两个问题。

**怎么补**：注入 exchange 函数（接缝已存在），断言：zone 分组去重、同一个 deadline 被所有 zone 共享、超时信息包含**真实已等待时长**且只列**未就绪**的记录、并发上限生效。

#### P1-4 · `failureFallback` 无测试

**现象**：验收文档第 7 节自己写明"需要某些 identifier 持续失败 + 临近过期才能触发，本用例不构造；默认关闭，且属于**会改变证书覆盖范围的安全决策**"。

**问题**：一个"会改变覆盖范围"的安全相关分支，既没有测试、也不是默认开启 —— 那么它要么被补上测试，要么被删掉。留在中间状态的风险是：某天有人打开它，没有任何行为契约可依。

**建议**：用假 ACME 构造"部分 identifier 持续失败 + 临近过期"，断言拆分后的子集**只覆盖仍在服务的那部分域名**、且不会因为拆分而丢掉本可覆盖的域名。或者明确标记为实验性并从发布物中移除。

#### P1-5 · `internal/spec` 的解析/观察/文件加载零覆盖

**现象**：`static.go`、`spec.go`、`observe.go`、`file.go` 里的 10 个函数 0.0%（包整体 67.6%）。这是 Part B 那一半的输入契约。

**为什么重要**：声明层决定了"哪些域名应该有证书"。解析出错或 `observe` 判断错，表现就是**某批域名静默失去覆盖** —— 而它不报错。

#### P1-6 · `onboarding` 的变更速率限制与凭证源

**现象**：`onboarding/onboard.go` 的 `overLimit` 0.0%、`sameBoolPtr` 0.0%；`deploy/credentials.go` 的 `NewCredentialSource` 0.0%。`fetchCVMRoleCredential` 已有 85.7%，说明凭证侧接缝存在。

**为什么提**：`overLimit` 是变更速率限制器 —— 属于**安全闸**（Part B 的熔断就靠它）。安全闸没有测试，等于"默认它是对的"。

---

#### P1-7 · 把最小 PASS 判据脚本化

验收用例末尾的 8 条判据（`orders=0`、`ACME order created` 出现 0 次、中断态下同名 2 行授权、`resuming the existing order`、并发两张都成功、`replaces=true`、`reclaiming it before deleting the row`、A4b 零重叠仍能签发）目前是**人工判读 SQL 与日志**。这些恰恰是回归最该自动化的部分。

**建议**：固化成 `scripts/acceptance-check.sh`，输入状态库 + 日志目录，逐条断言并给出 PASS/FAIL 清单。人工只负责制造场景，不负责判读。

### P2 — 常规补强

| 项 | 现象 | 建议 |
|---|---|---|
| P2-1 | `cmd/preflight` 12.4% | NS 委派判定与 `-prune-certs` 的确认门禁是真实逻辑，值得覆盖 |
| P2-2 | 测试不分层（无 `-short`、无 build tag） | 384 个用例还没到瓶颈，但 L2 集成用例继续增长后需要 `-short` 快车道 |
| P2-3 | 只有 `govulncheck`，无 lint | 加 `staticcheck`；`make vet` 抓不到未使用变量以外的多数问题 |
| P2-4 | 验收用例的 8 条最小判据靠人工解读 | 见 P1-7 |
| P2-5 | `docs/lifecycle-acceptance.md` 末尾写"这是 **7** 条"，实际列了 **8** 条 | 文档笔误，顺手修 |

---

## 5. 分层结论：缺的不是"更多测试"，而是三处特定位置

```
内部可注入层     ████████████████████  已打满（probeRecords / newTXTLeases / CertID / updateInstance 96% …）

验证工具本身     ░░░░░░░░░░░░░░░░░░░░  ← 两个二进制 0%           P0-1 / P0-2
发布门禁         ░░░░░░░░░░░░░░░░░░░░  ← 无覆盖率下限、make check ≠ CI  P0-3 / P0-4

声明发现层       ░░░░░░░░░░░░░░░░░░░░  ← onboarding/tencent.go 11 个函数 0%   P1-1
Noop 语义        ░░░░░░░░░░░░░░░░░░░░  ← deploy.enabled=false 时全靠它        P1-2
顶层编排         ████░░░░░░░░░░░░░░░░  ← WaitAll / waitZone / EnsureAccount    P1-3
spec / 熔断      ██████░░░░░░░░░░░░░░  ← 解析、observe、overLimit             P1-5 / P1-6

适配器接缝       ░░░░░░░░░░░░░░░░░░░░  ← coreAPI / LazyTencentCLB：不必追（见 3.3）
真实部署         ────────────────────  ← 结构性只能人工（见第 6 节）
```

**两处结论**：

1. **先补最上面两块（验证工具与发布门禁）。** 验证工具自己没测试，等于"证书是否真的在服务"这套判断没有立足点；而门禁缺位会让补上的东西在下一次重构里悄悄退回去。
2. **云侧不必大动。** 核实发现 `deploy/` 的核心逻辑已经 90%+（`updateInstance` 96.2%、`waitDeployRecord` 95.2%、`describeDeployRecord` 90.9%），真正空着的是**声明发现层**（`onboarding/tencent.go`）—— 而它错了表现为"整批域名静默失去覆盖"，比部署失败更难发现。

---

## 6. 必须留在人工的测试，及原因

这不是"懒得自动化"，是**结构上做不到**：

| 事项 | 为什么不能自动化 |
|---|---|
| CLB 开启 SNI 后静默忽略主证书 | 这是**服务端的行为**，且不报错。只有真跑一次、从 CLB API 独立取证才能发现。假服务端只会按我们的想象回应，测不到"它其实忽略了" |
| `UpdateCertificateInstance` 的重绑定 | 异步（实测约 15s），且**不是原子的**。断言必须等真实状态切换 |
| 真实 TLS 握手 / SNI 选到哪张证书 | 需要真实 CLB + 真实后端；另一张证书可能赢得 SNI，控制面看不到 |
| DNSPod 免费套餐 TTL 下限 600、9 台权威 NS 的传播时间（实测 78s） | 是外部服务的**真实约束与真实延迟**，桩掉就等于把被测对象换掉了 |
| 限速与配额的真实行为 | 只有在真实 CA 上才会体现；在 CI 里跑会消耗真实配额 |
| 时间跨度（ARI 窗口、宽限期、退避） | 验收用例用改状态库触发，不改系统时钟 —— 改时钟会同时影响 TLS、日志与 `Retry-After` |
| CVM 角色临时凭证 | 需要实例元数据服务，只有真 CVM 上有 |

**约定**：L3/L4 的人工结果必须留痕。现有做法是 `docs/lifecycle-acceptance-run-*.html`，这个约定保持。

---

## 7. 环境、数据与隔离

| 环境 | 用途 | 约束 |
|---|---|---|
| 本地 | L1/L2 | 不需要网络；测试用临时状态库 |
| **Let's Encrypt staging** | L3 | 配置必须指向 staging，`scripts/e2e-test.sh` 会强制检查；**用专用测试域名** |
| 腾讯云测试账号 | L4 | `testenv/` Terraform 自建 VPC/CLB/CVM；**不要用生产账号** |
| 生产 | L5 | 只读观测（`wecert-probe` / 指标），不做破坏性操作 |

**硬性隔离要求**：

1. **测试域名与客户域名分离。** 任何 e2e/验收都不许指向正在为客户服务的域名 —— L3 会在 DNS 上真实增删 TXT 记录。
2. **状态库隔离。** 每次验收用全新状态库（验收文档 P5 已要求"干净基线"）。共用状态库会让"未在窗口内开单"这类断言失去意义。
3. **配额意识。** L3 每次执行都会消耗真实的 CA 限额。验收用例把 `deploy.enabled: false` 全程打开是对的（不上传云证书，不烧上传配额）—— 保持这条。
4. **凭据最小化。** 本地跑 L3 用 `TENCENTCLOUD_SECRET_ID/KEY` 环境变量，不写进配置文件；能用 CVM 角色就不要用静态密钥。

---

## 8. 发布门禁

### 每个版本发布前，必须满足

- [ ] **L0–L2 全绿**，且 `make check` 已包含 CI 的全部检查（P0-4）
- [ ] **覆盖率不低于上一版本**（P0-3 落地后自动校验）
- [ ] **`CHANGELOG.md` 已更新**，且 `Tests` 段落如实反映新增测试
- [ ] 改动触及**订单状态机 / DNS 挑战 / 清理** → 必须跑 **L3 的 8 条最小 PASS 判据**
- [ ] 改动触及**部署 / CLB / SNI** → 必须跑 **L4 Stage B 或 B2**
- [ ] 改动触及**声明层 / desired state** → 必须跑 **Part B（至少 B4 + B5a）**
- [ ] 若本次修的是"绿灯下的慢性病"（配额泄漏、DNS 垃圾、覆盖丢失）→ 回归测试必须包含**已被验证过会失败的用例**

### 不需要跑全量验收的情形

只改文档、注释、图表、README 时。`make check` 绿即可。

---

## 9. 执行顺序建议

| 阶段 | 内容 | 为什么是这个顺序 |
|---|---|---|
| **第 1 步** | P0-1、P0-2：给 `wecert-probe` 与 `tatrun` 加测试 | 成本最低、价值最高：让"验证证书真的在服务"这件事本身可信。两个都是命令行工具，用本地 TLS 桩与注入接口即可，不需要云资源 |
| **第 2 步** | P0-3、P0-4：覆盖率下限 + `make check` 对齐 CI | 把已有成果锁住，同时消除"本地绿 CI 红"。这一步必须在前两步**之后马上做**，否则前面的补强没有护栏 |
| **第 3 步** | P1-1：`onboarding/tencent.go` 发现层 | 云侧唯一真正空着的一块，且错了会导致整批域名静默失去覆盖；`httptest` 可覆盖，不需要云账号 |
| **第 4 步** | P1-2：`Noop` 的三个方法 | 几行断言的事，但 `deploy.enabled: false` 是验收用例的常态，单元层却是空白 |
| **第 5 步** | P1-3、P1-7：`WaitAll` 编排 + 最小判据脚本化 | 把验收里最该自动化的部分固化下来，减少人工判读 |
| **第 6 步** | P1-4、P1-5、P1-6：`failureFallback`、`spec`、熔断 | 消除"安全相关分支无契约"与"覆盖范围静默丢失" |
| **第 7 步** | P2-* | 常规补强 |

---

## 10. 明确不做，及理由

| 不做 | 理由 |
|---|---|
| 在 CI 里跑真实 staging 签发 | 消耗真实 CA 配额，且依赖外部 DNS 传播时间 → 必然 flaky。flaky 的 CI 比没有 CI 更糟（会训练人忽略红色） |
| 在 CI 里跑 pebble/假 ACME 覆盖完整签发 | 值得考虑，但**优先级低于 P0/P1**：`internal/acme` 已 67.9%，缺的那段是 lego 薄封装；用 httptest 断言请求形状（P1-1）性价比更高。若要上，独立评估 |
| 自动化 CLB 绑定与 SNI 断言 | 需要真实云资源常驻 + 15s 异步等待，成本高于收益；已有 `testenv/` 人工阶段且留痕 |
| 时钟穿越测试 | 会同时影响 TLS、日志与 `Retry-After`，改状态库触发是更干净的手段（验收文档已说明） |
| 追求行覆盖率数字 | 本项目的失效形态是"语义正确但行为错"（比如集合比较漏了删域名方向），行覆盖率抓不到。第 4 节的每条都以**行为判据**收尾，而不是"覆盖到就行" |

---

## 附：命令速查

```bash
# L0–L2：本地门禁（注意：目前仍少于 CI，见 P0-4）
make check             # check-english + fmt-check + vet + test-race
make test              # 单元测试
make test-race         # 带竞态检测（多 SAN 时 DNS 探测与授权轮询并发）
make cover             # 覆盖率

# L3：端到端（真实 staging + 真实 DNSPod，人工）
make build tools
cp e2e-config.example.yaml e2e-config.yaml      # 填 token 与测试域名
./scripts/e2e-test.sh <测试域名> ./e2e-config.yaml

# L4：部署验收（真实云资源，人工）
./scripts/run-stage-ab.sh <域名> <邮箱>          # 默认只 plan
./scripts/run-stage-ab.sh <域名> <邮箱> --yes    # 真正创建资源
make validate-cloudinit                          # cloud-init 本地校验

# 其它门禁
make check-english     # 源码里不许有中文（.md 除外）
make diagrams-check    # 图表是否过期/溢出
```

---

## 变更记录

| 日期 | 变更 |
|---|---|
| 2026-09-16 | 首版。基线 `c6d6a51` / v0.4.2：总覆盖率 61.0%，384 个用例，识别出 4 个 P0 缺口 |
