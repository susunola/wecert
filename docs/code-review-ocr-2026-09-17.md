# 用 OpenCodeReview 跑的一轮代码审查（2026-09-17）

对象：本仓库当前分支相对于 `main` 的**产品代码**改动（`internal/`、`cmd/`，共 57 个文件、约 16k 插入行）。
工具：[`alibaba/open-code-review`](https://github.com/alibaba/open-code-review)（`ocr`），本机从源码构建。

## 1. 怎么跑的（以及为什么没走它的 LLM 通道）

```bash
git clone --depth 1 https://github.com/alibaba/open-code-review /tmp/ocr-probe
cd /tmp/ocr-probe && go build -o bin/ocr ./cmd/...
bin/ocr --version           # open-code-review dev darwin/arm64
```

`ocr review` 需要一个可用的模型端点（`ocr config provider` 交互式配置 API key），本机与 `~/wbenv` 都没有任何模型凭据，因此改用它的 **delegation 模式**：`ocr` 负责**选文件**与**解析审查规则**，审查本身由宿主 agent 执行（这正是 delegation 模式的设计用途，不需要 LLM 配置）。

```bash
# 选文件（范围模式 = 分支自 merge-base 起的改动）
ocr delegate preview --from main --to HEAD --format json
#   -> reviewable 99 / total 218，其中 internal/ + cmd/ 共 57 个文件
# 解析规则（按内容分组）
ocr delegate rule internal/deploy/tencent.go internal/acme/dns.go … --format json
#   -> 1 组 **/*.go，10.8KB 的 Go 审查细则
```

`ocr` 的默认过滤把 `*_test.go`、文档、生成物排除在外（与它规则里"默认只审生产代码"一致），所以下面的发现全部落在生产文件上。

宿主侧按包分成 9 组并行审查（每组都以上面那份 10.8KB 规则为 spec），返回结构化结果。**原始输出 36 条**（blocking 2 / major 14 / minor 20）；工作流结果在落盘时被截断，其中 **21 条**完整回收并逐条复核。下表只列我**亲自回到代码里核对过**的条目，以及核对后的修正意见——工具的结论不是终点，下面是"工具说 + 我核实"。

> **状态：本轮 36 条发现中，可完整回收的 21 条已逐条核实并全部修复**（B1、B2、M1–M7、m1–m4 见下文；另外 6 条见第 3 节的更新说明）。每条都有「没有它测试就红」的用例与变异校验；提交见 `67b9e44`、`9c117e4`、`30d09b1`、`da6da84` 与最后一组 CLI/限流修复。

## 2. 核实过的发现

### 2.1 blocking（已修复）

**B1. 回收守卫拿"订单里的上传 ID"和"**旧的**已部署 ID"比较，可能把刚上线的证书排进删除队列**
`internal/acme/manager_done.go:317`（调用）/ `:544-566`（守卫）/ `:169-176`（被容忍的写入失败）

`orphanToRecord` 的判断是：

```go
liveID := ""
if st, cerr := m.store.GetCert(certName); cerr != nil { … } else if st != nil { liveID = st.DeployedCertID }
// liveID == "" errs toward reclaiming: … a certificate still bound to a listener is protected by IsCheckResource refusing the delete.
if o.DeploymentCertID == liveID { return "", nil, nil }
return o.DeploymentCertID, nil, nil
```

而它在 `:317` 被调用时，**提升还没写**（提升在 `:326` 的 `WithTx` 里）。于是 `liveID` 读到的仍是**正在被替换的那张旧证书**，而 `o.DeploymentCertID` 是**新上传的 ID**——两者不可能相等，守卫形同不存在。真正让它"通常不出事"的是 `:169` 那句 `o.DeploymentCertID = ""` 的持久化，而那段代码**故意允许它失败**（"a successful issuance must not fail because a bookkeeping write did"，只打一条 Warn）。也就是说：只要这次 `PutOrder` 失败、而随后的 `WithTx` 成功，同一个事务就会一边 `PutCert(promoted)`（`deployed_cert_id` = 新证书），一边 `AddRetiredCert(新证书)`——**把正在服务的证书写进回收清单**，等保留期过后由 `ReapRetired` 调 `Delete` 删除。当前唯一的兜底是腾讯云侧 `IsCheckResource` 会拒绝删除仍被绑定的证书，而这正是代码自己在另一处（deploy 关闭的分支）明确不愿依赖的兜底。

**已修**：`orphanToRecord(certName, promotedID)`——续期路径传入本次要提升的 ID，只有 `discardOrder`（没有提升在进行）才回退到 store 读。用例 `TestAResumedCertificateIsNotQueuedForReclaim`：把守卫改回读 store，回收清单立刻多出一条（正在服务的证书）。

**B2. 订单里 `DeploymentCertID` 的清除发生在事务之外，事务回滚时唯一记录丢失**
`internal/acme/manager_done.go:169-176`（事务外）vs `:326-363`（事务内）

```go
o.DeploymentCertID = ""
if err := m.store.PutOrder(o); err != nil { m.log.Warn("cannot persist the cleared deployment ID", …) }
…
txErr := m.store.WithTx(ctx, func(tx *state.Tx) error {
    if err := tx.PutCert(&promoted); err != nil { … }
    …
    return tx.DeleteOrder(c.Name)
})
if txErr != nil {
    return m.recordFailure(st, fmt.Errorf("the certificate was issued and deployed, but recording that in state.db failed, so it is unchanged on disk …"))
}
```

clear 先落盘，提升与删单在事务里。事务失败时（错误信息自己描述的那种情况）：`promoted` 被丢弃、没有 `AddRetiredCert`，但盘上的订单**已经不再带 `DeploymentCertID`**。那张已上传的证书于是既不在 `certificates` 也不在 `retired_certificates`——**回收机制再也看不到它**；下一轮从订单读到空 ID，会走 `Upload` 分支而不是 `ResumeDeploy`，再上传一份同样的证书（`TencentCLB.upload` 允许重复指纹），第一份泄漏。错误信息里"state 在磁盘上没有变化"这句话对 order 行并不成立。

**已修**：事务外那次 clear 已删除，改由 `tx.DeleteOrder` 连行带 ID 一起删——成功时不留陈旧值，失败时**保留**续期锚点。用例 `TestAFailedEpilogueKeepsTheOrdersResumeAnchor`：把 clear 加回去，失败事务后订单的 `DeploymentCertID` 变空，测试变红。

### 2.2 major（均已回到代码核实，已全部修复）

| # | 位置 | 问题 | 核实结论 |
|---|---|---|---|
| M1 | `internal/onboarding/tencent.go:198-206` | `DescribeRecordList` 从不设 `ErrorOnEmpty`，DNSPod 默认"查不到就报错"（`ResourceNotFound.NoDataOfRecord`） | **核实**。全仓库没有任何一处设置该字段；本会话我自己的 API dump 就两次撞到这个错误码（删完记录的 `_wecert-lagtest`、没有记录的 `_acme-challenge` 过滤查询）。后果不止"少读一页"：`onboard.go:565` 会 `r.freeze("declaration source failed: …")`，而 `:387` 对 frozen 轮次直接 `return nil`（只写报告、不写 desired-state 文档与 state 文件）——**账号里任何一个没有 TXT 记录的 zone 就足以让整个 onboarding 停止收敛**（而且 `limit=100` 的翻页在总数正好是 100 的倍数时也会请求越界页）。**已修**：两处都做了（请求字段 + 错误容忍），并让测试的假客户端**模仿真实服务端**（匹配为空即报错，除非调用方要求空列表）。用例 `TestAnEmptyZoneDoesNotFreezeTheDeclarationRead`：带一个无 TXT 的 zone 与一个正好整页的 zone；两层都去掉后测试变红。 |
| M2 | `internal/ratelimit/tracker.go:69-95`（`NoteRetryAfter` 同形 139-157） | `Spend` 是 `Get → 计算 → Put`，自身无锁；store 的锁只覆盖单条语句 | **核实**。`manager_renew.go:141-142` 在**同一个 account 级 bucket** 上花钱，而管理器按证书并发（同进程 8 路，见 `reconcile.go` 的 `maxConcurrentStarts`），因此并发丢更新 → 本地配额估计偏乐观。这个仓库自己已经为同样的模式引入过 `UpdateCert` 原子读改写，配额路径却还是"读-改-写"。**已修**：新增 `state.Store.UpdateRateBucket`（持 `s.mu` 完成读改写，与 `UpdateCert` 同形），`Spend` 与 `NoteRetryAfter` 都走它。用例 `TestConcurrentSpendsOnOneBucketAllCount`：32 个并发 spend 必须一个不少；改回 Get+Put 后会丢更新（本轮实测丢 1 个）。 |
| M3 | `internal/ratelimit/ratelimit.go:108-116` + `internal/acme/ratelimit.go:59` | `Spendable()` 列了 4 个限额，实际只有 1 个被花掉，另外 3 个指标永远等于容量 | **核实**。全仓库 `Spend(` 只有 `manager_renew.go:141` 一处，且只花 `NewOrdersPerAccount`；而 `acme/ratelimit.go:59` 会为 `Spendable()` 的每一项发布 `wecert_ratelimit_remaining_tokens`。于是 `{limit="certs-per-exact-identifier-set"}` 恒为 5，`deploy/prometheus/wecert-alerts.yml` 里 `< 5` 的告警**结构上不可能触发**——恰恰是代码注释里强调"没有任何 override 通道"的那个限额。**已修**（选择「真正记账」）：签发时花 `certs-per-exact-identifier-set`（scope 与 `publishQuota` 推导一致）与 `certs-per-registered-domain`（按证书覆盖的每个注册域各一次），授权变 invalid 时花 `authz-failures-per-identifier`（两个可能先看到的轮询点都记）。ARI 豁免的续期也会被计入，这让估计成为**下界**——正是该包承诺的「错也只往更谨慎的方向错」。用例 `TestAnIssuanceSpendsTheCertificateBudgets` 与扩展后的 `TestAwaitAuthorizationInvalidRecordsIdentifierFailure`；去掉任一 spend 都会变红。 |
| M4 | `cmd/clbverify/main.go:93-111` | 断言只看监听器级证书（`Listeners[0].Certificate`），完全不看规则级绑定 | **核实**，而且**本会话的真机运行就是证据**：这个账号强制开启 SNI、监听器级证书被静默忽略（证书只能挂在规则上），`run-stage-ab.sh` 的 pre-rebind 检查因此直接失败并报 "the listener has no certificate bound"。文件里 `Rules` 出现 0 次。危险方向更值得注意：`-not-expect <旧证书>` 会在"旧证书仍绑在真正服务该域名的规则上"时**通过**——正是这个工具存在意义所在的反向假保证。**已修**：断言集合改为「监听器级 + 每条规则的证书」，逐条打印各规则的绑定，并新增 `-domain`：只断言服务该域名的那条规则，且「没有规则服务这个域名」是**报错**而不是空集合通过。用例 `TestAssertedCertificatesIncludeRuleBindings`、`TestAssertedCertificatesForOneDomain`、`TestAssertedCertificatesWithNoListenerLevelCertificate`；只留监听器级那条后立刻变红。 |
| M5 | `internal/webhook/webhook.go:346-374` | 具名触发用**缓存**的期望状态判定 "unknown"，刚加进文档的证书永远进不了这一轮 | **核实**。`CertNames()` 读 `r.last`（只在 Prime 与每轮 pass 时由 `resolve()` 写入）；`resolveTargets` 先用它过滤请求里的名字，未命中的直接归入 `unknown` 并**传空 targets** 给 `StartNamed`——而 `StartNamed` 自己会 `r.resolve(ctx)` 拿到**更新**的列表，却因为 targets 为空而什么也不启动。这正是 README 记录的 CI 用法（"域名刚加完就用 webhook 触发收敛"）会踩的坑：调用方被告知"不在配置里"，实际是"配置里有、缓存太旧"。**已修**：`resolveTargets` 换成只做去重排序的 `requestedTargets`，分类完全交给 `StartNamed` 的新鲜解析结果。用例 `TestTriggerStartsACertificateTheCacheHasNotSeen`：缓存里没有、新解析里有 → 必须 started；把缓存预过滤加回去后，它连启动都不会发生。 |
| M6 | `internal/state/backup.go:93-98` | 快照由 SQLite 以进程 umask（通常 0644）创建，**写完之后**才 `chmod 0600` | **核实**。这段窗口里文件含 ACME 账号私钥与全部证书私钥；窗口内进程被杀则留下一个 0644 且**永远不会被清理**的 `.snapshot-*.tmp`（列目录只认 `<base>.backup-<stamp>.db`）。同包的 `state.go` 早已为同样的原因用 `restrictiveUmask()` 包住建库窗口。**已修**：`VACUUM INTO` 外面套了 `restrictiveUmask()`（`chmod` 保留为兜底），并加了一个测试缝 `snapshotCopied`，因为「复制期间的模式」在 `Snapshot` 返回后已经看不到了。用例 `TestSnapshotIsBornWithRestrictivePermissions`：去掉 umask 后，复制落地时模式是 **644**，测试变红。 |
| M7 | `cmd/wecert/revoke.go:79-84` | 无论是否真的落盘，都会打印"请求已记录，每轮会重试" | **核实**。`RequestRevocation` 在四条路径上**早于** `AddRevokeRequest` 返回（证书不存在/无材料、reason 非法、store 错误）：例如对不存在的名字执行 `-revoke`，会先打印"The request is recorded … will be retried on every pass"，而实际 `wecert_revocation_pending` 保持 0。**已修**：新增哨兵 `acme.ErrRevocationNotRecorded`，四条「什么都没写进 store」的路径都包上它；CLI 只在**不是**该哨兵时才说「已记录、每轮重试」，否则明确说「什么都没记录，不会自动重试」。用例：三个既有测试各加一条 `errors.Is` 断言，并断言「已记录但 CA 未接受」这条**不匹配**哨兵；去掉包装立刻变红。 |

### 2.3 minor（抽查核实，已全部修复）

| # | 位置 | 问题 | 核实结论 |
|---|---|---|---|
| m1 | `internal/acme/dns.go:975-978` | `queryRecursive` 把截断响应当完整答案用（`probeTXTWithExchange`/`probeRecursive` 都检查了 `Truncated`，它没有），而 `exchangeDNS` 的契约正是"TCP 重试失败时把 TC=1 的答案交回调用方自己判断" | **核实**。`authoritativeNS` 用它构造权威服务器清单，截断会静默减少 NS 数量，进而可能让"多权威至少 2 个 NS 名确认"退化成单权威豁免——正是这条规则要防的假通过。**已修**：`queryRecursive` 遇到 `Truncated` 记为「该解析器无法判断」并换下一个。用例 `TestATruncatedAnswerDoesNotShrinkTheAuthoritySet`：第一个解析器返回截断的 NS 答案、第二个返回完整答案；去掉检查后权威集合塌缩，测试变红。 |
| m2 | `internal/acme/manager.go:463-465`（另有 449-451、`manager_done.go:47`） | `discardOrder` 失败时直接 `return err`，不经过 `recordFailure`，于是没有退避、没有升级 | **核实**。同一变更里新加的调用点（`manager_flow.go:76-83`）明确写了"必须仍然 recordFailure"，另外三处没有。**已修**：三处（过期订单、域名变更、已完成订单的收尾）都改为 `recordFailure`。用例 `TestAFailedDiscardSchedulesARetry`：用一个触发器挡住 `DELETE ON orders`，断言失败被记下且有退避；改回裸 `return err` 后测试变红。 |
| m3 | `cmd/tatrun/main.go:112-126` | `SUCCESS` 但 `TaskResult == nil` 时报成功、退出 0、无输出 | **核实**。这是"取证工具在拿不到证据时不该判成功"的典型（仓库自己的 docs/test-plan.md 也这么写）。**已修**：SUCCESS 但 `TaskResult == nil` 直接返回错误（并说明「没有可报告的证据」）。用例 `TestWaitForTaskRefusesSucceededWithoutEvidence`；恢复旧分支后变红。 |
| m4 | `internal/deploy/tencent.go:969-991` | `countBindings` 对"一个 region 都没数到"的响应给出 `complete:true, count:0` | **代码层核实，可达性未证实**：`res == nil`／空 `BindResourceRegionResult` 不会把 `complete` 置假（而同函数里 `region == nil` 会）。子代理查了本会话落盘的原始响应，真实服务端总是把条目填全，所以这更像**防御性缺口**而非已观测故障；但一旦出现，"旧证书 0 绑定"会被当成"切换已发生"的证据。**已修**：`res == nil` 或该条目一个 region 都没数到时 `complete = false`。用例 `TestAnUnpopulatedBindingEntryIsNotAnAuthoritativeZero`（nil 条目与无 region 两种形状）。 |

### 2.4 后续补修的 6 条（原先「未核实」，现已核实并修复）

| # | 位置 | 问题 | 状态 |
|---|---|---|---|
| N1 | `cmd/wecert/main.go`（`-once` 路径） | `RunOnce` 丢弃 `RunReport`，于是 `wecert-once.service` 在**每条证书都失败**时仍退出 0；`Trouble()` 没有任何生产调用者 | 已修：改用 `RunDetailed`，`Trouble()` 为真即返回错误；`onceExit` 的三种 trouble 形态与两种健康形态各有断言 |
| N2 | `internal/spec/observe.go` | 文件源首次读取成功后再也**不返回错误**，而是返回 frozen + nil error；于是 observe 模式对着读不出来的文档算出一份「安静」的差异，`ShadowReport.Error` 为空，切 enforce 的判据（`shadow_errors_total` / `shadow_last_read`）看起来一切正常 | 已修：frozen 的 shadow 报成「没有比较」；用例 `TestObserverReportsAFrozenShadowAsNoComparison`（去掉即变红） |
| N3 | `internal/acme/manager_done.go`（部署路径的两处 `PutOrder`） | 写入失败直接 `return err` 而不走 `recordFailure`：没有退避（连为这种情形准备的进程内 `transientBackoff` 也没有），且刚上传的云证书 ID 丢失，下一轮重新 `Upload`，每轮泄漏一张云证书 | 两处都改为 `recordFailure` 并说清「已上传但记账失败」；`TestAFailedDeployBookkeepingSchedulesARetry` 用一个 `WHEN NEW.deployment_cert_id != OLD.deployment_cert_id` 的触发器只挡住锚点写入（其余订单更新照常），断言失败被记下且有退避，改回裸 `return err` 即变红 |
| `internal/acme/manager_renew.go`（`ariCheckDue`） | 先判固定的 6h 下限、再看服务端 `Retry-After`，于是**比 6 小时更短的 Retry-After 永远不生效**（下限已经返回 false），与相邻注释「respect the Retry-After the server gave us」及 RFC 9773 §4.3 相反；当前 Boulder 恰好发 21600 才没暴露 | 改成「有 Retry-After 就用它（按 RFC 钳到 1m–24h），没有才用 6h 下限」；`TestAShortRetryAfterShortensTheARICheckInterval` 覆盖 1h 生效、无 Retry-After 时下限仍生效、72h 被钳到 24h（把判据改回取最小值即变红） |
| `internal/acme/revoke.go`（`alreadyRevoked`） | ACME 的 `alreadyRevoked` 被当成可重试：`ClearRevokeRequest` 只在成功路径，于是请求行永不清理 → `wecert_revocation_pending` 恒 ≥1、CRITICAL 告警常亮、每轮重试，而 CLI 对**已吊销**的证书持续说「会重试」；代码注释还把这次重试称为「harmless」 | 识别 `urn:ietf:params:acme:error:alreadyRevoked`（`errors.As` 到 `*legoacme.ProblemDetails`，文本兜底）为终态并清行；`TestAlreadyRevokedIsTerminalAndClearsTheRequest` 同时钉住「普通失败仍可重试、行保留」（去掉终态分支即变红） |
| `internal/config/config.go`（`probe.minValidFor`） | 只校验为正，没和 profile 的有效期比较：示例里的 `168h` 在 shortlived（160h）证书上永远不可能满足，`probe.Verify` 每次都失败 → `wecert_certificate_probe_match` 恒为 0 → critical 告警常亮且把原因错指向换绑/SNI；同一文件已拒绝同类的「`renewBefore` ≥ 有效期」 | 在证书归一化之后校验 `minValidFor < profileValidity[profile]` 并点名证书与 profile；`TestProbeMinValidForMustBeSatisfiableByTheProfile`（去掉校验即变红）。已确认随包示例（classic，90 天）不受影响 |
| `internal/ratelimit/ratelimit.go` | `Spend` 把快照锚点写成 `now`，即使时钟回拨；`Tokens` 已经计息到旧锚点，于是 `[now, s.At]` 会被**重复计息**，凭空多出配额 | 已修：锚点只向前走；用例 `TestASpendOnABackwardClockDoesNotReAnchorTheSnapshot` |
| N4 | `cmd/tatrun/main.go` | 截断的远端输出被当成完整结果打印，`Dropped` / `OutputUrl` 完全没用 | 已修：给出截断警告，且**不打印签名部分**（见下一条 P2）；用例断言警告包含丢弃字节数、不含 `q-signature` 等凭据 |
| N5 | `cmd/wecert/main.go` | 「快照已启用但目录不可写」分支**不可达**（`EnabledOr` 把显式设置直接返回，第一个分支已经吃掉），循环照常启动、每轮失败并打 ERROR | 已修：`planStateBackups` 把「开关」与「目录」分开判定；用例枚举五种组合 |
| N6 | `cmd/clbverify/main.go` | `-wait` 只限定尝试次数不限定耗时：先睡满一个间隔才看截止时间，`-wait 1s` 会阻塞 5s | 已修：先查一次、sleep 上限取剩余预算；用例断言 80ms 预算的耗时上限，并在把 sleep 改回固定间隔后变红 |

同轮依据 `code-review-expert` 复审结果补的小改动：日志 URL 去签名（P2）、`UpdateRateBucket` 的回调不得重入 store 的契约写明（P2）、DNSPod 空结果判定收敛到新的 `internal/tcerr`（P2，原先 `cmd/preflight` 与 `internal/onboarding` 各一份）、`bucketStore` 拆成读/写两个接口并删掉已无人使用的 `PutRateBucket`（P2）、采纳任务校验成功后打印耗时与绑定数（P2）、`pollUntilBound` 的回调合二为一并把轮询间隔提成常量（P3）。

**清理项（已做）**：`reconcile` 原先有三个整轮入口——`RunOnce`（`RunAll` 的兼容别名）、`RunAll`（包一层 `RunDetailed` 并丢掉报告）、`RunDetailed`。现在只剩 `RunDetailed` 一个；不需要结果的调用方写 `_ =` 明确表示，而不是调用一个「没法把结果交出来」的包装。守护进程的行为不变（一轮失败不会结束循环），但它现在会把每轮结果打出来（`attempted/succeeded/failed/backoff/skipped/trouble`）——此前「跑了一轮什么都没收敛」和「全部收敛」留下的痕迹是一样的。为了让这条契约可测，整轮入口作为参数注入 `runDaemon`，测试连跑三轮失败以证明循环存活并如实汇报（提交 `0ad34c7`）。

### 2.5 第二轮 OCR 复审（recover 被截断的发现）——本轮已修

第一轮的 workflow 结果落盘时被截断，36 条里只完整回收了 21 条。这一轮按包重新跑了一遍 delegation 复审，**每个审查组把结论写进文件**（不再经过会被截断的返回值），共回收 **19 条**新发现。本轮的修复：

| 位置 | 问题 | 修复与用例 |
|---|---|---|
| `cmd/clbverify/main.go` | 我上一轮抽取 `pollUntilBound` 时写成 `bound, lastErr := …`，**遮蔽**了外层 `bound`：等待轮询到了新证书、打印了进度，断言却读旧集合，于是**恰好在换绑成功时报失败**（`-wait` 存在的唯一场景） | 改回赋值并加注释；`assertBindings` 独立成可测函数；`TestTheWaitResultReachesTheAssertions` 把轮询与断言串起来测 |
| `cmd/tatrun/main.go` | `TaskResult.Output` 是 **Base64**（SDK 字段文档即如此，本仓库自己的 e2e 采集也是 Base64），工具却原样打印——所有取证输出是乱码，`-quiet \| grep` 永远匹配不到 | 解码后打印，解不出来则原样透出；测试的假客户端改为喂 Base64（这正是它藏了这么久的原因） |
| `internal/acme/manager_done.go` | 日志字段名 `dropped` 里装的是**保留**的域名个数（`len(c.Domains)` 是本次下发的集合） | 改名为 `issued` 并注明真正的数量在 ledger 行里 |
| `internal/state/revoke.go` | `RecordRevokeAttempt` 原样存 CA 错误，是包内唯一不截断的 `last_error` 写入者 | 走 `truncate(…, maxLastErrorBytes)` |
| `internal/state/backup.go` | 同毫秒冲突名 `<stamp>-1.db` 的 `-`（0x2D）排在 `.`（0x2E）**之前**，于是 `keep=1` 删掉的是**更新**的那份——与代码注释声称的正好相反 | 分隔符改为 `~`（0x7E），旧的 `-` 形式仍被识别（否则老快照永远不被清理）；`TestACollisionSnapshotSortsLastAndStillCountsAsOurs` |
| `cmd/wecert/main.go` | 函数拆分时 `startMetricsServer` 与 `startStateBackups` 的文档注释连成一段，`startMetricsServer` 反而没有文档 | 补空行并说明 |
| `internal/spec/observe.go` | shadow diff 只比较 profile/keyType/deploy，**`renewBefore` 的差异被报成"无差异"**，而 `Revision()` 把它算进哈希——切 enforce 的判据（diff==0）会在续期提前量变化时保持安静 | 纳入 `changed` 列表 |
| `internal/ratelimit/ratelimit.go` | `Spend` 从**已钳零**的 `Remaining` 里扣减，等于勾销零以下的欠债：-5 的桶再消费一次变 -1（应为 -6），下一个令牌提前好几个补充周期出现——与 `Spend` 自己「over-spend is not silently forgiven」的注释相反 | 抽出未钳零的 `level()` 承载补币算术，`Remaining` 在其上钳到 `[0, Capacity]`、`Spend` 用未钳零值扣减再把债务钳到 `-Capacity`；`TestSpendingWhileInDebtCarriesTheDebt`（改回从 `Remaining` 扣减即变红），并逐点钉住 5 次补充清零、第 6 次才有一个令牌 |
| `internal/state/state.go`（`pendingMigrations`） | 只检查**列**，检查不出缺整张表：缺表的库会被 unlocked open 接受，随后报原始 `no such table: revoke_requests`，而不是那句「本二进制需要 schema 更新，停进程跑 wecert -once」——每次发版新增一张表都会让上一版写出的库落进这个坑 | 表清单也声明成数据（`schemaTables`）并纳入检查，缺表时 `OpenUnlocked` 直接拒绝且点名缺哪张；`TestPendingMigrationsSeesAMissingTable`（去掉表检查即变红） |
| `internal/state/state.go`（退役表 upsert） | COALESCE 刷新了材料却**不刷新 `retired_at`**：先被 orphan 路径写入的行会按 orphan 的时间戳回收，于是云证书与刚归档的回滚材料在更早的窗口到期时就被删掉（renew 之前还会去删一张可能仍在服务的证书，只靠云侧绑定检查兜住） | `retired_at = EXCLUDED.retired_at`，让保留期从真正退役的那次写入起算；`TestRetiringACertificateRestartsTheRetentionClock`（去掉该列即变红） |
| `internal/deploy/tencent.go` | `progressBoundCount` 只按**已列出**的 region 判定就绪，nil 条目 / 空 region 列表被跳过：半填充的同步进度读成 `(0, ready=true)`，于是走「立刻硬失败」而不是交给权威部署记录（与已修的 `countBindings` 同一形状） | 未填充条目与 nil region 都计入 `unanswered`，答案不完整就不算就绪；`TestAHalfPopulatedSyncProgressIsNotAFinishedZero` 同时钉住「真实的全填充零仍是答案」，把 `unanswered` 条件去掉即变红 |
| `internal/onboarding/declaration.go` + `internal/config/config.go` | 声明里的 `profile`/`keyType` 值不校验，直到 `spec.WriteDocument` 才失败：一个写错的 TXT 值会让 `Run()` 报 `written`、`Commit` 永远失败，**文档与状态文件都不写**，每轮每条证书都失败直到有人改 DNS；与本包"一条坏声明只影响它自己"的既有约定矛盾 | 取值集合收敛到 `config.ValidProfile`/`config.ValidKeyType`（`normalize` 也改用它们），解析处即拒绝非法值，于是它变成"那一条声明被拒"；`TestParseDeclarationRejectsUnknownProfileAndKeyType`，去掉校验即变红 |
| `internal/webhook/webhook.go` | `reconcileResponse.Accepted` 无初值，什么都没接受时回 `202 {"accepted": null}`，与本包 `/hook/status` 已文档化并测试过的"空数组"约定相反 | 初始化为空切片 |

### 2.6 第二轮复审发现、**尚未修复**的清单（核实为真，留待下一轮）

按严重度排列。每条都写明位置、为什么成立、以及修法；这些是**已核实的问题**，不是猜测。

| 严重度 | 位置 | 问题 | 修法 |
|---|---|---|---|
| **major** | `internal/state/revoke.go:43` | 持久化的吊销请求**不记录证书身份**（表里只有 name/reason/时间/次数）。重试时 `processRevocation` 读的是**当前** `certificates.cert_pem`，而续期会覆盖它；reconcile 又在每轮证书循环**之后**重试吊销——于是同一轮里可以先提升新证书再把它吊销：新证书被吊销、泄露的旧证书继续有效，而请求行被当作成功清掉 | 把叶子身份（serial/AKI 或 NotBefore）随请求落库（`schemaColumns` 已支持），吊销前校验当前证书是否匹配；不匹配则改吊 `retired_certificates` 里的归档副本 |
| **major（待产品决策）** | `internal/onboarding/onboard.go:944` | 仍然被声明、但被 guard 1（或白名单）拒掉的名字，在同一轮就被**从期望状态里删除**：`applyGrace` 的 `stillDeclared` 分支只 `MarkPresent`，既不 carry 也不 `MarkAbsent`，因此绕过宽限期与 CLB 引用检查。guard 是网络读取的第二来源且**无法表达"结果可能不完整"**，一次规则抖动（区域缺失、部分可见、限流）就会静默剥掉线上覆盖；而 fuse 比较的是声明、声明没变，所以任何保护都不会触发。实测一次抖动 = 两次签发 + 两轮失去覆盖 | **这条我没有动手，因为它是一次语义反转，需要你拍板**。两种读法都成立：现行行为（把该名字当轮从文档里去掉，已有测试 `TestStillDeclaredNameIsNotReportedAsRemoved` 用"carry 会让 guard 1 拒绝的名字继续被签发"来钉住它）与复审主张（声明仍在，就应当保持覆盖；去掉会改 revision → 触发签发，恢复时再改一次 → 再签发一次）互斥。carry 的代价是"规则已删但声明未删"的名字会一直被证书覆盖（直到声明被删，才走宽限期 + 引用检查的正常移除路径）；不 carry 的代价是每次 guard 抖动两次签发加两轮失去覆盖。我的倾向是改成 carry，并把 `ListRuleDomains` 的"结果可能不完整"作为独立信号补上——但那要连同 `TestStillDeclaredNameIsNotReportedAsRemoved` 的语义一起改，所以留给你决定 |
| minor | `internal/acme/dns.go:200` | `WaitAll` 注册的 TXT 租约可能**活得比它的授权久**（未呈现行的回收不调 `CleanUp` 就删行；令牌刷新后 `CleanUp` 推导出的值也变了），于是该名字后续所有清理都会走"还有别的挑战在线"分支，**provider 的 delete-all 在进程重启前再也不会执行**，TXT 记录滞留在那里 | 在那两条丢失路径上释放租约，或让 `CleanUp` 用 store 里仍标记为 presented 的行来对账 |
| minor | `internal/acme/ratelimit.go:83` | 桶读失败（例如 SQLITE_BUSY）被当成 0 剩余并发布，于是 `wecert_ratelimit_remaining_tokens < 5`（15m）对**所有**限额误报"配额耗尽"，直到下一轮成功；同一包的 `retryRevocations` 在同样情形下刻意不动自己的指标 | `QuotaReport` 加"不可读"标记，读失败时不 `Set`（不发布 = 未知，本文件已把"缺席"定义为可接受） |
| minor | `internal/reconcile/reconcile.go:576` | `publishQuota` 只有 `RunDetailed` 末尾一个调用者：webhook 触发的 pass 会花配额、也会记录 CA 的 Retry-After，但**从不发布**这两个指标；比轮询间隔（默认 1h）短的 deadline 更是永远来不及被发布成 blocked，critical 告警不会响 | `StartAll`/`StartNamed` 也调用 `publishQuota`（两者都已持有解析好的 Result） |
| minor | `internal/reconcile/reconcile.go:362` | `publishOrphans` 只是**窥探** claim（`isClaimable` 马上释放锁）再在 store 读之后调 `CleanupOrphan`：webhook 触发的同步 claim 可以插进这个缝里，于是它的 TXT 记录/订单被拆掉——正是该处注释声称要防的破坏性交错 | 在整个拆除期间持有 claim |
| minor | `internal/acme/manager_renew.go:137-146` | 新订单配额记在**第一次** `NewOrder` 成功上；真正创建订单的 `replaces` 重试不记账，其错误也没走 `NoteRetryAfter`，于是发布的"下界"偏乐观 1，且一次限流拒绝被静默丢弃 | 记账与 `NoteRetryAfter` 都放在真正成功/失败的那次调用上 |
| minor | `internal/acme/manager.go:575-583` | ARI 守卫 `return ariErr` 绕过 `recordFailure`，而 `ARICheckedAt` 正是 `ariCheckDue` 的依据：状态库故障时会**每轮**重查 renewalInfo（按文档的 1 分钟间隔约 1440 次/天/证书），正是 `default:` 分支注释说要避免的循环 | 走 `recordFailure`（ctx 取消会被它透传，安全） |
| minor | `cmd/wecert-probe/main.go:178` | `-wait` 只在两次尝试之间检查，进行中的一次会用满 `-timeout`（默认 10s）：实测 `-wait 1s` 用 10.009s，与本文件"不得等超过要求的时长"的自我要求矛盾 | 每次尝试的预算取剩余时间 |
| minor | `internal/onboarding/onboard.go:383` | `Commit` 先写报告、再写文档与状态：失败的那一轮会留下一个声称 `mode: "written"`、带一份从未写出的 revision 的报告（而报告是该流程文档化的人读产物） | 报告最后写，或在报告中如实标注本轮失败 |
| minor | `internal/state/backup.go:96` 等 | 见 §2.5：本轮只修了冲突名排序；`pruneSnapshots` 的其余候选（`Stat` 错误被当成冲突可能自旋）留在原审查记录的 notes 里 | — |


**已全部返回**：8 个复审组的结果都已收到（最后一组 `internal/config`+`internal/deploy`+`internal/probe` 交回 2 条 minor，即上表两行）。8 组一致确认无 blocking 级问题。

---

## 3. 精度说明（这份审查的可信度边界）

- 工作流原始输出 36 条，落盘时被截断，**完整回收 21 条**；下面这些是我**逐条回代码核对**的：B1、B2、M1–M7、m1–m4，共 **15 条**。其余 6 条（`reconcile.go` 的 `RunOnce` 丢弃 `RunReport`、`internal/spec/observe.go` 的 frozen shadow 被报成新鲜对比、`rate-limit` 的时钟回拨重复计息、`ratelimit` 的 `Spendable` 之外几条 minor）**未逐条核实**，按"工具报告、待确认"看待。
- 没有任何一条被判定为**误报**；m4 是唯一被我下调严重度的一条（可达性）。
- **修复状态（更新）**：核实的 15 条 + 原先「未核实」的 6 条**全部修完**。后 6 条我逐条回到代码确认了它们都成立，然后各自修复并钉住：
  1. `cmd/wecert` 的 `-once` 路径改用 `RunDetailed`，`Trouble()` 为真就返回错误（systemd timer 不再「每条证书都失败却退出 0」）；`Trouble()` 的三种形态各有断言。
  2. `spec/observe.go`：frozen 的 shadow 源现在报成「没有比较」（`ShadowReport.Error` 非空），而不是对着读不出来的文档算一份「安静」的差异。
  3. `ratelimit.Spend` 的快照锚点**只向前走**：时钟回拨时不再把锚点带回更早的瞬间，否则 `[now, s.At]` 这段会被重复计息一次、凭空多出配额。
  4. `tatrun` 对截断的输出给出警告（`Dropped` / `OutputUrl`），部分输出不再被当成完整证据。
  5. `cmd/wecert` 的「快照已启用但目录不可写」变成独立分支（原来被 `EnabledOr` 吃掉、永远不可达），并保持不启动必然失败的快照循环。
  6. `clbverify` 的 `-wait` 真正限定耗时：先查一次、再按剩余预算 sleep（原来先睡满一个间隔、`-wait 1s` 会阻塞 5s）。
  六条的变异校验全部通过（去掉修复即变红）。
- 审查范围只覆盖**本分支相对 main 的产品代码改动**，不代表整个仓库已审。
- `ocr` 的 delegation 模式不产生行内注释或 SARIF，只给"文件 + 规则"；行号是我复核时按当前文件确认的。

## 4. 复现

```bash
# 1) 构建（本机没有 LLM 凭据，故走 delegation）
git clone --depth 1 https://github.com/alibaba/open-code-review /tmp/ocr-probe
cd /tmp/ocr-probe && go build -o bin/ocr ./cmd/...

# 2) 选文件 + 取规则
cd <wecert>
/tmp/ocr-probe/bin/ocr delegate preview --from main --to HEAD --format json
/tmp/ocr-probe/bin/ocr delegate rule internal/deploy/tencent.go internal/acme/dns.go --format json

# 3) 若有模型端点：直接让它自己审
ocr config provider && ocr review --from main --to HEAD
```
