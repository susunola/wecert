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

## 2. 核实过的发现

### 2.1 blocking

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

修法：把已知的 `deployedID` 传进 `orphanToRecord`（`m.orphanToRecord(c.Name, deployedID)`），别再从事务前的 store 里读旧值；顺带把这次 clear 移进同一个事务（见 B2）。

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

修法：删掉事务外这次 clear，让 `tx.DeleteOrder` 原子地连 ID 一起清（配合 B1 的改动），或给它一个 `tx` 版本的写入。

### 2.2 major（均已回到代码核实）

| # | 位置 | 问题 | 核实结论 |
|---|---|---|---|
| M1 | `internal/onboarding/tencent.go:198-206` | `DescribeRecordList` 从不设 `ErrorOnEmpty`，DNSPod 默认"查不到就报错"（`ResourceNotFound.NoDataOfRecord`） | **核实**。全仓库没有任何一处设置该字段；本会话我自己的 API dump 就两次撞到这个错误码（删完记录的 `_wecert-lagtest`、没有记录的 `_acme-challenge` 过滤查询）。后果不止"少读一页"：`onboard.go:565` 会 `r.freeze("declaration source failed: …")`，而 `:387` 对 frozen 轮次直接 `return nil`（只写报告、不写 desired-state 文档与 state 文件）——**账号里任何一个没有 TXT 记录的 zone 就足以让整个 onboarding 停止收敛**（而且 `limit=100` 的翻页在总数正好是 100 的倍数时也会请求越界页）。修法：`req.ErrorOnEmpty = common.StringPtr("no")`，并把 `ResourceNotFound.NoDataOfRecord` 当作空页处理。 |
| M2 | `internal/ratelimit/tracker.go:69-95`（`NoteRetryAfter` 同形 139-157） | `Spend` 是 `Get → 计算 → Put`，自身无锁；store 的锁只覆盖单条语句 | **核实**。`manager_renew.go:141-142` 在**同一个 account 级 bucket** 上花钱，而管理器按证书并发（同进程 8 路，见 `reconcile.go` 的 `maxConcurrentStarts`），因此并发丢更新 → 本地配额估计偏乐观。这个仓库自己已经为同样的模式引入过 `UpdateCert` 原子读改写，配额路径却还是"读-改-写"。修法：给 store 加 `UpdateRateBucket(…, fn)`（持 `s.mu` 包住读改写），`Spend`/`NoteRetryAfter` 改用它。 |
| M3 | `internal/ratelimit/ratelimit.go:108-116` + `internal/acme/ratelimit.go:59` | `Spendable()` 列了 4 个限额，实际只有 1 个被花掉，另外 3 个指标永远等于容量 | **核实**。全仓库 `Spend(` 只有 `manager_renew.go:141` 一处，且只花 `NewOrdersPerAccount`；而 `acme/ratelimit.go:59` 会为 `Spendable()` 的每一项发布 `wecert_ratelimit_remaining_tokens`。于是 `{limit="certs-per-exact-identifier-set"}` 恒为 5，`deploy/prometheus/wecert-alerts.yml` 里 `< 5` 的告警**结构上不可能触发**——恰恰是代码注释里强调"没有任何 override 通道"的那个限额。修法：在签发完成/授权失败处真正记这笔账，或者从 `Spendable()` 里移除，别发布一个结构性恒满的数字。 |
| M4 | `cmd/clbverify/main.go:93-111` | 断言只看监听器级证书（`Listeners[0].Certificate`），完全不看规则级绑定 | **核实**，而且**本会话的真机运行就是证据**：这个账号强制开启 SNI、监听器级证书被静默忽略（证书只能挂在规则上），`run-stage-ab.sh` 的 pre-rebind 检查因此直接失败并报 "the listener has no certificate bound"。文件里 `Rules` 出现 0 次。危险方向更值得注意：`-not-expect <旧证书>` 会在"旧证书仍绑在真正服务该域名的规则上"时**通过**——正是这个工具存在意义所在的反向假保证。修法：把 `Rules[i].Certificate`（可按 `-domain` 选中规则）纳入断言集合。 |
| M5 | `internal/webhook/webhook.go:346-374` | 具名触发用**缓存**的期望状态判定 "unknown"，刚加进文档的证书永远进不了这一轮 | **核实**。`CertNames()` 读 `r.last`（只在 Prime 与每轮 pass 时由 `resolve()` 写入）；`resolveTargets` 先用它过滤请求里的名字，未命中的直接归入 `unknown` 并**传空 targets** 给 `StartNamed`——而 `StartNamed` 自己会 `r.resolve(ctx)` 拿到**更新**的列表，却因为 targets 为空而什么也不启动。这正是 README 记录的 CI 用法（"域名刚加完就用 webhook 触发收敛"）会踩的坑：调用方被告知"不在配置里"，实际是"配置里有、缓存太旧"。修法：分支只按请求体判断（无 cert/certs → `StartAll`，否则把请求里的名字原样交给 `StartNamed`，用它的 started/unknown 结果回答）。 |
| M6 | `internal/state/backup.go:93-98` | 快照由 SQLite 以进程 umask（通常 0644）创建，**写完之后**才 `chmod 0600` | **核实**。这段窗口里文件含 ACME 账号私钥与全部证书私钥；窗口内进程被杀则留下一个 0644 且**永远不会被清理**的 `.snapshot-*.tmp`（列目录只认 `<base>.backup-<stamp>.db`）。同包的 `state.go` 早已为同样的原因用 `restrictiveUmask()` 包住建库窗口。修法：`VACUUM INTO` 外面套同一个 `restrictiveUmask()`。 |
| M7 | `cmd/wecert/revoke.go:79-84` | 无论是否真的落盘，都会打印"请求已记录，每轮会重试" | **核实**。`RequestRevocation` 在四条路径上**早于** `AddRevokeRequest` 返回（证书不存在/无材料、reason 非法、store 错误）：例如对不存在的名字执行 `-revoke`，会先打印"The request is recorded … will be retried on every pass"，而实际 `wecert_revocation_pending` 保持 0。修法：给"什么都没记录"一个可 `errors.Is` 的区分，只有真的入队时才说"已记录"。 |

### 2.3 minor（抽查核实）

| # | 位置 | 问题 | 核实结论 |
|---|---|---|---|
| m1 | `internal/acme/dns.go:975-978` | `queryRecursive` 把截断响应当完整答案用（`probeTXTWithExchange`/`probeRecursive` 都检查了 `Truncated`，它没有），而 `exchangeDNS` 的契约正是"TCP 重试失败时把 TC=1 的答案交回调用方自己判断" | **核实**。`authoritativeNS` 用它构造权威服务器清单，截断会静默减少 NS 数量，进而可能让"多权威至少 2 个 NS 名确认"退化成单权威豁免——正是这条规则要防的假通过。修法：`queryRecursive` 里把 `Truncated` 当作该解析器"无法判断"，换下一个。 |
| m2 | `internal/acme/manager.go:463-465`（另有 449-451、`manager_done.go:47`） | `discardOrder` 失败时直接 `return err`，不经过 `recordFailure`，于是没有退避、没有升级 | **核实**。同一变更里新加的调用点（`manager_flow.go:76-83`）明确写了"必须仍然 recordFailure"，另外三处没有。修法：统一 `return m.recordFailure(st, …)`。 |
| m3 | `cmd/tatrun/main.go:112-126` | `SUCCESS` 但 `TaskResult == nil` 时报成功、退出 0、无输出 | **核实**。这是"取证工具在拿不到证据时不该判成功"的典型（仓库自己的 docs/test-plan.md 也这么写）。修法：该分支返回错误。 |
| m4 | `internal/deploy/tencent.go:969-991` | `countBindings` 对"一个 region 都没数到"的响应给出 `complete:true, count:0` | **代码层核实，可达性未证实**：`res == nil`／空 `BindResourceRegionResult` 不会把 `complete` 置假（而同函数里 `region == nil` 会）。子代理查了本会话落盘的原始响应，真实服务端总是把条目填全，所以这更像**防御性缺口**而非已观测故障；但一旦出现，"旧证书 0 绑定"会被当成"切换已发生"的证据。修法：照 `progressBoundCount` 的 `listed > 0 && answered == listed` 收口。 |

## 3. 精度说明（这份审查的可信度边界）

- 工作流原始输出 36 条，落盘时被截断，**完整回收 21 条**；下面这些是我**逐条回代码核对**的：B1、B2、M1–M7、m1–m4，共 **15 条**。其余 6 条（`reconcile.go` 的 `RunOnce` 丢弃 `RunReport`、`internal/spec/observe.go` 的 frozen shadow 被报成新鲜对比、`rate-limit` 的时钟回拨重复计息、`ratelimit` 的 `Spendable` 之外几条 minor）**未逐条核实**，按"工具报告、待确认"看待。
- 没有任何一条被判定为**误报**；m4 是唯一被我下调严重度的一条（可达性）。
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
