# 第六轮代码复审（2026-09-18，5 个独立复审者）

> 承接 [`docs/code-review-round4-2026-09-18.md`](code-review-round4-2026-09-18.md)（前 5 小轮，42 条已修）。这一轮的问题不是「再读一遍代码」——前几轮已经把能读出来的东西读得差不多了——而是**换五种不同的看法**：只攻击最新代码的、只看最少人看过的包的、只比对文档与行为的、只量测试质量的、以及只从架构与安全下手的。每人的结论写进 `/tmp/wecert-r6/<组>.json`，再由我逐条回代码核实、修复、做变异校验。

---

## 1. 这一轮怎么做的

| 复审者 | 只看什么 | 返回 | 我核实后 |
|---|---|---|---|
| 攻击最新代码 | 6d2eb98 / 2399075 两个提交的每一处（draining、落盘次序） | 4 条（1 medium、3 low）+ 10 条驳回 | **1 条成立**（medium），3 条按「已知取舍/无生产调用方」处理 |
| 最少人看的包 | `tcerr`、`metrics`、`probe`、`spec`、`group`、`config`、`state/backup` | 22 条（2 high、3 medium、13 low、4 驳回） | **2 high + 3 medium + 5 low 成立**，其余记为已知项 |
| 文档 vs 行为 | `README*.md`、`docs/`、`deploy/`、`scripts/` 与代码逐条对照 | 52 条（36 成立：7 high、15 medium、14 low；16 驳回） | **7 high + 9 medium 已修**，其余如实列为未修 |
| 测试质量 | 覆盖率、变异校验、空测试、抖动、次序 | 覆盖缺口 + 3 条「假信心」 + 1 条「没有任何用例钉住」 | **2 条已补**（缺的用例、空断言），1 条记为方法学限制 |
| 架构 / 安全 | SOLID、移除候选、注入、密钥、文件与网络面 | 16 条（1 **P1**、4 P2、11 P3）+ 12 条移除候选 + 28 条驳回 | **P1 + 3 P2/P3 已修**，其余分类记录 |

**方法上的一条教训**：我一边改代码一边让复审者读同一棵树，结果其中一个复审者的子代理把我刚加的两个 webhook 测试当成「未授权的改动」删掉了（`internal/webhook/webhook_test.go` 少了 45 行）。三件事：复审期间不要让工作树变动；复审者写进报告里的「工作树不干净」需要我来确认是谁改的；被删的测试要当成缺陷处理（已补回并跑绿）。这一轮之后，下一轮应当**先提交再复审**。

---

## 2. 已修的（按影响排序）

### 2.1 两处 HIGH：快照保留会删掉它刚写的那一份 / 空库快照挤掉真快照

| 位置 | 缺陷 | 修法与用例 |
|---|---|---|
| `internal/state/backup.go` | 保留策略按**文件名里的墙钟时间**排序、从前面删。快照名一旦比「现在」更晚（NTP 往回校、虚拟机从快照恢复、备份目录是从一台时钟走快的机器上恢复的），**刚写的那一份就排在最前面**，于是这次调用删掉了自己刚写的文件：调用方打印「state database snapshotted path=…」而这个路径已经不存在，恢复点**静默停止前进** | `pruneSnapshots(dir, keep, protect)`：受害者集合里排除本次写入的路径，等于多删一个最旧的，保留数仍等于 `keep`。用例 `TestPruningKeepsTheSnapshotItJustWroteWhenTheClockWentBackwards`（造一个 now+1h 的假快照名，keep=1）；去掉保护即变红，报「the snapshot this call just wrote was deleted by its own pruning: no such file or directory」 |
| `internal/state/backup.go` + `cmd/wecert/main.go` | 空数据库的快照被当成正常快照参与保留。而快照存在的**唯一场景**（state.db 丢了）正好会造出空库：每次重启写一份空快照、挤掉一份真快照 —— 实测 keep=3、重启 3 次 → **3 份真快照全部消失**，运维还没来得及发现丢失，最后的恢复点已经没了 | 新增 `Store.HasRecoverableState()`（accounts / certificates / orders / revoke_requests / retired_certificates 里有任何一行；rate bucket 与失败计数**不算** —— 丢它们只丢限额知识）；`takeSnapshot` 在没东西可恢复时跳过并 WARN。用例 `TestHasRecoverableStateTracksWhatASnapshotCouldRecover`、`TestAnEmptyDatabaseIsNotSnapshotted`（空库不写、有证书才写）；去掉守卫即变红（写了两份，报「got 2」） |

### 2.2 P1：Makefile 会把 git tag 名当 shell 执行

`VERSION ?= $(shell git describe --tags …)` 被展开进 `-ldflags "…$(VERSION)"` 这个**双引号 shell 词**里，而 git 的 refname 允许 `"`、`;`、`>`、`$`。实测：`git tag 'v0.0.1";id>/tmp/PWNED;#'` → `make build` **退出码 0** 并且执行了注入的命令；`git clone` 会带上 tag，所以受害者的工作树是干净的，而 `make release` 的产物正是 `install.sh` 以 root 安装的东西。

修法：`SANITISE_VERSION`（`tr -c 'A-Za-z0-9._+-' '-'`）后再拼进 ldflags；同一个 tag 下 `make build` 退出 0、`/tmp/PWNED` 不存在、版本号是 `v0.0.1--id--tmp-PWNED---dirty`。

### 2.3 关闭路径与状态库

| 位置 | 缺陷 | 修法与用例 |
|---|---|---|
| `internal/acme/manager_flow.go` | 挑战已经写进 DNS、但**记录它的那次状态写入失败**时，盘上那一行仍然只有上一轮的 token（续做路径刻意如此），于是新记录在盘上、租约表里、日志里**都没有名字**：恢复时按旧 token 探测 → 被权威否认 → 删行，那条 TXT 就永远留在 DNS 里占额度 | 写入失败且 `a.Presented` 为真时，先把刚写的记录**收回来**（`removeAuthzTXT`）再报失败，收不回来就明确 WARN 并指出 `txt_name`。用例 `TestAFailedStateWriteTakesThePresentedRecordBackOut`：用 SQLite 触发器让「记录 presented 的那次 UPDATE」失败（读得到、写不进，与磁盘满/页损坏同形），断言 provider 的 delete-all 恰好触发一次；去掉回收即变红（0 次） |
| `internal/webhook/webhook.go` | 锁定检查在**token 检查之前**，按客户端 IP 计数 —— 而 README 自己推荐的部署就是在监听器前面放 TLS 终结器，所有客户端共用同一个地址。于是未认证的攻击者花掉这个地址的预算后，**持正确 token 的运维**在每个 hook 路由上收到 429（含只读的 `/hook/status`），15 分钟可续 | token 先判，锁只作用于**认证失败**的请求；暴力破解的边界不变（错 token 计数、超预算直接 429）。改了 `TestAuthLockoutAfterFailures` 的契约（旧注释「the block is on the address, not on the credentials」连同代价一起留在用例里），新增 `TestACorrectTokenIsNotLockedOutByFailuresFromTheSameAddress` |
| `internal/webhook/notify.go` + `cmd/wecert/main.go` | 通知目标 URL **原样进日志**（启动时一条、每次投递失败一条，而失败的错误串里还嵌着一次 URL）。Slack/飞书/钉钉这类 webhook 把密钥放在路径里，日志的去处通常比守护进程的主人更广 | 新增 `RedactNotifyURL`（保留 scheme+host，路径与查询打码）与 `withoutURL`（剥掉 `*url.Error` 里的 URL，保留传输层原因）；两个日志点都改用它。用例 `TestANotificationTargetIsNotLoggedVerbatim`（连不上的端口 + 秘密路径，断言日志里没有秘密、但有主机）、`TestRedactNotifyURL`（7 个形状） |

### 2.4 告警/指标的「假绿」

| 位置 | 缺陷 | 修法与用例 |
|---|---|---|
| `internal/probe/runner.go` | **解析失败**那条分支没有把 `wecert_certificate_probe_match` 置 0，而它的两个兄弟分支都置了（注释还写着「stale 1 正是这个指标要排除的假绿」）。一台上一轮匹配成功、这一轮 DNS 丢了的主机，会一直报 `probe_match=1`，而 `== 0` 的告警对**唯一一台真的解析不出来的主机**永远不响 | 该分支补上置 0。用例 `TestResolveFailureMarksProbeMatchZero`（先跑一轮成功把指标顶到 1，再让 `probeAll` 返回解析错误）；去掉置 0 即变红 |
| `internal/config/config.go` + `internal/reconcile/reconcile.go` | `probe.minValidFor` 的检查遍历 `c.Certificates`，而 **enforce 模式要求这个列表为空**（证书只来自文档）—— 于是这个检查在架构主推的模式里是空转：floor 比 shortlived 的有效期还长时，每张证书的探测都失败、`probe_match` 钉在 0、CRITICAL 告警把原因指向换绑或 SNI | 抽出 `config.CheckProbeFloor`，`normalize` 与**解析出文档之后**各调一次；文档是会变的，所以 reconcile 侧只报 ERROR 不失败（监控配置问题不该停掉签发）。用例 `TestAProbeFloorTheDocumentCannotSatisfyIsReported` |
| `internal/reconcile/reconcile.go` | `publish()` 读状态库失败时**裸返回**：文档称为「唯一到期信号」的 `wecert_certificate_not_after_timestamp_seconds` 继续报上一轮的值，而 `wecert_last_reconcile` 在前进 —— 一个看起来刚写过的陈旧数字 | 读失败改为 WARN 并说明该证书的序列会保持旧值（同包的两个兄弟指标有专门的陈旧计数器，这个读还没有；如实写明日志是唯一信号） |
| `internal/tcerr/tcerr.go` | 只归类了 `ResourceNotFound.NoDataOfRecord`，漏了同一族的 `NoDataOfDomain`（SDK 的错误表与腾讯云官方错误码页都有）。于是 `cmd/preflight` 的 `findDomain` 对它自己文档化的答案（`nil, nil` = 这个账号里没有这个域名）永远走不到：空域名列表会打印「check the dnspod:DescribeDomainList permission」，把运维指向一个没问题的权限 | 新增 `CodeNoDataOfDomain` / `IsNoDataOfDomain`，preflight 在该分支返回文档化的 `nil, nil` |

### 2.5 输入与成本

| 位置 | 缺陷 | 修法与用例 |
|---|---|---|
| `internal/spec/document.go` | 读取用 `io.LimitReader(f, 16MiB)` **静默截断**，而截断点落在证书边界上时，前缀本身是一份合法的完整文档 —— 实测 200,000 张证书的文档被接受为「114,909 张的期望状态」，其余全部被丢掉（enforce 模式下等于把它们从证书里摘掉） | 读 `cap+1` 字节，超限直接报错并说明为什么不能截断。用例 `TestAnOversizedDocumentIsRefusedRatherThanTruncated` |
| `internal/deploy/credentials.go` | config 层校验凭证环境变量时会 `TrimSpace`，deploy 层却**原样再读一次**：`SECRET_ID="   "` 通过了校验，然后原样送进 CAM 客户端，得到的是一次 `SignatureFailure`（看起来像密钥错），而不是「没有配置凭证」 | deploy 侧同样 `TrimSpace` |
| `cmd/wecert-onboard/main.go` → `internal/onboarding/onboard.go` | `-profile` / `-keytype` 直接进 `Options`，绕过了 config 层与声明解析器都有的校验：一个拼错的 profile 会让 `Run` 报 `mode="written"` 并给出证书数量，而 `Commit` 失败、文档根本没写（与第 4 轮修掉的「written 但磁盘上没有」同一类） | `onboarding.New` 校验 profile/keytype（与 `-drop-threshold` 的守卫同一位置） |

### 2.6 让文档里的契约变成真的

- **`wecert-probe -json`**：两份 README 与 `docs/test-cases.md`（TC-PROBE-20/21/21b）都写「NDJSON，每次尝试一行」，而 `emitJSON` 用的是 `SetIndent` —— 一次尝试约 30 行、没有任何一行是独立 JSON。**这是第 4 轮我自己误判为「已按 NDJSON 设计」并写进文档的**。这一轮把代码改成真的每行一个对象（`SetIndent` 去掉），并加 `TestJSONOutputIsOneObjectPerLine` 钉住「两个地址 = 两行、每行可独立 `json.Unmarshal`」。
- **CAM 策略漏权限**：三份随仓库分发的策略都缺 `ssl:DescribeDeleteCertificatesTaskResult`，而 `IsCheckResource=true` 的删除**都是异步的**，确认删除结果就靠这个调用 —— 用随仓库策略部署时，回收循环永远确认不了删除、每轮告警、配额不回收。已补进三份策略，并新增 `scripts/check-cam-policies.py`（从 `pkg.NewXxxRequest` 提取代码真正调用的 action，与策略求差集）+ 自测 `scripts/test-check-cam-policies.py`（缺 action 必须报错、完整策略必须通过、新增 API 必须被发现），接入 `make check-scripts`。

---

## 3. 复核后**驳回**的（同样记下来，说明这些面查过了）

| 复审说法 | 为什么不是缺陷 |
|---|---|
| `internal/acme/manager_flow.go:111` 的 `return err` 绕过 `recordFailure`（P2） | **逐条列过 `solveChallenges` 的全部 16 个 `return`：每一个错误返回都已经走 `m.recordFailure(st, …)`**，没有任何裸错误能传出来。在外层再加一次会**把每次失败记两遍**（`consecutive_failures` 翻倍、退避变长），比原样更糟。这一条是「同族缺陷」推断错了，不是漏修 |
| `ratelimit.Spend` 的容量钳制（第 5 轮已驳过，这轮行为验证者又实测一遍） | 结余丢弃、`cost > capacity` 夹在 `-capacity`、欠债继续背、负 cost 不当 credit —— 全部符合设计 |
| `ParseRetryAfter` 的严格度、`[1m,24h]` 的归属 | 四种真实 Boulder 措辞都精确解析；钳制在 RFC 9773 §4.3.2 的 ARI 区间上（`manager_renew.go`），不在解析结果上 |
| 状态库迁移、`CASE WHEN` upsert、`releaseRowStaleLease`、`Drain` 的核心契约 | 行为验证者用真实旧 schema 与并发用例逐条跑过，无一失败 |
| Webhook 的认证顺序/常量时间比较/方法检查/413/服务器超时（slowloris 5s 掐断、2MB 头 431） | 全部符合设计，`-race` 与压力用例通过 |
| 密钥不外泄（AK/SK、账户私钥、webhook token 在日志/报告/`-json`/`%+v` 中的暴露面）、SQL 拼接、shell 注入、状态库与快照的 0600、TLS 校验、`math/rand` 只用于 jitter | 逐项枚举后确认无问题（47 处 SQL 只有两处拼接、都是硬编码 schema 字面量；三个密钥持有类型没有任何 `%+v`/`String()`/`MarshalJSON` 路径） |
| `state.Store` 的 `UpdateCert` / `PutRateBucket` 等「死代码」 | 确实是未被生产调用的导出 API，但删除导出符号是 API 决策（且有测试调用方），列入移除清单而不是这一轮直接删 |
| `internal/probe` 的期望语义与调用方不一致 | 逐个调用方比对后不成立 |

---

## 4. 明确**没做**的（连同理由）

| 项 | 为什么不做 |
|---|---|
| `state.go` 打开状态库没有 `O_NOFOLLOW`（符号链接可把 schema 与账户私钥写进攻击者的文件；目标文件仍是 0600，所以实际影响需要攻击者拥有该文件） | 拒绝符号链接会**破坏合法用法**（把 state.db 符号链接到另一块盘是常见运维做法），而文档只对期望状态文档明确禁止符号链接。核实为真、按「有意的取舍」记录：加固方向是像 `internal/spec` 那样做属主校验，而不是一刀切拒绝 |
| 状态目录权限不会被收紧（`MkdirAll` 对已存在的目录不改权限） | 同上：改已存在目录的权限会让运维意外。文档已写明目录 0700 |
| 每注册域名的配额序列只发布第一张证书的 scope（`WecertRateLimitNearlyExhausted` 对其它域名不响） | 修它要把 `PublishQuota(scopes map[string]string)` 改成「一个家族多个 scope」，涉及 `CertManager` 接口、manager、reconcile 与测试假件；这一轮不做半成品重构。**已记入待办**：改成 `map[string][]string` 后按解析出的每个注册域名发布 |
| 三处重复的「临时文件→fsync→chmod→rename」持久化协议（onboarding 报告、期望状态文档、onboarding 状态文件；第 4 轮报告 fsync 的漂移就是这么来的） | 抽公共函数要同时改三处并保持各自的 fsync 语义，属重构而非缺陷修复；记入待办 |
| `ratelimit/tracker.go` 的四个无调用方导出符号、`UpdateCert`、`PutRateBucket`、webhook 接口里的 `StartCert` 等 12 个移除候选 | 删除导出 API 需要单独一次「只做删除」的改动并跑全量门禁，混在这一轮里会让 diff 难以审阅。清单在 `/tmp/wecert-r6/architecture-security.json` |
| CI 不构建 `-tags lego_dns`（两个 tag 相关的生产文件与其测试无门禁） | **已在后续处理**：先用 `make release`（额外编译 linux/amd64 的 lego_dns 变体）与 `make test-tags`（进 `make check`）覆盖，随后用仓库所有者提供的、带 `workflow` scope 的凭据把 `make test-tags` 加进了 `.github/workflows/ci.yml`（提交 `b7b914d`） |
| 文档里剩下的低价值漂移（测试数量 633/60/18 vs 775/75/19、Roadmap 的「Outstanding」有 4/5 已交付、参考文档的状态表只列了 9 张表里的 5 张且缺两列、`docs/test-plan.md` 的覆盖率数字、`/hook/desired` 在 enforce 模式下返回的是文档里的决定而非实时评估） | 都是「读了不会做错事」的陈旧描述；已记录在案，留给下一轮或你决定 |
| `probe` 不限制解析地址数量（成本 = `ceil(N/8)×Timeout`，在证书自己的 pass claim 内） | 上限会与第 4 轮定下的「每个解析地址都必须判定」冲突；合理的修法是「超过上限即判定为无法完整验证（fail closed）」而不是抽样，需要设计。已记录 |

---

## 5. 这一轮的门禁

`gofmt -l .` 干净；`go vet ./...` 与 `go vet -tags "pebble lego_dns" ./...` 干净；`staticcheck ./...` 干净；`python3 scripts/check-english.py` **185 个源文件**通过；`make check-scripts` 5/5 + 新增的 CAM 策略检查（含自测）通过；`go test -race -count=1 ./...` **19/19 包通过**；`make check`、`make test-repeat`、`make test-pebble`（2/2）、`make e2e`（3/3）通过。提交：`94e69ab`（代码/策略/脚本）、`404059c`（文档），两份都已推送且 CI 在 `test/e2e-tlsserver-renewal`（PR #67）上 **success**。

新用例（每个都做过变异校验，除纯日志/注释两处）：`TestPruningKeepsTheSnapshotItJustWroteWhenTheClockWentBackwards`、`TestHasRecoverableStateTracksWhatASnapshotCouldRecover`、`TestAnEmptyDatabaseIsNotSnapshotted`、`TestAFailedStateWriteTakesThePresentedRecordBackOut`、`TestTheFirstVisitChallengeIsPersistedBeforeTheDNSWrite`、`TestResolveFailureMarksProbeMatchZero`、`TestAProbeFloorTheDocumentCannotSatisfyIsReported`、`TestAnOversizedDocumentIsRefusedRatherThanTruncated`、`TestACorrectTokenIsNotLockedOutByFailuresFromTheSameAddress`、`TestTriggerAllWhileShuttingDownIs503`、`TestTriggerCertWhileShuttingDownIs503`、`TestANotificationTargetIsNotLoggedVerbatim`、`TestRedactNotifyURL`、`TestJSONOutputIsOneObjectPerLine`；以及 `scripts/test-check-cam-policies.py` 的三条自检。

---

## 6. 精度说明（这一轮的可信度边界）

- **这轮抓到的两处 HIGH 都是「告警/恢复静默失效」**，不是签发逻辑错：快照保留删掉刚写的那份、空库快照挤掉真快照。两处都只有靠构造场景（时钟回拨、状态库丢失后重启）才会暴露 —— 值得记住的是**测试全绿与「恢复点还在」无关**。
- **一次误判被这一轮纠正**：`-json` 的 NDJSON 契约（第 4 轮我判「文档对、代码对」，实际文档对、代码不对）。写进文档之前应当先跑一次看输出形状，这是流程上的教训。
- **反过来的教训同样成立**：复审者提出的 `return err` 绕过 `recordFailure` 是**错的**，逐条列出 16 个 return 才看清；如果照它改，每次失败会被记两遍。复审者的每条结论都必须回代码核实，这一轮再次证明。
- **测试质量的边界**：覆盖率与变异只能证明「这条用例对这处修复敏感」，不证明覆盖了所有回归路径。这一轮发现 `bgMu` 的竞态用例只在 `-race` 下、且大约 1/20 概率变红（CI 跑 `-race`，所以有门禁但不稳定）；`TestStartingAPassDoesNotRaceWithDrain` 在普通运行下 40/40 通过 —— 已如实记下，确定性变红的是两个拒绝语义用例。
- **未跑/未验证（与前几轮合并）**：云端对 `IsCheckResource` 与删除任务状态的真实执行、CA 是否真的会在同一 authz URL 上换挑战、DNSPod 是否真会返回非规范记录名（以及 `NoDataOfDomain` 的真实触发形状）、真实崩溃注入、线上 LE 429 文案、生产 LE、自然到期续期、Stage C 在 CVM 上的「首绑→换绑」重跑、SNI 关闭路径、`-tags lego_dns` 的 CI 门禁（推不了 workflow）。
- **这一轮改了两处「有意的设计」**，都在代码注释与用例里写明理由，若你不同意可以单独回退：webhook 锁定不再作用于持正确 token 的请求；`probe.minValidFor` 在 enforce 模式下由「静默空转」改为「每次 pass 报 ERROR」。
