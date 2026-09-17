# 第四轮代码复审（2026-09-18，共 4 小轮）

> 承接 [`docs/code-review-ocr-2026-09-17.md`](code-review-ocr-2026-09-17.md)（前两轮，已清空）。这一轮换了打法：**5 个独立复审者并行**，每人只负责一组文件，结论写进 `/tmp/wecert-review-r4/<组>.json`（不经过会被截断的返回值），再由我逐条回代码核实、修复、并做「去掉修复就变红」的变异校验。
>
> 复审原则沿用仓库里那份规则说明（`/tmp/wecert-e2e/ocr-rule-1.md`）：**精度优先**，只报能追到可达调用路径的缺陷；gofmt / go vet / staticcheck / race 已经能判的一律不报；每条都要引用 file:line 原文。

---

## 1. 分轮计划与进度

| 小轮 | 覆盖面 | 状态 |
|---|---|---|
| 第 1 轮 | ACME 订单状态机；DNS 挑战层/ARI/吊销/配额记账；state + ratelimit；onboarding + spec + config；deploy + probe + reconcile + webhook + cmd | **已完成**（7 组复审返回，见 §2） |
| 第 2 轮 | 第 1 轮剩下未修的项 + 并发/生命周期/资源泄漏视角 | 待做 |
| 第 3 轮 | 对本次会话全部改动的对抗性复审 + 不变量与属性/模糊测试 | 待做 |
| 第 4 轮 | 跨面：文档 vs 行为、cmd/*、scripts、deploy、testenv，以及遗留项收口 | 待做 |

---

## 2. 第 1 轮：复审返回 37 条，核实后修掉 14 条

复审分组与条数：`acme-a`（订单状态机）5、`acme-b`（DNS/ARI/吊销/配额）5、`state`（state + ratelimit）2、`onboarding` 6、`deploy` 8、`cmd` 7、`webhook` 4。

### 2.1 已修复（每条都有会变红的用例）

| # | 位置 | 缺陷 | 修法与用例 |
|---|---|---|---|
| 1 | `internal/onboarding/tencent.go` | **上一轮我自己引入的回归**：`TotalCount` 在分页循环**内部**与「已读到的条数」比较，于是任何超过一页（100）的 region 都返回 `errIncompleteRuleList` —— 分页成了死代码，守卫被永久判定为不完整（不查规则、不删名字），每轮打印一次假的「规则列表被截断」 | 比较移到循环**之后**（用整轮累计的 `read` 与最后一次上报的 `TotalCount`）。假 CLB 现在按 Offset/Limit 分页、`TotalCount` 按「过滤后的总数」上报（之前它把整表塞进一页，正好掩盖了这个 bug）；`TestListRuleDomainsPagesPastOnePage`（250 个 LB 必须分页且枚举全）+「真的少了仍然报错」 |
| 2 | `internal/onboarding/onboard.go` | **carry 语义的配套缺口**：被 guard 拒掉但仍在声明的名字被 carry 了，可 `groupSettings` 跳过「未 accepted」的声明，于是证书的 profile/keyType/deploy 掉回默认值 —— 文档 revision 变了、触发签发；声明 `deploy=0` 的名字甚至会被**打开部署**。与上一轮提交里「revision 不变、不重签」的说法直接矛盾 | 新增 `settingsStillApply`：声明的任何名字仍在覆盖集合里时，它的设置继续生效。`TestACarriedDeclarationKeepsItsSettings`（规则消失前后 profile 仍是 tlsserver、deploy 仍为 false、revision 不变） |
| 3 | `internal/onboarding/onboard.go` + `internal/config/config.go` | `g.Cover(onboarding.maxNames)` 不看**该组实际会用的 profile**：`maxNames: 100`（classic 合法）+ 一条 `profile=tlsserver` 的声明 → 26 个名字的文档被 `spec.WriteDocument` 拒绝，于是 **Commit 每轮对每张证书都失败**（不写文档、不写状态、不写报告），而 Run 仍报 `written` | 先解析 groupSettings，再以 `min(maxNames, ProfileMaxNames(profile))` 分组的 SAN 上限（新增导出的 `config.ProfileMaxNames`），超限走 `overLimit`（保留上一版并写清原因）。`TestAGroupIsCappedByTheProfileItWillUse` |
| 4 | `internal/acme/manager_done.go` + `internal/deploy/tencent.go` | **从未被绑定的证书永远无法完成续期**：`download` 总把未绑定的 `DeployedCertID` 当 `UpdateCertificateInstance` 的 oldID，云端回 `FailedOperation.CertificateDeployInstanceEmpty`（真机实测，见 09-18 报告 §5.3），pass 失败 → 提升不执行 → 状态里的证书继续过期，每轮又签发并上传一张 | 新增 `deploy.ErrNothingBoundYet`：换绑失败后，若**新旧两张证书的绑定枚举都是「完整且为 0」**，这不是换绑失败而是「仍在等第一次手工绑定」——按首签处理（记录新 id、`DeployConfirmed=false`、再次提示绑定、不计失败）。**要求答案完整**是关键：部分枚举报 0 会把「某个 region 没读到」当成「没人绑定」，从而跳过一次必须的换绑。用例：`TestARenewalWithNothingBoundYetConvergesAsAFirstBind`（acme 侧收敛）+ `TestDeployReportsAPendingFirstBindInsteadOfAFailure`（deploy 侧，含「部分枚举不得当作无人绑定」的反例） |
| 5 | `internal/ratelimit/ratelimit.go`（`ParseRetryAfter`） | **CRITICAL 告警结构上不可能触发**：解析要求 CA 消息在时间点处**结束**，而 Boulder 会在后面追加 `: see https://letsencrypt.org/docs/rate-limits/#...` —— 真实拒绝串一律解析失败 → 从不记录 deadline → `wecert_ratelimit_blocked` 永远不为 1。原测试用的是自己编的无后缀消息，所以一直是绿的 | 截掉 `: see ` 之后的部分再解析；`TestParseRetryAfterAcceptsTheRealMessage` 用 Boulder 的完整真实串（含收尾链接）与带小数秒的变体，外加无后缀形式仍可用 |
| 6 | `internal/ratelimit/ratelimit.go`（`Spend`） | 从**未钳零上界**的补充值里扣：闲置两个月的 5 容量桶会存下 45.35 个 token，`Remaining` 又把显示钳到 5，于是「满了」这个读数在 CA 早已不允许的情况下还能撑过上百次消费 —— 与「估计只会往谨慎方向错」的包级承诺相反 | `math.Min(level(...), l.Capacity) - cost`；`TestSpendingAnIdleBucketStoresNoMoreThanCapacity` 同时钉住「闲置后一次消费存的是 4 不是 45」和「连续 5 次正好用尽、第 6 次读出 0」 |
| 7 | `internal/acme/dns.go` | DNS provider 的 HTTP 调用**没有超时**：lego 的默认值只在自己 `NewDefaultConfig()` 里有，而本仓库用结构体字面量构造，于是 tencentcloud 的 `ReqTimeout=0` → SDK 造出 `http.Client{Timeout: 0}`；`Present`/`CleanUp` 是**握着每个名字的租约互斥锁**去调它的，一条卡住的连接会把这个挑战名上所有证书一起钉死，pass 永不结束、TXT 留在 DNS；dnspod 分支不传 HTTPClient 也一样（回退到无超时的 `http.DefaultClient`） | 抽出 `tencentDNSConfig`/`dnspodConfig` 并显式设置 60s（与 `internal/deploy` 的另一个腾讯云客户端一致）；`TestDNSProviderConfigsBoundTheirAPICalls`（这两个字段无法从 provider 里读回，所以直接测构造出的 config） |
| 8 | `internal/acme/provider_*.go` + `internal/config/` | `-tags lego_dns` 的支持标志由 `internal/acme` 的 `init` 设置，而 `cmd/wecert-onboard` **不链接** acme —— 于是带 tag 编译的 onboard 会拒绝一份合法的 `dns.provider: lego` 配置，并让操作者「用你刚刚用过的 tag 重新编译」 | 标志改由 `internal/config` **自己的** build-tag 文件设置（`lego_registry_tags.go` / `lego_registry_notags.go`），与链接了哪些包无关；acme 的 init 移除。实测：默认构建拒绝并给出重建指令，`-tags lego_dns` 构建的 onboard 接受该配置（走到「no output path」）。`internal/config/lego_registry_{tags,notags}_test.go` 成对钉住 |
| 9 | `internal/webhook/webhook.go` | 全量触发把 `StartAll` 的 **nil** slice 直接赋给已经初始化为空切片的 `Accepted`，于是「什么都没接受」的响应回 `{"accepted": null}` —— 正是那条初始化注释要防的形状（具名触发分支用的是 append，所以只有这条路径回归） | 改 append；`TestFullTriggerWithNothingAcceptedSerializesAsEmptyArray`（假 reconciler 新增 `allBusy`，返回 nil accepted + 非空 skipped） |
| 10 | `cmd/preflight/main.go` | `-prune-certs` 丢掉 `DeleteCertificate` 的响应：`DeleteResult=false`（云端拒绝，无传输错误）被打印成 `deleted <id>` 且退出 0 —— 破坏性操作报了一个没发生的成功。`internal/deploy` 对同一个字段是检查的 | 新增 `deleteOutcome`（拒绝 / 无响应体 / 异步 task 都算「未确认」并计入失败）；`TestDeleteOutcomeReportsARefusal` 四个子例 |
| 11 | `cmd/preflight/main.go` | `DescribeCertificates` 的**空响应体**被读成 0，打印「OK - the account already holds 0 certificates」—— 没读到的答案被报成通过 | 新增 `certificateCount`：nil 响应 / nil Response / nil TotalCount 一律报错；`TestAnUnreadableCertificateCountIsNotZero` |
| 12 | `cmd/wecert-probe/main.go` | `-wait` 预算在第一次尝试前就用完时，`checkOne` 直接 `return lastCode`（零值 = exitOK）：`wecert-probe -host H -wait 1ns` 退出 0，一次都没拨号 —— 脚本最信任的那个「端点服务的是期望证书」是在没看的情况下给出的 | 第一次尝试永远执行（预算不足时给 250ms 下限），只有**重试**受剩余预算约束；`TestASpentWaitBudgetStillProbesOnce`，同时保住既有的 `TestWaitBoundsAnAttemptAlreadyInFlight`（文档 TC-PROBE-11/13/15 也是这个口径） |
| 13 | `cmd/clbverify/main.go` | ① `-raw` 在**任何断言之前**就 return，于是 `clbverify -raw -expect <id>` 打印完原始响应就退出 0，静默跳过断言；② 只校验 `SECRET_ID`，空的 `SECRET_KEY` 能过一个「消息里点名两个变量」的检查 | ① 抽出 `evaluateListener`（writer + refetch 可注入），`-raw` 只打印不再返回，`TestRawStillAsserts`（三个子例）；② 抽出 `missingCredential`，两半都要有 |
| 14 | `internal/reconcile/reconcile.go`、`internal/webhook/notify.go`、`cmd/tatrun/main.go` | ① panic 的 pass 不会发通知（`recover` 在 defer 里，通知调用在栈展开时不可达），而 panic 恰恰是最该被告知的失败；② notifier 用默认 HTTP 客户端**跟随 3xx**：301/302/303 会把签名 POST 变成无 body 的 GET 并把「事件丢了」记成投递成功，307/308 还会把带 `X-Wecert-Signature` 的 body 重发到重定向目标；③ tatrun 的失败任务输出没有 Base64 解码（用真机跑才发现的）、`timed out waiting for the TAT result` 在 production 里不可达（run() 的 ctx 截止总是先到，返回的是 SDK 原始的 context deadline exceeded） | ① panic 分支自己发通知（`TestAPanickingPassStillNotifies`）；② `CheckRedirect` 直接拒绝重定向（`TestANotifyRedirectIsNotADelivery`：目标没被访问、日志里没有 delivered）；③ 失败分支也解码（`TestAFailedTaskPrintsItsOutputDecoded`）+ `timeoutErr` 把两条截止路径都转成点名 invocation 的消息（`TestTheTATTimeoutMessageSurvivesTheContextDeadline`） |

### 2.2 核实后**驳回**的（不算缺陷，如实记录）

| 位置 | 复审说法 | 为什么不是缺陷 |
|---|---|---|
| `cmd/preflight/main.go` `confirm` | 「文档承诺『非交互 stdin 视为 no』但没实现」 | 已实现：`confirmFrom` 的 `sc.Scan()` 在空 stdin 上返回 false → 视为 no；`-yes` 是文档里的显式跳过开关。只有**回答了 y** 的管道才算授权，这正是文档那句话的意思 |
| `cmd/wecert-probe -json` | 「不是一份 JSON，而是每次尝试一行」 | `docs/test-cases.md` TC-PROBE-21 明确把 `-json -wait` 定义为 NDJSON（每次尝试一行），TC-PROBE-20 的单次尝试正好是一行 | 
| `internal/ratelimit` `ParseRetryAfter` 的其余宽松度 | — | 只接受两种固定布局、拒绝零时间，与「宁可漏报也不猜一个错误 deadline」的注释一致 |
| `internal/state/tx.go` 的注释 | 「注释说 fn 里读 store 看到事务前状态，实际会死锁」 | 属实但**无调用者**（可达性不成立），且属于文档措辞；不在本轮范围内，记在这里备查 |

### 2.3 复审自己确认「干净」的面（有证据，供后续参考）

- 订单 URL 在任何 CA 调用前落盘；通配符与 apex 共用一个 TXT 名的 write-all/wait-all/accept-all/cleanup-all；`replaces` 在两条续期路径上都带；ARI 的 `Retry-After` 钳位与 RFC 9773 §4.3.2 一致；证书配额记账的 scope 推导。
- `state`：`schemaTables`/`schemaColumns` 与全部 SQL 语句逐列对照；用旧版（`430211c`）建库后跑**每一个**导出方法（含 NULL `cert_pem`/`key_pem` 扫描）；`WithTx` 的全有全无；锁的获取/释放（含 nil）；umask 恢复；`VACUUM INTO` 的权限/保留/冲突命名；`COALESCE`/upsert 语义。
- `deploy`：Upload → UpdateCertificateInstance → 等待 → 验证绑定整条链及其每个错误分支（不泄漏已上传证书、不虚报 deployed、resume anchor 不丢）；凭据不落日志不落盘；CVM 角色路径。
- 并发/关闭：每证书 claim 与 backoff、webhook HTTP 面、probe 判定与指标。

### 2.4 本轮未修（留给后面 3 个小轮，逐条已核实）

| 位置 | 问题 | 计划 |
|---|---|---|
| `internal/onboarding/onboard.go` | 报告 JSON 落盘用 rename 但不 fsync（文档与状态都 fsync），崩溃后可能留下被截断的报告 | 落盘前 fsync |
| `internal/onboarding/onboard.go` | 同名的「无法解析的声明」被拒绝后，另一条同名记录解析成功并 included，报告里同一 hostname 同时出现 excluded 与 included | 让 included 覆盖早期的排除决定 |
| `internal/onboarding/onboard.go` | `build()` 用「被声明的通配符覆盖」改写 carry 原因，于是被 guard 拒掉这件事在报告里消失 | 保留 carry 原因并附上通配符说明 |
| `internal/webhook/webhook.go` | 超长请求体用 `io.LimitReader` 截断后按正常解析，应回 413 而不是静默截断 | 判定溢出并回 413 |
| `internal/webhook/webhook.go` | `/hook/status` 读状态库失败时按「没有这个证书」回答 | 区分「读不到」与「没有」 |
| `internal/acme/manager_flow.go` | `reclaimUnpresentedTXT` 把「权威否认」当成「写入从未发生」，但 DNSPod 的写入传播可以滞后（本轮实测删除传播到所有权威最多 60s） | 给授权行加「挑战准备时间」列，滞后窗口内不采信否认 |
| `internal/acme/manager_renew.go` | 任何 newOrder 限流拒绝都记到 `new-orders` 桶，exact-set 的拒绝会让那个「没有 override」的限额读数偏乐观 | 按 CA 消息分类到正确的限额 |
| `internal/acme/manager.go` | 授权状态 `expired`/`deactivated`/`revoked` 没有分支，按 pending 处理（重新呈现 + 等满 3 分钟） | 视为订单不可用并丢弃订单 |
| `internal/acme/manager.go` | `GetFallback` 读失败被当成「没有 fallback」，与同包 `fallback.go` 在同样失败下选择「保持」相反 | 读失败时保持上一版 |
| `internal/acme/manager.go` | `GetOrder` 失败裸返回，绕过 `recordFailure`（没有失败计数、没有 backoff） | 走 `recordFailure` |
| `deploy/prometheus/wecert-alerts.yml` | fallback 的 CRITICAL 告警 `{{ $value }}` 取的是 0/1 gauge，永远说「missing 1 name(s)」；且该 gauge 在**决定**时就被置位，而不是在降级证书真的上线后 | 注解取正确的序列；gauge 的置位时机另议 |
| `cmd/wecert-probe/main.go` | CLI 用 `probe.Probe`（第一个成功的地址）判定，而守护进程用 `ProbeAll`（多地址时一个旧证书就能藏住） | 决定语义后统一 |
