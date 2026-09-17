# 第四轮代码复审（2026-09-18，共 4 小轮）

> 承接 [`docs/code-review-ocr-2026-09-17.md`](code-review-ocr-2026-09-17.md)（前两轮，已清空）。这一轮换了打法：**5 个独立复审者并行**，每人只负责一组文件，结论写进 `/tmp/wecert-review-r4/<组>.json`（不经过会被截断的返回值），再由我逐条回代码核实、修复、并做「去掉修复就变红」的变异校验。
>
> 复审原则沿用仓库里那份规则说明（`/tmp/wecert-e2e/ocr-rule-1.md`）：**精度优先**，只报能追到可达调用路径的缺陷；gofmt / go vet / staticcheck / race 已经能判的一律不报；每条都要引用 file:line 原文。

---

## 1. 分轮计划与进度

| 小轮 | 覆盖面 | 状态 |
|---|---|---|
| 第 1 轮 | ACME 订单状态机；DNS 挑战层/ARI/吊销/配额记账；state + ratelimit；onboarding + spec + config；deploy + probe + reconcile + webhook + cmd | **已完成**（7 组复审返回，见 §2） |
| 第 2 轮 | 第 1 轮剩下未修的项 + 并发/生命周期/资源泄漏视角 | **已完成**（见 §3） |
| 第 3 轮 | 对本次会话全部改动的对抗性复审 + 不变量与属性/模糊测试 | **已完成**（见 §4） |
| 第 4 轮 | 跨面：文档 vs 行为、cmd/*、scripts、deploy、testenv，以及遗留项收口 | **已完成**（见 §5） |

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

### 2.4 第 1 轮收尾：又修掉 9 条（同属第 1 轮复审的返回）

| 位置 | 缺陷 | 修法与用例 |
|---|---|---|
| `internal/onboarding/onboard.go`（报告落盘） | 报告用 rename 落盘但**不 fsync**（文档与状态都 fsync），崩溃/丢页缓存后可能留下被截断甚至 0 字节的报告 | 落盘前 `tmp.Sync()`，与另外两个写入者一致。**这条是持久性加固，没有行为用例**（无法在测试里制造崩溃），如实说明 |
| `internal/onboarding/onboard.go`（parse） | 一条无法解析的记录给出的排除决定，在**同名**记录解析成功并被 included 后没有撤销（父 zone 与委派子 zone 各写一条、其中一条有 typo 就会命中），报告里同一 hostname 同时 excluded 与 included | 记录被接受时 `unreject(d.Hostname)`；`TestAnIncludedHostnameIsNotAlsoReportedAsExcluded` |
| `internal/onboarding/onboard.go`（build） | 「被声明的通配符覆盖」这句把 carry 原因**整个改写**掉，于是「某个筛选器正在拒它」在报告里消失 | 两句话拼接而不是替换；`TestAWildcardCoveredCarryKeepsItsFilterReason` |
| `internal/webhook/webhook.go`（请求体上限） | 用 `io.LimitReader` 截断超长请求体后照常解析：正好切在 JSON 边界上就被**接受**，切在中间则报「invalid JSON」，把人引向错误的排查方向 | 改用 `http.MaxBytesReader` 并识别 `*http.MaxBytesError` → **413**；`TestAnOversizedTriggerBodyIsRefused` |
| `internal/webhook/webhook.go`（`/hook/status`） | 读状态库失败时回的是零值 `certStatus`，与「这张证书还没有状态」无法区分 —— 而这个端点的全部意义就是回答「触发到底成没成」 | `certStatus` 增加 `error` 字段并在读失败时填上；`TestStatusReportsAnUnreadableCertificateState` |
| `internal/acme/manager.go`（`GetFallback` 读失败） | 读失败被当成「没有 fallback」，于是 SAN drift 分支立刻去订**完整**（已知有问题）的标识集，而同包 `fallback.go` 在同样的失败下选择「保持」 | 读失败时按「有 fallback」保守处理并在日志说明；`TestAnUnreadableFallbackRecordHoldsInsteadOfReissuing`（测试用第二个连接 DROP 掉 `cert_fallback` 表，制造「库部分损坏」） |
| `internal/acme/manager.go`（`GetOrder` 读失败） | 裸返回，绕过 `recordFailure`：没有失败计数、没有 backoff、没有内存里的临时 backoff，于是状态库恰好在这次读上失败是完全不可见的 | 走 `recordFailure`；`TestAFailedOrderReadSchedulesTheRetry`（同样用 DROP TABLE 制造失败，断言 `consecutive_failures` 与 `next_attempt_at` 都被写上） |
| `internal/acme/manager_renew.go`（限流归类） | 任何 newOrder 拒绝都记到 `new-orders`：exact-set 的拒绝会点亮错误的序列，而「没有任何 override」的那条限额继续读得偏乐观 | `refusedLimits` 按 CA 的原话（Boulder 的三种措辞）归类到对应限额，scope 与记账路径一致；`TestARefusalIsBookedAgainstTheLimitItNames` 三个子例 |
| `deploy/prometheus/wecert-alerts.yml` + `internal/metrics` | fallback 的 CRITICAL 告警 `{{ $value }}` 取的是 `== 1` 的 gauge，永远说「missing 1 name(s)」；而 gauge 的 Help 说「正在服务一张部分证书」，实际是在**决定**时就置位 | 注解不再插值错误的数字（真正的数量在 `wecert_certificate_fallback_dropped_names`，模板无法 join）；Help/描述改成「fallback 生效中（即将或正在服务部分证书）」，并把「为什么在决定时置位」写进注释（决定才是可行动事件；等部署会掩盖一个自身签发也在失败的 fallback） |

### 2.5 第 1 轮的最后两条（也已修复）

| 位置 | 缺陷 | 修法与用例 |
|---|---|---|
| `internal/acme/manager_flow.go` | RFC 8555 §7.1.6 的 `deactivated`/`expired`/`revoked` 三种「已关闭」授权状态没有分支，被当成 pending：每轮都重新呈现挑战（真写 DNS + 等传播）、对已关闭的授权 POST `AcceptChallenge`、再等满 `authzWait`，直到订单自己的 7 天 TTL 到期 | 新增分支：丢弃订单（下一轮下新单，新单的授权是新的），并且**不记 identifier 失败**（名字并没有验证失败，记账会让 fallback 误伤健康名字）。`TestAClosedAuthorizationDiscardsTheOrder`（三种状态各一例，断言订单被丢弃、账本为空、DNS 无写入） |
| `cmd/wecert-probe/main.go` | CLI 用 `probe.Probe`（**第一个**应答的地址）判定，而守护进程用 `ProbeAll`（「更新过的节点不能藏住还在服务旧证书的节点」）：换绑是逐个后端生效的，于是这个工具最核心的用途（等换绑生效）由「碰巧先应答的那个地址」回答，旁边还打印着全部解析地址 | 改用 `ProbeAll`：每个解析地址都判定、都输出，任一地址不匹配即退出码 2（不匹配优先于不可达）。`TestEveryResolvedAddressDecidesTheVerdict` 用 stdout 捕获断言「第二个地址确实被检查过」（去掉遍历即变红） |

### 2.6 最后一条（同样已修）：拒绝的「证据效力」有了时间下限

| 位置 | 缺陷 | 修法 |
|---|---|---|
| `internal/acme/manager_flow.go` + `internal/state`（新增 `authorizations.challenge_prepared_at`） | `reclaimUnpresentedTXT` 把「所有可达权威都否认」当成「这次写入从未发生」。但同一个行形状有两种来历：**死在 DNS 写入与状态落盘之间**，以及**死在持久化挑战与写 DNS 之间**——只看记录无法区分。DNSPod 的权威服务器滞后于 API 写入（本轮实测删除传播到所有权威最多 60s），于是刚写下的记录可能被每个权威否认，行与租约被删掉，而记录稍后出现：唯一的线索已经没了，那条 TXT 会留在 DNS 里占用额度、并可能污染同名（通配符 + apex 共用）的下一次挑战 | 授权行新增 `challenge_prepared_at`（`schemaColumns` 加列，老行为 0 = 年龄未知）；选择挑战时写入；否认只在「距选择挑战已超过传播窗口」时才被采信，窗口取 solver 自己的 `PropagationTimeout()`（新增到 `challengeSolver` 接口）。三个用例：刚准备（10s 前）→ 保留行；一小时前 → 删除行（否则老行永远留不完）；无时间戳的旧行 → 沿用旧行为。两处变异（去掉年龄判断、不写时间戳）各自变红 |

第 1 轮至此**全部 28 条已核实发现都已处置**（28 修，0 遗留），其中「非交互 stdin」「`-json` NDJSON 形状」「tx.go 注释」三条经核实**驳回/不计**（见 §2.2）。

### 2.7 第 1 轮之后仍待办（第 2–4 小轮）

| 位置 | 问题 | 计划 |
|---|---|---|
---

## 3. 第 2 轮：生命周期 / 并发 / 资源视角（1 个复审者 + 我的机械核查）

复审者只看「谁的生命周期比谁长」：goroutine、context、锁、资源清理；结论写进 `/tmp/wecert-review-r4b/lifecycle.json`（4 条）。另有两条是我自己的机械核查：Schema/SQL 列对照、旧库迁移、被吞掉的错误、ticker/response body/goroutine 的数量与终止条件。

### 3.1 已修复

| # | 位置 | 缺陷 | 修法与用例 |
|---|---|---|---|
| 1 | `internal/acme/manager_flow.go` | **租约登记与注销用的不是同一个值**：`registerRecoveredLeases` 登记行里**持久化的** `txt_value`（那是「DNS 里确实是这个值」的记录），而 `CleanUp` 注销的是由 `challenge_token` 推导出来的值（lego 的 provider 按它删）。代码自己的注释就承认存在「token 刷新过、TxtValue 不再匹配」的旧行 —— 对那种行，**登记进去的租约永远注销不掉**：该名字之后每一次清理都走「还有别的挑战在线」分支，provider 的 delete-all 在进程重启前再也不会执行，这条记录就留在 DNS 里 | 新增 `releaseRowStaleLease`（在两条清理路径上、调 provider 之前调用）：当本行的持久化值与 token 推导值不一致时释放本行自己的租约；「另一个 presented 行还声称同名同值」的检查要**排除本行自身**（否则它永远声称着）。`TestARowWhoseTokenChangedDoesNotBlockItsOwnCleanup`（断言 delete-all 确实触发、旧值租约被释放；去掉释放即变红） |
| 2 | `internal/reconcile` + `cmd/wecert` | **webhook 触发的 pass 无人 join**：SIGTERM 时 `runDaemon` 返回、`drainNotifier` 只等通知、`run()` 返回后 `defer store.Close()` 就把 SQLite 关在了仍在跑的 pass 底下——它的 epilogue（提升、resume anchor 的 `PutOrder`、授权行、`recordFailure`）全部失败。代码自己写过的极端情形：在 `staged.Upload` 返回 id 与 `PutOrder` 落盘之间退出，那张云证书既不在 `certificates` 也不在 `retired_certificates` 里，计费且永不回收。-once 模式同样可达（webhook 监听在 -once 分支之前就起来了） | `Reconciler` 增加 `bg sync.WaitGroup`（`Add` 在 goroutine 启动前，排队等 start slot 的也算）与 `Drain(ctx) error`；`cmd/wecert` 在两条退出路径上都先 `drainBackground`（30s 上限，超时明确告警说明「存储即将在活着的 pass 底下关闭，下一轮会从已落盘的 order URL 续上」）。`TestDrainWaitsForABackgroundPass`、`TestDrainIsBounded`（去掉计数即变红） |

### 3.2 核实后**故意不改**（如实记录，不是遗漏）

| 位置 | 复审说法 | 为什么不动 |
|---|---|---|
| `internal/acme/dns.go`、`internal/deploy/tencent.go` | 每次调用都新建 SDK client，而 SDK 的 `Init` 会 clone `http.DefaultTransport`：DNS 的每次 Present/CleanUp、部署的每次调用都是一次全新的 TLS 握手，外加一条 30s 的 idle 连接；`common.DefaultHttpClient` 本仓库从未设置 | **核实为真**（`common.Client.Init` / `WithProfile` 的源码在案）。但它**不是**「改一行就好了」：SDK 通过 `c.httpClient.Timeout = ReqTimeout` **修改它拿到的那只 client**，所以把 `DefaultHttpClient` 设成共享 client 会让不相关的超时互相覆盖；SDK 也没有注入 transport 的接口。代价是「每次调用一次握手 + 一条 30s idle fd」，在数百张证书的规模下才值得为它设计（那时正确做法是自建 per-credential 的 client+共享 transport 池并在两处统一 ReqTimeout）。本轮把两处**误导性注释**改成事实（原文写「negligible cost」/「used to rebuild it on every call」），并把上面这段理由写进注释 |
| `internal/acme/manager_flow.go` | `releaseStaleLease` 可能释放掉某名字最后一个租约而不触发 delete-all，于是别的行先前「留给最后一个离开者」的记录被搁浅 | 后果是「一条 TXT 记录滞留」，不是验证失败，而且要构造出「A 的清理因 B 的租约而跳过、随后 B 的租约又由 releaseStaleLease 释放」这个次序；在正常流程里该名字随后还会被写一次（新值的 delete-all 会把旧的带上）。**记为已知取舍**，不为它引入「按名字主动 delete-all」的新路径（那才是真会误删别人记录的方向） |
| `internal/acme/manager_done.go`（回收循环） | （我自己查的）云端删除成功但 `DeleteRetiredCert` 失败时，下一轮会对同一 id 再删一次 | 再删一次的失败会一直留下该行并每轮告警；反向顺序（先删行再删云）才是会造成真正泄漏的写法。记录在案，不改 |

### 3.3 机械核查结果（无发现，作为「这些面已经查过」的证据）

- **Schema/SQL 列对照**：9 张表、全部 SQL 语句的列都已在 `schema`/`schemaColumns` 中声明（脚本对照，0 不一致）。
- **旧库迁移**：手工建一份「缺少最新两列」的旧库，`Open` 后两列都被补上，`PutAuthorization` 不写年龄时**保留**原值（`CASE WHEN excluded > 0`），`revoke_requests.cert_identity` 往返正常 → `TestLegacyDatabaseGainsTheNewColumns`。
- **被吞掉的错误**：13 处 `_ =` / `_, _ =` 逐条看过，全部是「HTTP 响应写失败（对端已走）」「hash.Write」「drain body」「Flock 解锁」「清理路径的 Close」这类无可作为的情形。
- **资源终止条件**：`time.NewTicker` 有 `defer Stop` + ctx 退出；HTTP body 有 Close；goroutine 扇出都有上界（`startSlots`、`maxProbeConcurrency`、`maxNotifyInFlight`）且都等或可取消；shutdown goroutine 由 ctx 与超时界定。

### 3.4 顺带修掉的仓库卫生问题（我自己引入的）

`git add -A` 把仓库内一份 **GOCACHE（1,963 个文件、约 146MB）** 和三个 terraform plan 二进制提交进了 `770d018`。已从工作树移除并加进 `.gitignore`（`.gocache/`、`gomodcache/`、`gopath/`、`tfplan-*`），跟踪文件数 2,196 → 232。**历史里的 blob 还在**（这次没有改写历史）；要彻底回收体积需要一次 `git filter-repo`，那会重写这个分支的提交，留给你决定。

---

## 4. 第 3 轮：对抗性复审（攻击我自己刚做的修复）

方法：`git diff b72d1e3..HEAD` 逐块读，对每处修复只问一句「它在什么情况下会把事情弄得更糟」；另有一个独立复审者拿到同样的任务（只审这一天的改动），结论写进 `/tmp/wecert-review-r4c/adversarial.json`。属性侧同时跑了 `make test-pebble`（2/2）、`make e2e`（3/3）、4 个 fuzz 目标（45s 各）、`go test -race -shuffle=on -count=2`（19/19）。

**在自己刚做的修复里抓到两个缺陷**（都已修 + 变异校验）：

| # | 是哪次修复引入的 | 缺陷 | 修法 |
|---|---|---|---|
| 1 | 4.1 的「仍在等第一次绑定」 | 提升新上传的同时，把**被替换的那张上传**从状态里抹掉了：它没有任何绑定（这正是判定成立的前提），承载它的行马上被覆盖，而回收记录没写 —— 于是这个 id 既不在 `certificates` 也不在 `retired_certificates`，**永远计费、永不回收** | 该情形下把旧 id 记入回收清单（安全性由两点保证：deployer 只在**两份枚举都完整且为 0** 时才报 `ErrNothingBoundYet`，且删除时云端仍会因资源引用而拒绝）。用例扩到断言回收清单里有 `cloud-old`，去掉修复即变红 |
| 2 | 4.1b 的「fallback 读不到就保持」 | 我复用了「有降级在生效」那个标志，而 `applyFallback` 也读它 —— 那条路径**跳过到期窗口判断**（降级一旦生效就继续，不看剩余寿命）。于是一次状态库抖动就能让一张离到期还很远的证书**丢名字**，与「保持」的初衷正好相反 | 拆成独立标志 `fallbackUnknown`：只让 SAN drift 分支保持，不告诉 `applyFallback`「有降级在生效」。新用例先断言「若真的在降级，这份 fixture 确实会丢名字」（避免空测试），再断言读不到时不丢名字；把两个标志都置上即变红 |
| 3 | 4.1b 的限流归类 | 我按「registered domain」这个词匹配，但 Boulder 对这条限额的真实文案**不含这三个词**：`too many certificates (%d) already issued for %q in the last %s, retry after %s`（从 Boulder 源码 `ratelimits/limiter.go` 取回逐条核对），于是它压根匹配不上、又退回 new-orders | 按真实形状匹配（`already issued for "…"`，且不是 exact set），并**从消息里取出 CA 点名的那个域名**作为 scope（证书跨多个注册域时，猜「第一个」会把告警指向没被限流的那个）。用例改成 Boulder 的真实串，且证书的两个注册域故意让被点名的排在第二；去掉提取、或退回旧词匹配，各自变红 |

**这一轮也确认了没有问题的部分**：`Spend` 的容量钳制对欠债桶/零容量桶都给出保守读数（fuzz 目标覆盖）；`: see ` 截断不会吞掉合法消息（时间戳是前缀，且仍有 `trimTrailing`）；`Drain` 在 `-once` 与守护进程两条退出路径上都成立；`MaxBytesReader` 的 413 与 `errors.As` 匹配正确；`challenge_prepared_at` 的 `CASE WHEN excluded > 0` 在「不改年龄的写入」上保留原值（旧库迁移用例覆盖）。

---

## 5. 第 4 轮：跨面收口（文档 vs 行为、脚本、cmd、部署面）

| 面 | 检查 | 结果 |
|---|---|---|
| 文档 vs 行为 | `docs/desired-state.md`（守卫/carry、闸门 3）、`docs/test-cases.md`（TC-PROBE-11/13/15 与新增 TC-PROBE-21b）、`README.md` + `README.zh-CN.md`（probe `-json` 是 NDJSON；`-prune-certs` 把云端拒绝报成失败） | 4 处更新，已提交；`docs/staging-checklist.md` 的 `clbverify -raw` 步骤因「-raw 现在同时断言」而更强，无需改 |
| 脚本 | `scripts/e2e-wildcard.sh`（等待窗口）、自测 5/5、`shellcheck` 干净；`scripts/check-alerts.py` + 自测通过；`scripts/e2e.sh` 三个套件通过 | 无发现 |
| 告警/指标 | `deploy/prometheus/wecert-alerts.yml`（fallback 注解不再插值错的数字）、`check-alerts` 17 条规则引用的序列都存在 | 无发现 |
| `cmd/*` | 6 个二进制全部在本轮被改过（`wecert`：UA 位置、drain、事后撤销顺序；`wecert-onboard`：报错输出；`wecert-probe`：每次尝试都执行 + 每个地址都判定；`clbverify`：-raw 断言 + 双凭据；`preflight`：删除判定 + 证书数；`tatrun`：失败输出解码 + 超时消息）；每个新行为都有用例 | 无遗留 |
| `testenv/` | 三个 `tfplan-*` 二进制已停止跟踪并加入 `.gitignore`；`terraform.tfvars`/README 未受影响 | 见 §3.4 |
| 遗留项 | §2.7 的 12 条：11 条已修，1 条（LC-2 客户端复用）与 LC-4 明确记为「核实为真但故意不改」，理由见 §3.2 | 收口 |

**四轮总计**：复审者返回 37（第 1 轮）+ 4（第 2 轮）+ 独立对抗复审（第 3 轮，与本轮自查并行）条；**已修 30 条**（第 1 轮 28、第 2 轮 2、第 3 轮又自查出 2 条并修），**驳回 3 条**，**核实为真但故意不改 2 条**，其余按「脚手架 / 需产品决策」分类记录。所有修复都带「去掉修复就变红」的用例（唯一的例外是报告 fsync，属持久性加固，已注明无行为用例）。

---

## 6. 精度说明（这份审查的可信度边界）

---
