# 第四轮代码复审（2026-09-18，共 4 小轮 + 1 小轮补做）

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
| 第 5 轮（补做） | 只审 4.2/4.3 与今天这批修复本身（两个独立复审者：一个只攻击 diff，一个只跑代码） | **已完成**（见 §6） |

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

第 1 轮至此**全部 26 条已核实发现都已处置**（26 修，0 遗留：§2.1 的 14 + §2.4 的 9 + §2.5 的 2 + §2.6 的 1），另有 4 条经核实**驳回/不计**（见 §2.2）。

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

**五轮总计（按本文各表逐条计数）**：已修 **42 条** —— 第 1 轮 26 条（§2.1 的 14 + §2.4 的 9 + §2.5 的 2 + §2.6 的 1）、第 2 轮 2 条（§3.1）、第 3 轮 3 条（§4，其中 2 条是那批修复**自己引入**的）、第 5 轮 11 条（§6.1，其中 4 条是修复自己引入的：第 1、2 条属这一轮，第 5、6 条推翻了 4.2 与这一轮的修复）；**驳回/不计 4 条**（§2.2），外加第 5 轮复审者独立提出、核实后不成立的 8 项（§6.3 的表）；**核实为真但故意不改 3 条**（§3.2）。复审者返回的条数与「已修」条数**本来就不相等**：返回里混着同一缺陷的重复描述、追不到可达调用路径的猜测（不计），以及属于脚手架 `testenv/` 而不属于产品的观察。所有修复都带「去掉修复就变红」的用例（唯一的例外是报告 fsync 与第 4 条那处日志文案，已注明无行为用例）。

---

## 6. 第 5 小轮（补做）：两个独立复审者，一轮只攻击修复、一轮只跑代码

第 3 轮的对抗复审只覆盖 `b72d1e3..HEAD` 那道 diff，而 4.2（`c49ff31`）、4.3（`ed88a4b`）两个提交是它之后才落的；今天这批修复（重写 `manager_test.go` 时带掉的用例、挑战行落盘次序、onboarding 记录次序、提示文案）也没有经过任何独立复审者。于是补一轮，方法与第 3 轮相同——**只问一句「这处修复在什么情况下会把事情弄得更糟」**——但这次派了两个人，并要求结论落到磁盘（`/tmp/wecert-r5/*.json`）而不是返回值：一个**只攻击修复**（读 diff 与代码），一个**只跑代码**（自己写用例观察行为，不看结论）。这一轮抓到 7 条新缺陷，其中 2 条推翻了**我自己前两轮的修复**。

### 6.1 复核出的 11 条（其中 4 条是我自己引入的）

第 1–4 条来自**第一批**（我自己的复查 + 一个对抗复审者）；第 5–11 条来自**两个独立复审者**：一个只攻击这批修复（结论写进 `/tmp/wecert-r5/adversarial.json`），一个只**跑代码**做行为验证（不读结论，写进 `/tmp/wecert-r5/behaviour.json`，17 项检查 / 5 项未验证）。第 5、6 条推翻的是**我自己这两轮的修复**。

| # | 位置 | 缺陷 | 修法与用例 |
|---|---|---|---|
| 1 | `internal/acme/manager_test.go` | **我在 4.3（`ed88a4b`）重写这个文件时把 4.1b 刚加的用例删掉了**：`TestAFailedOrderReadSchedulesTheRetry` 守的是 4.1 的修复「状态库读订单行失败必须走 `recordFailure`」（否则该 pass 在 `wecert_certificate_consecutive_failures` 里不可见、且按 pass 频率立刻重试）。用例没了，修复就成了没人守的代码（`git log -S` 可查：`48e7490` 加入，`ed88a4b` 删除） | 用例按原样补回（`dropTable(orders)` 造出读失败，断言 `ConsecutiveFailures` 与 `NextAttemptAt` 都非零）。变异校验：把 `m.recordFailure(...)` 改回裸 `fmt.Errorf`，两条断言同时变红 |
| 2 | `internal/acme/manager_flow.go` | 挑战行与**刷新后的 `challenge_prepared_at`** 只在「首次访问」那条路径上先落盘；**续做路径**（行里有旧 token、`Presented=false`）要等到循环末尾那次 `PutAuthorization` 才写盘。中间崩溃时，磁盘上留下的年龄**比写入还老**——而 4.1d 刚定的规则是「权威否认只有在写入经过传播窗口之后才算证据」，于是回收探针会去信一个针对**仍在传播**的记录的否认，删掉行却把 TXT 留在 DNS 里 | 年龄必须在 DNS 写入**之前**落盘，但**能落到盘上的只有年龄**（见第 5 条：这一版最初写成「无条件连新 token 一起写」，被对抗复审推翻，终版按访问类型分开——首次访问可以连新 token 一起写，续做路径只写年龄、token 等写入成功后的末尾那次落盘再改）。用例 `TestTheChallengeIsPersistedBeforeTheDNSWrite`（`onPresent` 钩子在 `Present` 被调用的一瞬间读库）与 `TestAFailedWriteOnTheRevisitPathKeepsTheTokenThatNamesTheRecord`（见第 5 条） |
| 3 | `internal/onboarding/onboard.go` | 4.1 给「被包含的名字不能同时被报成排除」加的 `unreject` **依赖记录次序**：域名区遍历先返回哪条记录不由我们决定。坏记录在前、好记录在后时 `unreject` 生效；**好记录在前**时，后面那条无法解析的记录又无条件 `reject` 一次，报告对同一个名字给出两个相反结论（`included=true` 与 `included=false` 并存） | 无法解析的分支先看 `byHost`：该名字已经有可用声明时不再写排除结论（与 `unreject` 互为镜像）。用例改成**两个次序都跑**。变异校验：把守卫去掉，`order broken-first=true`（好记录在前）那轮变红，红出的正是两条矛盾结论 |
| 4 | `internal/acme/manager_done.go` | 4.1 新写的提示文案说「bind **either** certificate once in the CLB console」，但在同一轮里「等第一次绑定」已被实现为「提升新证书 + 把被替换的那张放进回收清单」：照提示去绑旧的那张，程序跟踪的那行仍然是未绑定 → 下一轮再次判定「无人绑定」→ 再上传第三张、再烧一次签发额度 | 文案改为只指本次上传的那张（并点名 `certId` 字段），同时写清旧的那张会被回收、换绑之后自动进行。**这条是日志文案，没有行为用例**（没有任何用例断言提示字符串），如实说明。对抗复审者独立核了文案里的三处事实（旧证书确实进了回收清单、云端在仍有引用时确实拒绝删除、按提示绑定后确实会自动换绑），未推翻 |
| 5 | `internal/acme/manager_flow.go` | **第 2 条的第一版把「年龄先落盘」做成了「无条件连新 token 一起先落盘」，这会在另一条路径上丢线索**：一行只存一个 token，而 `reclaimUnpresentedTXT` 正是靠它推导出要探测的 TXT 值。续做路径上若 CA 给出了不同的挑战（代码自己承认这个形状存在，`releaseStaleLease`/`releaseRowStaleLease` 就是为它写的），而这次写入**失败**（一次普通的 DNSPod 报错，不需要崩溃），盘上的 token 已经变成新的：恢复时按新值探测 → 被权威否认 → 删行，而 DNS 里那条旧记录从此没有任何东西指向它 | 终版：续做路径只把**年龄**落盘（token/URL 保持旧值），写入成功后的末尾那次落盘才换 token；首次访问没有旧记录可言，仍连新 token 一起先落盘。用例 `TestAFailedWriteOnTheRevisitPathKeepsTheTokenThatNamesTheRecord`（拒绝写入的 provider + 权威只提供旧值；断言盘上 token 仍是 `tok-1`、年龄已刷新、恢复时 delete-all 确实触发）。两处变异各自变红：改回「无条件写新 token」→ 行名变成 `tok-2`、`delete-all ran 0 times`；去掉续做路径的年龄落盘 → 年龄仍是 30 分钟前的旧值 |
| 6 | `internal/reconcile/reconcile.go` | **4.2 的 `Drain` 有两个真缺陷（都是我自己引入的）**：(a) `startCert` 的 `bg.Add(1)` 与 `Drain` 的 `bg.Wait()` 并发——`sync.WaitGroup` 明确要求「从零开始的 Add 必须发生在 Wait 之前」，实测可复现进程级 panic `sync: WaitGroup is reused before previous Wait has returned`（`-race` 下每次都报 DATA RACE）；生产路径真实存在：HTTP server 的 `Shutdown` 是异步的，触发器可以在 `Drain` 期间到达。(b) 同一个竞态还让 `Drain` 返回**之后**才启动的 pass 照常运行（`select` 两个 case 同时就绪时随机选），其状态写入全部落在已关闭的库上（`sql: database is closed`）——正是 `Drain` 要防的那种丢失 | 新增 `bgMu` + `draining`：`beginPass()` 在同一把锁下判断并 `Add`，`Drain` 先在锁内把 `draining` 置位再 `Wait`；`StartAll`/`StartNamed`/`StartCert` 在 draining 后以新哨兵 `ErrShuttingDown` 拒绝（不能报成 `ErrAlreadyRunning`——那会让调用方以为「已经在跑、等着就行」），webhook 的两条错误日志也改成如实说明「状态读不到**或**进程正在退出」。用例 `TestAPassStartedAfterDrainIsRefused`、`TestAShutdownRefusalIsNotReportedAsAlreadyRunning`、`TestStartingAPassDoesNotRaceWithDrain`（40 轮 StartAll×Drain 对撞）。变异校验：把 `draining` 判断改成恒假，拒绝用例立刻报「no pass may run after Drain returned, these did: [a]」，对撞用例三次全部 `WARNING: DATA RACE` |
| 7 | `internal/onboarding/onboard.go` | 两个复审者各自独立复现：**同一个 hostname 会出现 2–3 条排除结论**。冲突之后再写第三条记录 → 冲突那条 + 「repeats a hostname already rejected」那条；同一个名字在两个 zone 各写一条坏记录（都没有可用声明）→ 2–3 条一模一样的「unparseable declaration」 | `reject` 变成**每个 hostname 只记第一条**（第一条就是原因），冲突之后那条分支不再补记（只拒收），并新增 `include()` 统一处理「包含」结论（先 `unreject` 再追加）。用例 `TestOneVerdictPerHostname`（6 个子例：冲突+第三条、坏+好+坏、好/坏两种次序、只有坏记录 2 条、只有坏记录 3 条）；把 `reject` 改回「一律追加」→ 后两个子例分别报 2 条和 3 条 |
| 8 | `internal/onboarding/onboard.go` | 同一个 DNS 名字、两种拼写、两个相反结论：`hostnameFromRecord` 只去掉**一个**尾点、也不做 `group.Normalize`，而 `ParseDeclaration` 是 `Normalize` 过的。于是 `_wecert.api.example.com..`（多一个点）或带多余空格的名字，会被报成 `api.example.com.` 排除 + `api.example.com` 包含 | `hostnameFromRecord` 按 `ParseDeclaration` 的方式规范化（`group.Normalize`，失败时退回去前缀的字符串）。用例 `TestOneVerdictPerHostname` 的两个「非规范拼写」子例；去掉规范化 → 两个子例都报出 `api.example.com.` 的排除条目 |
| 9 | `internal/onboarding/onboard.go` | 第 3 条的守卫把「矛盾」换成了「静默丢弃」：一条无法解析的记录若同名已有可用声明，就**什么决定都不留**，而 `parse()` 的文档注释还写着「无法解析的记录会留下一条决定」——`Decisions` 是运维唯一会读的产物，于是一个写错的 `wildcard=maybe` 就这样消失了 | 决定列表仍然只留一条（不能自相矛盾），但**日志里点名**：记录名、zone、hostname 与解析错误。用例 `TestAnIgnoredBrokenRecordIsNamedInTheJournal`（harness 现在把日志收进 buffer 供断言），并同步改掉文档注释 |
| 10 | `internal/onboarding/onboard_test.go` | 第 3 条那个「两个次序都跑」的用例，失败信息里的 `order[0].Record == broken.Record` **恒为真**（两条记录的 Record 字符串相同，区别在 Zone），所以明明是「好记录在前」那轮失败，却打印 `broken-first=true`——一个会把人带偏的诊断 | 改成比较 Zone。复审者验证：改回字符串比较后，失败轮被标成 `broken-first=true`，而实际是 good-first |
| 11 | `internal/reconcile/reconcile.go` | `reconcileOne` 上方的文档注释被复制成两遍（`...into metrics// reconcileOne processes...`），是某次脚本编辑留下的残骸 | 去重（纯注释） |


### 6.2 这一轮的机械核查

- **用例清单不缩水**：`git show HEAD:<file> | grep -c '^func Test'` 与工作树逐文件对照，函数总数 765 → 773，**只有新增、无删除**（新增的正是第 1、2 条与第 5–9 条那几条）。这条核查是因为第 1 条缺陷（静默删用例）才加的，之后每轮都会跑。
- **8 处变异校验亲自复跑**（在 `/tmp` 的副本里改，绝不动工作树）：每处都先确认变异**能编译**且确实把修复改回去了，再看失败输出，而不是只看 `grep`。8 处全部变红且失败信息指向缺陷本身（只有第 4 条是日志文案，无变异可做）。其中 2 处是**推翻我自己上一次修复**的（第 5、6 条）。
- **顺手清掉机械恢复留下的垃圾**：上一轮用脚本补回被误删的 `solver.newProvider` 赋值时，在新用例里留下了**一处死赋值**和一处多余空行（gofmt 不会报）；`reconcileOne` 上方的注释还被复制成两遍（第 11 条）。都已清掉并按全量门禁重跑。
- **没有「不断言」的用例**：脚本按大括号配对取出全部 `Test*` 的函数体，筛「体内既没有 `t.Error/Fatal/Fail/Skip` 也没有 `t.Run`」的，只有 1 个命中：`TestReclaimSkipsAProberWithoutHostEnumeration` —— 它的断言就是「不 panic」（类型断言若写成非 comma-ok 形式，这个用例会以 panic 失败），属误报。作为「测试不是在自我安慰」的证据记录。

### 6.3 独立复审者的结论

两个复审者用了**不同的方法**，这一点比他们的结论更重要：一个只读代码与 diff、假设每处修复都错（对抗型），一个只跑代码、自己写用例去观察真实行为（行为型，`17 项检查`）。两人的交集是第 7 条（重复结论），说明这类「报告产物的一致性」缺陷是读代码就能看见的；而第 5、6 条只有动手构造场景才会暴露——**只读结论的复审者两轮都没发现它们**。

**他们独立提出的、我核实后不成立的（驳回项）**——这些同样是这一轮的产出，记下来是为了说明哪些面真的查过了：

| 面 | 复审说法 | 为什么不是缺陷 |
|---|---|---|
| `ratelimit.Spend` 的容量钳制 | 超出容量的结余、`cost > capacity`、负 cost 三种输入下行为可疑 | 行为验证者自己写表驱动用例跑过：结余**丢弃**（不是结转）、`cost > capacity` 把欠债夹在 `-capacity`（保守方向）、欠债会继续背、负 cost 不会被当成 credit。最初两条「失败」是**复审者自己的算术错**，不是产品缺陷 |
| `ParseRetryAfter` 的严格度 | 提示里的 `2026-09-18T05:00:00Z` 形状解析不出来 | Boulder 的 `Decision.Result` 用的是 `Format("2006-01-02 15:04:05 MST")`，那个形状**不是** CA 会发的；四种真实措辞（含/不含 `: see <url>`）都精确解析，空串、垃圾、零时刻都返回 `(zero,false)`，不 panic、不落零窗口。**[1m,24h] 的钳制不在这个解析结果上**（它按原样保存），而在 RFC 9773 §4.3.2 的 ARI 区间上，实现于 `manager_renew.go:224-229`，30s→1m、25h→24h、服务端给的 2h **不会**被我们 6h 的下限拉长——这一条我此前在文档里说得含糊，已按实测改正 |
| 状态库迁移 | 旧库（缺列）打开后是否丢数据 | 行为验证者用 `6172439^` 的真实旧 schema 建库、每张表都放一行，`Open` 后两列补齐、数据无损、部分迁移可用、拿不到锁时拒绝并且**不碰文件** |
| `CASE WHEN excluded > 0` 的 upsert | 不知道新列的写入者会不会把值抹掉 | 不会：挑战年龄与 CA 截止时间在「不写该列」的更新里保留，写入者知道时替换，只有显式清除才清空 |
| `releaseRowStaleLease` / `releaseStaleLeaseExcept` | 会不会放掉还活着的租约 | 不会：排除自身那行的逻辑成立，别的证书在同一名字上的声明仍然保住租约，读库失败时**保留**租约（保守方向） |
| 落盘次序（第 2、5 条的终版） | 是否真的做到「写 DNS 时盘上已有本次挑战」 | 用同一个 `onPresent` 钩子对两条路径、多标识符订单逐点验证：`Present` 被调用时盘上的行已经是本次挑战、`Presented=false`、年龄是新的；反向次序观察不到 |
| `Drain` 的核心契约（修好第 6 条之后） | 是否真的等到 pass 及其状态写入结束 | 会：等在飞的 pass（含它那次 `PutCert`）、等等待期间启动的 pass、并发 `Drain` 都能返回且不会 double close |
| 第 4 条那处提示文案的三条事实 | 旧证书是否真进回收清单、云端是否真会拒绝删除仍被引用的证书、按提示绑定后是否真会自动换绑 | 三条都成立（回收清单由同一事务写入；`Delete` 带 `IsCheckResource=true` 并等异步任务，任何非成功状态都保留回收记录；`Noop.Delete` 会拒绝而不是假装成功）。没有找到「照提示做反而被卡住」的序列 |
| 第 3 条的守卫键 | `hostnameFromRecord` 与 `ParseDeclaration` 的 Hostname 会不会对不上 | 对 DNSPod lister 能产出的 11 种形状逐一比对，全部一致；只有「记录名不带 `_wecert.` 前缀」这种会被 lister 过滤掉的形状才可能不一致 |

**他们明确无法验证的（与我自己的清单合并，见 §7）**：云端对 `IsCheckResource` 的真实执行与真实删除任务状态、CA 是否真的会在同一个授权 URL 上换挑战（第 5 条的前提）、DNSPod 是否会返回非规范记录名（第 8 条的前提）、在「落盘」与「写 DNS」之间注入真实崩溃、线上 LE 429 的真实文案、以及第 6 条那个窗口在生产里出现的频率（需要放大并发才复现）。

### 6.4 本小轮的门禁

两批改动（`6d2eb98` 与第 5–11 条那一批）各跑一遍完整门禁：`gofmt -l .` 干净；`go vet ./...` 与 `go vet -tags "pebble lego_dns" ./...` 干净；`staticcheck ./...` 干净；`python3 scripts/check-english.py` 182 个源文件通过；`go test -race -count=1 ./...` **19/19 包通过**；`make check`、`make test-pebble`（2/2）、`make e2e`（3/3）通过；`scripts/test-e2e-wildcard.sh` 5/5；抖动/次序门禁 `make test-repeat`（`-race -shuffle=on -count=3`）**19/19 包通过**；`6d2eb98` 已推送且 CI 在 `test/e2e-tlsserver-renewal`（PR #67）上 **success**，第二批同样推送后复核 CI。

---

## 7. 精度说明（这份审查的可信度边界）

这份文档只声称它真的做到的事，下面把边界写清楚：

- **缺陷的判定标准**：必须能追到一条可达调用路径，并给出具体场景；追不到的一律不计（§2.2 的第 4 条就是这种：注释与实现不符属实，但没有调用者）。gofmt / vet / staticcheck / `-race` 已经能判的东西不重复报。
- **「每条修复都有会变红的用例」的含义与边界**：它证明这条用例对**这处**修复敏感（去掉修复就红，已逐条实测），**不证明**用例覆盖了该修复的所有回归路径，也不证明没有别的地方还在依赖旧行为。第 5 轮那 8 条变异是我在 `/tmp` 的副本里亲自复跑的（先确认变异能编译、确实改回了旧代码，再看失败输出），不是只看 `grep`。反过来说：**这一轮最值钱的两条缺陷（§6.1 第 5、6 条）恰恰是「用例全绿」时被复审者用新场景打出来的** —— 用例绿只说明它守的那条路径没坏。
- **工具能证明什么**：`-race` 只覆盖测试里**实际发生**过的交错，不是「无竞态」的证明（§6.1 第 6 条的竞态就是靠一个 40 轮对撞的用例才每次都报出来的，单跑一次并不保证）；4 个 fuzz 目标各跑 45s，不是跑到饱和；`staticcheck`/`vet` 只能判它们看得见的模式。ACME 订单状态机没有做模型检查或形式化验证 —— 它的正确性来自用例、pebble 集成测试与真机 e2e 的观察。
- **复审者的独立性有限，但方法差异有效**：第 1/2/3/5 轮的复审者是同一模型族的不同实例，共享同样的盲区（例如都可能在腾讯云 API 文档过时、DNSPod 免费额度行为这类**外部事实**上判断错）。这一轮把「读代码」和「跑代码」分成两个人之后，两个只读型的复审（第 3 轮与第 5 轮的对抗者）都没有发现 `Drain` 的 WaitGroup 误用，只有动手构造场景的那一个发现了 —— 说明**换方法比换复审者更值钱**。真机 e2e 是唯一能证伪外部事实盲区的手段，而它只覆盖了跑过的那些路径。
- **本轮明确未跑 / 未验证**（不是「应该没问题」，是**没验证**；与 `docs/e2e-run-2026-09-18-credentialed.md` 第 6 节一致）：
  1. 真实时间流逝下的自然续期（真机跑的是把续期窗口推到当下的等价做法）—— **未跑**；
  2. 生产（非 staging）Let's Encrypt 的配额与签发行为、以及线上 429 的真实文案（全程 staging，另加本地 pebble；`ParseRetryAfter` 的四种措辞是照 Boulder 源码核对的，不是线上抓的）—— **未跑**；
  3. 「归档副本也没了」的吊销报错分支 —— **真机未跑**，单元层面由 `TestAReplacementIsNeverRevokedInPlaceOfTheRequestedCertificate` 覆盖（`ListRetiredCertMaterial` 只返回 `cert_pem IS NOT NULL` 的行，所以「保留期已回收」与「行里没有材料」落到同一条错误分支：请求保持未决、`last_error` 写明只能在 CA 侧吊销）；
  4. 「枚举超时 / 未覆盖全部 region」的部署哨兵分支 —— **真机未跑**，仅单元测试（本轮换绑走的是 adopted task + 恢复判定）；
  5. Stage C「首绑 → 自动换绑」在 CVM/systemd 上的重跑（09-18 那轮只在 Stage B 用同一条 `UpdateCertificateInstance` 路径复核了换绑，CVM 侧只跑到「首签上传 + 提示手工绑定」）；
  6. 监听器关闭 SNI 的路径（本账号无法关闭 SNI）；
  7. 云端对 `IsCheckResource=true` 的真实执行与真实删除任务状态（单元与 seam 测试覆盖了状态 4 的处理，真机没构造过「证书仍被引用时删除」）；
  8. CA 是否真的会在**同一个授权 URL** 上换挑战（§6.1 第 5 条的前提：代码自己承认这个形状存在，但真机上没观察到）、以及 DNSPod 是否会返回非规范记录名（第 8 条的前提）；
  9. 在「落盘」与「写 DNS」之间注入**真实崩溃**（第 2、5 条的时间窗是用测试钩子观测的，不是真崩溃）；
  10. §6.1 第 6 条那个 `Add`/`Wait` 窗口在生产里出现的频率（要靠放大并发才复现，真实触发概率未知——但代价是进程级 panic，所以按「会发生」处理）；
  11. LC-2（SDK client 复用）与 LC-4（最后一个租约的 delete-all）—— 核实为真但**故意不改**，理由见 §3.2。
- **本文与代码的对应**：每条「已修」都对应一次提交（`770d018`、`48e7490`、`41b55cf`、`0f61177`、`9d9b12e`、`c49ff31`、`ed88a4b`，以及第 5 轮的两批：`6d2eb98` 与 §6.1 第 5–11 条那一批）；改动只在 `internal/`、`cmd/`、`scripts/`、`deploy/` 与 `docs/` 内，`testenv/` 只被顺带清理（那是你的测试脚手架，不是产品）。

---
