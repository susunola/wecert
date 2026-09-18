# 第七至十轮代码复审（2026-09-18，共 4 轮）

> 承接 [`docs/code-review-round4-2026-09-18.md`](code-review-round4-2026-09-18.md)（第 1–5 小轮，42 条）与 [`docs/code-review-round6-2026-09-18.md`](code-review-round6-2026-09-18.md)（第 6 轮，16 条）。第 6 轮之后先把它**故意没做**的 9 项做完（提交 `0497d14`），再按四个**互不相同的视角**继续复审：故障注入、协议一致性、性质/模糊测试、以及对自己修复的对抗性攻击。

每一轮的规矩不变：复审者的结论先落到磁盘（`/tmp/wecert-r7*/**`、`/tmp/wecert-r8*/**`），我再逐条回代码核实；**驳回的也写下来**（连同反证）；真缺陷修掉并配「去掉修复就变红」的用例（变异校验）；全量门禁跑绿；每轮提交并推送、CI success。

---

## 0. 第 6 轮遗留项的收尾（`0497d14`）

| 项 | 结果 |
|---|---|
| 每注册域名的配额序列只发布第一张证书的 scope | `PublishQuota` 改为「一个家族 → 全部 scope」（`map[string][]string`），按解析出的期望状态发布每个注册域名、每个标识符集合、每个标识符；用例 `TestEveryScopeInAFamilyIsPublished`、`TestQuotaPublishingCoversEveryManagedScope` |
| 三处重复的「临时文件→fsync→chmod→rename」 | 抽成 `internal/atomicfile`（外加**目录 fsync**，让 rename 本身也能挺过断电），报告/文档/onboarding 状态文件与快照安装都改用它 |
| statePath 符号链接、状态目录 0777 | 改为**警告而不拒绝**（两者都是合法运维做法）：`statePathWarnings`，用例 `TestStatePathHazardsAreWarnedAboutNotRefused` |
| 探测地址数没有上限 | 超过 32 个地址即判「无法验证」而**不是抽样**（每个地址都必须判定；上限防止一个名字吃掉整轮预算），用例 `TestTooManyAddressesIsRefusedRatherThanSampled` |
| 可删的死导出 API | 删掉 `RefillPerSecond`、`WorstCaseBlockedBy`、`Describe`、`Summarize`、`ClearRateBucketReset`、`ListRateBuckets`、`SetLegoProviderSupport` 及其专属用例；**保留** `UpdateCert`、`PutRateBucket`、`Verdict.Summary` 等（它们是测试观测缝或生产调用，第 6 轮那份移除清单本身有错——`GetKeyAuthorization` 在生产里被调 3 次） |
| `lego_dns` 的 CI 门禁（推不了 workflow） | 改为放进 CI 本来就会跑的 `make release`（额外编译 linux/amd64 的 lego_dns 变体），并新增 `make test-tags`（`-race -tags "pebble lego_dns"` + 同 tag 的 vet），已接入 `make check` |
| 文档遗留漂移 | 测试清单重算（633/60/18 → 787/76/19，含分包数量）、Roadmap 的 5 项「Outstanding」全部已交付（改为说明真正的未验证项）、状态表补齐 9 张表（原先只列 5 张）含新增两列、`/hook/desired` 说明决定来自文档而非实时评估 |

---

## 1. 第 7 轮：故障注入（3 个复审者，各管一类故障）

**方法**：复审者被要求**真的注入故障**，不许只讲道理：SQLite 触发器让某一类写入失败、第二个连接 DROP 表/列、删掉 `-wal`、进程在流程的六个点被 kill、FIFO/符号链接/不可删除的文件、以及时钟前后跳。无法注入的必须明说。

返回：磁盘类 10 条（6 驳回）、数据库/崩溃类 4 条、时间/网络/上下文类 6 条（2 驳回）。**核实后修掉 13 条**，驳回 1 条并给出反证。

### 1.1 已修（medium）

| # | 位置 | 缺陷 | 修法与用例 |
|---|---|---|---|
| 1 | `internal/spec/document.go`、`internal/onboarding/state.go` | **FIFO 会让读取方永远阻塞**：`open(2)` 打开一个没有写端的 FIFO 会一直等，于是「必须是普通文件」的检查**永远到不了**。把 FIFO 放在 `desiredState.path`，enforce 模式的 daemon 会卡在 `newProvider` 里——**在 metrics/webhook/快照启动之前**，而 `Type=simple` 的 unit 不会重启一个还活着的进程；onboarding 的状态文件同理，而它此时已经握着跨进程锁，后面每一轮都排在它后面 | 两处打开都加 `O_NONBLOCK`（对普通文件无副作用），随后既有的 regular-file 检查即可生效；状态文件另外拒绝符号链接（Save 会用 rename 替换链接，读时跟随会让两个文件对宽限期各说各话）。用例 `TestAFIFOAtTheDocumentPathIsRefusedNotOpened`、`TestAFIFOAtTheStatePathIsRefusedNotOpened`（5s 超时即判失败） |
| 2 | `internal/deploy/tencent.go`（7 处调用点） | **关机被记成业务失败**：腾讯云 SDK 把传输层错误**重新包装**成全新的 `*TencentCloudSDKError`（不 Unwrap），所以被取消的调用在上游看起来是普通 API 错误，`recordFailure` 那条「被停掉的 pass 不算业务失败」的规则看不到 `context.Canceled`：证书白白得到一个失败计数、`last_error` 和退避 | 新增 `sdkCallError`：**上下文是「这次调用为什么停下」的权威**，先看 `ctx.Err()`，再把 SDK 错误原样保留（活着的上下文里它就是真失败，调用方要靠它分类）。用例 `TestACancelledSDKCallCarriesTheContextError` |
| 3 | `internal/acme/manager_done.go` | **真正的 CA 超时被当成「pass 被取消」**：`recordFailure` 用 `errors.Is(err, context.Canceled/DeadlineExceeded)` 判断，而 `net/http` 会把自己的请求超时包进 `*url.Error`，其 `Unwrap` 正是 `context.DeadlineExceeded`——于是 CA 侧超时（最常见的失败）被记成取消：没有 `consecutive_failures`、没有 `last_error`、没有退避，首次签发甚至连一行证书状态都不落 | `recordFailure` 改为收 pass 的 `context`，判断 `ctx.Err() != nil`：**规则说的是「这个 pass 被停了」，不是「这个错误包着什么」**。用例 `TestAnInnerTimeoutIsRecordedAsAFailure`（两个方向都断言）、既有的 `TestACancelledPassDoesNotSetABackoff` 仍绿 |
| 4 | `internal/acme/manager_done.go` | **续期锚点写入失败会泄漏一张已上传的云证书**：`orders.deployment_cert_id` 写不进去时，订单无法命名这张上传件，提升也不会发生——于是这个 id 只活在一行日志里：不在 `certificates`、不在 `retired_certificates`，`ReapRetired` 永远看不到它，却一直占账号的上传证书配额，而下一轮还会再传一张 | 落不进锚点就把它放进**回收清单**（安全：这张副本从未被绑定过——本该切到它的部署没跑；而且删除时云端仍会因资源引用而拒绝）。用例 `TestAnUnrecordableResumeAnchorLeavesTheUploadReclaimable`（触发器只拒绝那一条 UPDATE），变异校验：去掉回收即红 |
| 5 | `internal/state/state.go` | **`state.db-wal` 被删掉是静默的**：WAL 模式下的已提交事务都在 `-wal` 里，直到 checkpoint 才并回主库；干净关闭会同时删掉两个 sidecar。因此「有 `-shm` 没有 `-wal`」是「wal 被人删了」（清理脚本匹配 `*-wal`、运维手动、或者恶意的 rm）的指纹：下一次 `Open` 一声不吭，而上次 pass 写下的订单 URL 已经没了——下一轮只好重新下单，又花一次 exact-set 额度 | 新增 `walMissing`/`missingWALWarning`：`Open` 时发现这个指纹就打印警告并指向 `docs/recovery.md`。用例 `TestAMissingWriteAheadLogIsReported`（三种组合都断言） |
| 6 | `internal/acme/manager.go` | **读证书状态失败没有排重试**：`Reconcile` 开头那次 `GetCert` 裸返回，与它自己三行之上的文档注释矛盾，也与第 4 轮修掉的订单行/fallback 两处读同一类 | 走 `recordFailure`（用一个新的同名 `CertState` 记失败：存储坏了时计数写不进去，能留下的是内存里的临时退避，这正是让 pass 频率不变成重试频率的东西）。用例 `TestAnUnreadableCertificateStateSchedulesTheRetry` |

### 1.2 已修（low）

| # | 位置 | 缺陷 | 修法与用例 |
|---|---|---|---|
| 7 | `internal/acme/dns.go` | 取消输给了预算：`waitZone` 先查超时预算、后查 `ctx.Done()`，于是落在最后一轮探测里的取消会变成「传播超时」——上游于是 `markResumedUnpresented` 改写授权行、`recordFailure` 记一次业务失败，与两条明文规则都相反 | 先查 `ctx.Err()` 再查预算 |
| 8 | `internal/acme/manager.go` | **时钟回跳会让绑定检查彻底停摆**：`now.Sub(last) < 6h` 在 `last` 来自未来时是负数，而负数「小于间隔」——实测时钟回跳后跨 48 小时的三轮 pass 里绑定查询次数为 **0**，`DeployConfirmed` 永远是 false，而 `probeCert` 对未确认部署的证书直接早退，于是**网络探测也不跑**。现在「存下来的时间在未来」= 立刻到期。用例 `TestABackwardClockStepDoesNotSilenceTheBindingCheck` |
| 9 | `internal/state/backup.go` | **保留策略被一个删不掉的快照永久卡住**：`pruneSnapshots` 在第一次 `os.Remove` 失败时就返回，于是运维给快照加了不可删除属性（`chattr +i`、ACL——勒索软件加固的常规做法）之后，备份目录每个间隔长一个文件，每轮都对着同一个最旧的名字报错 | 逐个尝试、错误用 `errors.Join` 合并；测试用 `removeSnapshotFile` 这个缝注入「一个删不掉」。用例 `TestPruningAttemptsEveryVictim` |
| 10 | `internal/state/backup.go` | 快照必须**先建临时文件再删掉**（`VACUUM INTO` 拒绝已存在的路径），于是在「允许创建、不允许删除」的目录里快照**永远写不出来**，每次还留一个 0 字节 `.snapshot-*.tmp` 没人清理 | 名字改为**挑一个不存在的**（`freeTempName`，stat 循环，不再创建），并按年龄清扫中断留下的 `.snapshot-*.tmp`（1 小时，远长于任何一次快照）。用例 `TestStaleSnapshotTempsAreSweptAndFreshOnesKept` |
| 11 | `internal/state/backup.go` | **未来时间戳的快照永远删不掉**：名字按墙钟，向前的时钟偏移（NTP 校正、从时钟走快的机器恢复的虚拟机）会写出排在所有诚实时间戳**之后**的名字，而保留策略保留最新的名字——于是它永久占一个名额（keep=3 实测只剩 2 个真恢复点） | `repairFutureDatedSnapshots`：这类文件**改名**而不是删除（内容没问题），改成它实际的写入时间（mtime，若 mtime 也在未来则用现在）。用例 `TestAFutureDatedSnapshotIsAgedRatherThanKeptForever` |
| 12 | `internal/atomicfile`、`internal/state` | 写入侧的符号链接与权限问题：`rename` 替换的是**名字**，所以通过符号链接写入会毁掉链接、让目标文件停在旧内容；`Install` 在 rename 之前 `chmod`，而 `chmod` 跟随符号链接（会把无关文件的权限改掉，并把链接本身装成目标） | `Write` 拒绝符号链接目标；`Install` 在 chmod 前做 `Lstat` 并要求普通文件。用例 `TestWriteRefusesASymlinkedTarget`、`TestInstallRefusesANonRegularTemporaryFile` |
| 13 | `internal/state/state.go` | 状态目录被删/数据库被替换是**完全静默**的：SQLite 写的是它打开的那个 inode，所以 `rm -rf` 之后每次写入都成功、每次读取都成功，而下次启动什么都没有；`Close` 也曾经能在事务还在提交时返回（事务在 `Close` 返回、锁也释放之后才落盘） | 新增 `Store.VerifyOnDisk()`（数据库是否还是那个文件 + 锁文件是否还是我们持有的那个），每轮 pass 开头报一次；`Close` 先取 `s.mu`，等事务结束再关。用例 `TestVerifyOnDiskNoticesADeletedOrReplacedDatabaseAndALostLock`、`TestCloseWaitsForAnInFlightTransaction` |

### 1.3 驳回（有反证）

| 复审说法 | 反证 |
|---|---|
| `deployRecordGrace` 的墙钟算错：时钟 +20s 会让未完成的部署任务在**第一次轮询**就被判成「旧证书没有任何绑定」 | 生产里 `now: time.Now`（`tencent.go:117`），字段不导出、只有测试通过 `newTestDeployer(clock.now)` 注入。`time.Now()` 带单调读数，`Add`/`After`/`Sub` 在两个操作数都带单调读数时走单调时钟，**墙钟跳变动不了这个比较**。复审者的注入走的是测试缝（没有单调读数），是测试夹具的产物，不是生产行为。记为驳回而不是「修」 |

### 1.4 复审者另外核过、确认没问题的（作为「这些面查过了」的证据）

- 崩溃重启：在签发流程的**六个点**真杀进程（下单后、写 TXT 后、AcceptChallenge 后、finalize 后、锚点写失败后、提升提交后）——全部收敛（`newOrder` 调用数 0、证书被记录、28872 字节 WAL 被恢复）；两个标识符之间崩溃留下一行完整 + 一行只有 token，下一轮回收正确。
- 事务：epilogue 在触发器拒绝与事务中途 `DROP TABLE` 下都是全有全无（锚点存活）；半途迁移可收敛（9 张表、0 待补、旧数据完好）；关闭后的 store 报可读的错误、不 panic、可重复 Close；外来写锁 → `SQLITE_BUSY` 后完整恢复；取消的 ctx 不会卡住连接。
- 快照：三种保留边界（keep≤0、keep=1、旧式命名）、VACUUM INTO 中途失败不留残骸、目录消失/被替换。
- 时钟：限额桶两个方向（不向后发币、锚点不回退、前跳只补到容量、欠债只还一次、CA 的截止时间是绝对时刻）；onboarding 的宽限期与预算在两个方向都偏保守；DNS 判定（NXDOMAIN=否认、SERVFAIL=不可达、第二个陈旧权威不覆盖）。
- 网络：`FetchRenewalInfo` 在非 200 时**没有**丢 `Retry-After`（实测 503 + `Retry-After: 3600` → 1h0m0s，响应体关闭）；notifier 的 `Drain` 会等、能扛住被取消的 pass ctx、有界、拒绝 Drain 之后的投递。

---

## 2. 第 8 轮：协议一致性 / 配额经济学 / 性质与模糊测试（3 个复审者）

**方法**：一个复审者逐条把代码对着 RFC 原文核（并要求引用章节号）；一个只打**配额经济学与状态机不变量**（要求给出「这一下花掉多少额度」的数字）；一个**生成输入**而不是读代码（自己写 fuzz/property target，各跑 30–150 秒）。返回：协议 8 条（9 驳回）、配额 9 条（7 驳回）、性质 5 条（全是 low、10 个新 target）。**核实后修掉 15 条**，驳回 1 条（有反证），其余记为已知取舍。

### 2.1 已修（high）

| 位置 | 缺陷 | 修法与用例 |
|---|---|---|
| `internal/config/config.go` | **含 IP 字面量的证书永远签不出来**：`validateDomain` 接受 IPv4 字面量，lego 会把它提升为 RFC 8738 的 `ip` 标识符，CA 于是只提供 tls-alpn-01/http-01，DNS-01 选择器找不到挑战 —— **整张证书**（连同其它 SAN）每一轮都失败，错误信息指向挑战类型而不是文档里那行字。裸公共后缀（`co.uk`）与单标签同理（没有可验证的上级） | 在**写入文档的地方**就拒绝：IP 字面量、以及「自己就是公共后缀」的名字（`publicsuffix.PublicSuffix` 直接判，因为 `internal/group` 反向依赖本包，不能引）。用例 `TestIdentifiersThatCannotBeIssuedAreRejected`（5 个反例 + 4 个正例，含通配符与 punycode） |

### 2.2 已修（medium）

| # | 位置 | 缺陷 | 修法与用例 |
|---|---|---|---|
| 1 | `internal/acme/manager_renew.go` | **CA 自己给的截止时间没人看**：桶只被写、被发布成指标，然后被忽略——「retry after 3h」之后我们按自己的 1m..6h 退避又发了 **8 次** newOrder（实测窗口内 8 次）。每一次都是 CA 已经说过不可能成功的请求，而在按标识符记的限额上它们还要花掉整个账号共用的预算 | 下单前先查已记录的截止时间：账号级（new-orders）直接停这一轮，按 scope 记的只停**它点名的那张证书**（因为一个域名被暂停就拒掉整个机群会停摆）。用例 `TestARecordedDeadlineStopsTheOrderBeforeItIsPlaced`（账号级 + 按域名级 + 「另一个注册域名不受影响」） |
| 2 | `internal/acme/manager_renew.go` | **429 的 `Retry-After` 头从未被读**：lego 把它放在类型化错误上（`RateLimitedError.RetryAfter`），而代码只解析错误**文本**——CA 只发头、不在文本里重复时刻时（协议允许：头是答案，散文是注释），就完全没记截止时间；而且紧接着还会发出「去掉 replaces 再试一次」的那次重试，正好落在 CA 刚说的窗口里 | 新增 `ParseRetryAfterHeader`（秒数与 HTTP-date 两种形式）与 `Tracker.NoteDeadline`（非文本来源的截止时间）；记录的截止时间同时意味着「现在不要重试」。用例 `TestTheRetryAfterHeaderIsHonouredAndNotRetriedInto` |
| 3 | `internal/acme/manager_renew.go` | **Boulder 的第四条 newOrder 限额**（`too many failed authorizations (5) for %q …`）没有归类，于是截止时间被记在账号级的 new-orders 桶上，而真正被暂停的那个标识符序列仍然显示「还剩 5」——告警把运维指向整个账号 | `refusedLimits` 认出 `failed authorizations`，`newOrderRefusalScope` 优先用消息里点名的那个域名（与注册域名限额同一规则）。用例 `TestTheFailedAuthorizationRefusalIsBookedOnTheIdentifier` |
| 4 | `internal/acme/manager.go` | **冷却只在进程内**：它保护的预算（`rate_buckets`）是持久化的，但重启不会重新武装——实测同一进程 +3m 被挡住，重启后同一个 +3m 又花掉一个 token。多张证书共用一个名字时，每轮重启一次就能花光 5/小时的预算 | 冷却可以从持久账本（`identifier_failures.last_failed_at`）重新播种；读不到账本时不猜（当作没有冷却） |
| 5 | `internal/acme/manager_flow.go` | **一次 pass 只登记第一个失效授权**：实测 [a,b,c] 里 a、b 都被 CA 判失效，账本只记了 a；降级轮于是下单 **[b,c]**（仍然含 CA 拒绝的 b），两张坏名字的证书永远降不到能签出来的程度 | 初次抓取与轮询两处都改成「先把这一轮看到的**全部**失效授权登记完，再让这一轮失败」。用例覆盖两处（并修掉了一个我自己引入的回归：把返回放在「pending 为空就提前返回」之后，会让一张既有用例变成 120 秒超时） |

### 2.3 已修（low）

- **ARI 不再为已过期证书发请求**（RFC 9773 §4.3 MUST NOT）：过期证书没有可续的东西，而一个失败数月的机群成员会在它一直留在期望状态期间被一直轮询。用例 `TestAnExpiredCertificateDoesNotAskTheCAForARI`。
- **ARI 的长期/临时错误不再混为一谈**（§4.3.3）：404 是长期（CA 根本不认识这张证书），此时服务器给的短 `Retry-After` 会让轮询变成「每分钟问一次，问一辈子」；现在 404 走自己的 6 小时下限（新增 `ErrRenewalInfoLongTerm`）。同时 `start == end` 的空窗口（§4.2 不允许）会留下一条 WARN，而不是无声回退。
- **`probe -expect-san` 的规范化不再依赖调用次数**：先 trim 空格、再去一个尾点的写法不是幂等的，`www.example.com..` 会在两次规范化后变成两个不同的键，于是同一个名字既出现在「缺失」里又出现在「多余」里（自相矛盾的判定 + 退出码 2）。改为循环到稳定。用例 `TestExpectSANNormalisationIsIdempotent`。
- **限额桶不会被非有限值毒化**：`Spend` 会清洗负 cost，但不挡 NaN/±Inf，一个这样的值会让 `Tokens` 永远是 NaN（所有比较为假，欠债钳制失效）。现在直接拒绝并告警（今天四个调用方都传字面量 1，正因如此守卫要放在函数里而不是注释里）。
- **空证书 id 不能再进回收清单**：这种行 `ReapRetired` 永远删不掉（`Delete("")` 每轮失败），槽位被永久占住——与回收清单的目的正好相反。用例 `TestARetiredRowWithNoCertificateIdIsRefused`。
- **「估算的界」方向写反了**：包文档与 `Remaining` 说「下限 / 至少还剩这么多」，而只统计自己花掉的量得到的是**上限**（别的账号花了就只会更少）。README 在第 6 轮改过，包文档没有；现在两处都写「最多还剩这么多」，并说明为什么方向重要。
- **下单日志说真话**：`replaces=true` 记录的是「我们请求了什么」，lego 在目录不声明 renewalInfo 时会把这个字段丢掉；字段改名为 `replacesRequested`，历史真机报告里引用的旧日志加了一行说明。

### 2.4 驳回 / 记为已知取舍

| 复审说法 | 处理 |
|---|---|
| ARI 的 `[1m,24h]` 钳制违反 RFC | **驳回**：§4.3.2 明确允许客户端对窗口做合理钳制，而代码正是这么做的（复审者自己也纠正了他给的章节号：badNonce 是 §6.5.1、rateLimited 是 §6.6/§6.7、DNS-01 是 §8.4） |
| 订单/授权轮询忽略 `Retry-After` | **记为限制**：lego 的 `ExtendedOrder` 没有这个字段（它自己的 `pollInterval` 3s 恰好等于 Boulder 给 processing 订单的 3s，所以对 LE 无影响）。要修得先让 lego 暴露它，记入待办 |
| `DomainKey` 用逗号连接且不校验成员：一个 SAN 里含逗号的证书（`"a.example.com,b.example.com"`）能让 `CoverageDrift` 误判「没有漂移」 | **记为限制**：需要 CA 签发这种 SAN（公共 CA 不会），而且 `VerifyCoverage` 用的是集合而不是拼接键、能看见。记入待办（改为长度前缀或结构化比较） |
| 「失效授权登记」这条修复会不会让 pass 在该失败时不失败 | **驳回**：登记完仍然在 `pending` 为空之前 `recordFailure`，行为与之前一致（而且我自己先写错过一次，被 120 秒的用例逮住） |
| 第五个限额（连续授权失败导致**标识符暂停**，1152、每天回 1、成功即清零）没有建模 | **记为缺口**：要建模需要「成功即清零」的语义，现有桶没有；运维的出路是 CA 的 unpause 门户。已写入报告而不是半实现 |
| 降级集合一旦生效，即使原因消失也只能等到续期窗口/改配置才恢复（WARN 文案承诺的「证据过期后重试完整集合」不成立） | **记为缺口**：改动涉及 hold 的设计；本轮只把文案与事实对齐的评估留到第 9 轮文档审计 |

### 2.5 复审者另外跑过的性质测试（「这些面查过了」，但不是证明）

声明解析器（60s / 416 万次执行，含 `hostnameFromRecord == Hostname` 与幂等性）、`parse()` 的「每个名字一个结论 + 与记录次序无关」（77s）、`validateDomain`（42s / 630 万次 + 归一化不动点）、`CertName` 单射与分组稳定性、`LoadDocument`（77s：加载即校验、写读往返、十亿笑声/深层嵌套/重复键/非 UTF-8 全部拒绝、16.77MB 合法文档 1.2s 读完）、限额桶序列（62+46+45+45s，最多 2900 万次，含「时钟回拨不发币」与冻结时钟的守恒）、`tcerr`（2×30s）、probe 判定（不变性/单调性）、状态库 120 组随机操作序列（每步断言不变量 + 重开后 9 张表逐字节一致）+ 62s fuzz、reconciler 决策属性（153s：不 due 不下单、失败必排重试、收缩必有 fallback 记录、不超 profile 上限）。

---

## 3. 第 9 轮：运维面 + 文档（2 个复审者）

**方法**：一个复审者只走**运维真正会碰的东西**（systemd unit、install.sh、cloud-init、告警规则、runbook、CLI 契约），并要求能跑的就跑（`systemd-analyze verify`/`security`、容器里真跑 unit、真跑 install.sh、`bash -n`/`shellcheck`）；一个只做**文档 vs 行为**，范围是第 6 轮之后改动的约 40 处行为（第 6 轮审计过的那 36 处不再重复）。

### 3.1 已修（HIGH：定时器模式下指标告警根本不可能响）

`wecert-once.timer` 模式下 `/metrics` 只在**一次 pass 的时长内**存在（`cmd/wecert/main.go:252` 起，`:261-274` 就返回），而 17 条规则里 13 条带 `for:`（5 分钟到 24 小时）——**它们永远不可能满足 `for`**，另外 4 条也只有恰好在那段时间里被抓到才算数。而 README 把 `/metrics` 说成两种模式通用的告警路径，定时器的退出码只覆盖「这一轮没收敛」：`probe_match==0`、未决吊销、限额封禁、孤儿证书、文档冻结全都看不见。

**修法**：README 明确写出这个限制（「指标只在守护进程活着的时候存在；要让那 17 条规则有意义就得跑守护进程，或者定时器 + push gateway」）。

### 3.2 已修（medium：告警规则本身不可能完成它的工作）

| # | 缺陷 | 修法 |
|---|---|---|
| 1 | 三条到期规则是按 profile 写的，而指标只有 `cert` 一个标签 —— 一张 shortlived（160 小时）证书在它**整个生命周期**里都会触发 22.5 天与 11.25 天两条告警 | 指标加 `profile` 标签（发布处按证书 profile，空值回落 classic），三条规则各自选择自己的 profile；顺带修掉 `DeleteCertSeries` —— 它用单值删除，在新标签下会 panic（`DeleteLabelValues` 的值个数必须等于标签个数），而「证书移除后序列被回收」这条既有用例正好抓住了它 |
| 2 | `increase(probe_errors_total[1h]) > 3` **不可能达到**：每个主机每次 pass 只加 1，pass 每小时一次 —— 于是「这是环境问题不是证书问题」的告警永远不响，响的是一条 CRITICAL 的「服务的不是部署的那张证书」，正好是这两个指标存在的意义所在 | 窗口改为 6 小时 |
| 3 | `remaining < 5` 恰好等于两条限额的容量（exact-set 5/7 天、identifier 5/小时），于是每次签发之后大约一天半里这条 warning 一直是亮的 | 阈值改为 1 token |
| 4 | `HasNotReconciledRecently` 没有 `> 0` 守卫：`last_reconcile` 是普通 gauge、从 0 开始，于是**每次进程启动半小时后**就会告警「两小时没有完成过一轮」 | 加 `> 0` 守卫 |

### 3.3 已修（install.sh 与 runbook）

- **只装了 `wecert`**，而随仓库分发的 onboarding 定时器执行的是 `wecert-onboard` —— 每个 tick 都是 203/EXEC（对期望状态文档来说是静默失效）。现在从 wecert 同目录安装它，找不到就明确说明哪个 unit 起不来。
- **镜像里没有 `file(1)` 时**：`set -e` 下脚本以 127 退出，而且下一行把「工具缺失」误报成「不是 Linux ELF」。现在先检查命令是否存在并说清楚。
- **找不到 unit 文件时**：先打印 error，然后照样打印「Installation complete」并以 0 退出。现在以非 0 退出。
- **`WECERT_STATE_DIR` 与 unit 沙箱不兼容**（`StateDirectory=wecert` + `ProtectSystem=strict`，没有 `ReadWritePaths`）：现在会明确警告「需要给 unit 加 ReadWritePaths」。
- `wecert-onboard -h` 退出码从 1 改为 **64**（与 probe/preflight 一致；1 在这个仓库的文档里是「程序跑了但失败」）。
- `docs/staging-checklist.md` 第 1.1 步（`-once`）与本清单「守护进程在跑」的前提冲突（状态库有锁，会被拒绝），并补上 `sudo -u wecert`。
- `docs/desired-state.md` 的 reload unit 用 `${WEBHOOK_TOKEN}` 却没有任何 `Environment=`：systemd 把未定义变量展开成空串 → 401，而 `curl -sf` 让这个 unit 看起来只是「没触发」。现在给出 `EnvironmentFile` 的正确写法。
- `README.md` 的 `-dry-run` 说法收敛为事实：它在构造 DNS provider 与 deployer **之前**就返回，所以不会验证 DNSPod token 或 CAM 凭据。
- 新行为补文档：探测的 32 地址上限、（第 7 轮加的）状态文件符号链接/可写目录警告。

### 3.4 已修（HIGH：文档把 ARI 豁免规则说错了，而这是「通配符优先」的论据）

四份 README 与生命周期页面都写「ARI 豁免要求 identifier 集合**不变**」。Let's Encrypt 的实际规则是「与被替换证书**至少共享一个标识符**」（`at least one identifier matching the certificate it intends to replace`）；代码从 `b88b910` 起就是按真实规则做的（SAN drift 分支照发 `replaces`），它自己的注释还引用了官方措辞，而 `TestDriftReissueWithAnOverlappingSetKeepsTheExemption` 一直在钉这个行为。**文档说的比代码严**，代价是运维会以为「加一个域名必然花掉 50/7 天额度」。已按真实规则改正 5 处文档 + 1 处日志措辞。

其余已修文档：中文 README 对（第 6 轮只改了英文）的 `statePath` 默认值、限额外负担方向、Roadmap 五项、CAM 权限两项、状态表；英文参考文档里 `identifier_failures` 写了不存在的列（`first_seen`/`last_seen`，是第 6 轮自己引入的）；10 处 grep 仍在找第 8 轮改名的 `replaces=true`（其中一处是**否定断言**，改名后它会空转通过）；`recovery.md` 没有第 7 轮新加的「WAL 被删」警告所指向的内容；测试清单与 `make check` 描述过期。

---

## 4. 第 10 轮：对抗自己 + 新眼睛（2 个复审者）

**方法**：一个只攻击第 7/8 轮与第 6 轮收尾的**修复本身**（要求对每处修复给出反例或「我试过，它顶住了」的证据）；一个**全新视角**看从没被指派过的面（`internal/metrics`、`tcerr`、`group`、`spec` 的冷路径、测试辅助函数），并**重测早先的驳回**——驳回是「这不是缺陷」的断言，最弱的那几条用真实复现再打一遍。

### 4.1 已修

| 严重度 | 位置 | 缺陷 | 修法 |
|---|---|---|---|
| medium | `internal/acme/manager_renew.go` | **第 8 轮的回归**：拒绝 scope 的提取只认 `already issued for %q`，于是 Boulder 的 failed-authorization 措辞落到「证书的第一个域名」上。第 8 轮让这个截止时间**开始生效**之后，它就变成双向的可用性 bug：含被暂停名字的那张证书不被拦，而恰好共享第一个域名的**无关证书**被拦 | 改为取消息里**第一个被引号括起来的名字**（两条 Boulder 措辞都满足），并加用例把三种形状钉住（点名 b、点名注册域名、什么都没点名时的回落） |
| medium | `internal/reconcile/reconcile.go` | **panic 容器不是容器**：deferred 处理器自己在里面调 `notifier.Renewal`，从这条路径再 panic 就没有任何 handler 了；实测 panic 逃逸、`Reconcile` 少跑一张证书，而在 webhook 路径上那是裸 goroutine，会**杀掉进程**。同一次运行还让同一个 pass 同时计入 `ok` 与 `error` | 通知走自己的 recover（`notifyPanicSafe`）；计数只在 switch 没跑过时才补记（`accounted` 标志） |
| low | `internal/reconcile/reconcile.go` | 部署**只是未确认**时也会回收该主机的探测序列（`probeCert` 对未确认部署故意早退），于是每个续期周期序列都会闪烁一次；如果换绑最终失败，`probe_match==0` 那条文档化告警赖以触发的序列已经没了 —— 对它要抓的失败保持沉默 | 证书仍在期望状态、只是 `DeployConfirmed=false` 时保留序列（拿不到期望状态时也保留；只有「确实不再被探测」才回收）。用例 `TestAnUnconfirmedDeploymentKeepsItsProbeSeries` |
| low | `internal/state/tx.go` | 文档说「fn 内通过 store 读取会看到事务前状态」——**假的**：那会永久阻塞在不可重入的 `s.mu` 上（ctx 也救不了），随后连 `Close` 都冻住。两个生产调用方都干净，所以今天不可达，但这句话会骗到下一个维护者 | 注释改为陈述真实行为（会死锁，必须通过 `Tx` 读） |

### 4.2 复审者重测后确认「仍然成立」的驳回（这些面的可信度因此提高）

preflight 的 `confirm`（空/出错的 stdin 都算 no，且闸门在删除循环之前）、`solveChallenges` 的 16 个错误返回全部走 `recordFailure`、probe 期望语义与两个调用方一致、`replaces` 空值不会上线（lego 的 `omitempty` + 目录门控）、`probe` 的 `NotAfter` 秒级精度往返无损、`pruneSnapshots` 的 protect、`HasRecoverableState`、token 先于锁定、7 处 `sdkCallError`、`onboarding.New` 的校验、`PublishQuota` 的新签名、`make test-tags`、`make release` 里的 lego_dns、`atomicfile.SyncDir`。

### 4.3 驳回与已知取舍（本轮）

| 复审说法 | 处理 |
|---|---|
| IP/PSL 校验会不会拒掉合法名字（私有后缀、punycode、通配符、`ca.test`） | **驳回**：仓库里所有 fixture 与脚本用的名字都通过；单标签名字被拒，但 `dns.go` 的 SOA 走查本来就会拒掉「托管区正好停在公共后缀」的情况，是闭环。唯一遗留是措辞（消息说「no certificate authority」，对私有 CA 不准确） |
| `AddRetiredCert("")` 的守卫只在 store 上、`Tx.AddRetiredCert` 没有 | **接受为遗留**：两个入口都应带守卫，记入待办 |
| `orphaned_certificates` 是单向 gauge（行按设计保留） | **记入文档**：指标 Help 与 README 说明「行会被保留、这个 gauge 不是瞬时状态」 |
| 探测部分地址失败时 `probe_match=0` 且 `probe_errors` 增加（行为有意，契约写反） | **修文档**：metric Help 与 README 说明「0 也可能是环境问题，配合 probe_errors 看」 |
| `WithTx` 内读 store 会死锁（上一轮记为「仅措辞」） | **上一轮的驳回被削弱**：可达性那半仍然成立（无调用方），但注释已按真实行为改写（见 4.1） |

---

## 5. 四轮合计与门禁

| 轮次 | 视角 | 复审者返回 | 核实后已修 |
|---|---|---|---|
| 第 7 轮 | 故障注入（磁盘 / 数据库与崩溃 / 时间·网络·上下文） | 20 条（10+4+6） | **13**（1 medium×6、low×7），驳回 1（`deployRecordGrace` 的墙钟算术，有反证） |
| 第 8 轮 | 协议一致性 / 配额经济学 / 性质与模糊测试 | 22 条（8+9+5） | **15**（high×1、medium×6、low×8），驳回 1、记为缺口/限制 4 |
| 第 9 轮 | 运维面 / 文档 vs 行为 | 51 条（15+36） | **约 30**（high×5、medium×8，其余为低价值但会导致误操作的陈旧描述） |
| 第 10 轮 | 对抗自己 + 新眼睛 + 重测驳回 | 6 条 | **4**（medium×2、low×2），并把上一轮的一条驳回降级为「真实行为比文档更糟」 |

四轮的门禁每一项都跑过并绿：`gofmt -l .`、`go vet ./...`、`go vet -tags "pebble lego_dns" ./...`、`staticcheck ./...`、`python3 scripts/check-english.py`（188 个源文件）、`python3 scripts/check-alerts.py`（17 条规则引用的序列都存在）、`python3 scripts/check-cam-policies.py`（10 个 API 都被三份策略覆盖）、`go test -race ./...` **20/20 包**、`make check`（含 `test-tags`）、`make test-pebble`（2/2）、`make e2e`（3/3）。提交：`a607998`、`3a0fabd`、`0f7acf5`、`c0a2156`（前一个 `0497d14` 是第 6 轮遗留项收尾），每个都已推送且 CI success。

## 6. 精度说明（这四轮的可信度边界）

- **驳回也要有证据**：这一轮序列里共有 30 余条「不是缺陷」的结论被写下来（含反证），并且第 10 轮专门派人**重测**其中推理最弱的几条——重测改变了一条（`WithTx` 的注释：可达性那半成立，但真实失败是死锁而不是「读到旧值」）。
- **抓到的最值钱的东西是「修复自己的回归」**：第 8 轮的截止时间消费让一条早已存在的 scope 提取缺陷开始咬人（第 10 轮抓到）；第 8 轮给指标加标签又暴露了 `DeleteCertSeries` 的单值删除（既有用例抓到）。两处都说明：**修复会把沉睡的缺陷激活**，所以每一轮都要回头打自己。
- **仍然未验证**（与前面各轮合并，不再重复列举）：真机生产 LE、自然到期续期、云端对 `IsCheckResource` 的真实执行、真实断电/掉页、CA 是否真的会在同一 authz URL 上换挑战、DNSPod 是否真的返回非规范记录名、`-tags lego_dns` 的 CI 门禁（token 推不了 workflow，已用 `make release` 与 `make test-tags` 覆盖）、`docs/certificate-lifecycle*.html` 里的若干陈旧陈述（那两张页面由 `make diagrams` 从中文源生成，本轮没有重新生成）。
- **两处刻意留给后续**：第五个 CA 限额（连续授权失败导致标识符暂停）没有建模；降级集合的「证据过期后自动重试完整集合」还没有实现（第 9 轮只把 WARN 文案的评估记录下来）。两者都写在 §2.4 与 §4.3 里。
