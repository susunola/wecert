# 第七至十轮代码复审（2026-09-18）

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
