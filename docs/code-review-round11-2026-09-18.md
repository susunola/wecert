# 代码与架构 review 第十一轮（2026-09-18）

前四轮（第 7–10 轮）的结论在 [code-review-rounds7-10-2026-09-18.md](code-review-rounds7-10-2026-09-18.md)。
这一轮换了三个**从未用过的视角**，并把两个被推迟的产品缺口做掉了一个。

## 0. 方法与视角

| 视角 | 派了什么 | 返回 | 核实后已修 |
|---|---|---|---|
| A · 真实运维走过的路 | 把文档里承诺的**每一条运维旅程**当成断言，用真实二进制逐条跑：锁拒绝、恢复流程、告警路径、探针 CLI 契约、webhook 状态码、onboard 文档形状与退出码、preflight 的拒绝行为 | 27 条（8 条是缺陷、11 条**实测成立**、8 条本机跑不了） | **8/8** |
| B · 规模与资源 | 合成规模下的行为：N 张证书、N 个 host、N 条 webhook 队列、SQLite 争用、内存与文件描述符上限 | 10 条（4 条实测成立、5 条带数字驳回、1 条记为取舍） | **4/4** 成立项 |
| C · 所有面向运维的文案 | 逐个 `log.*`/`slog.*`/`fmt.Print*` 调用点，把文案与它引用的指标名、doc 指针、flag 名、config key 逐个对照，并**实测**可复现的那些 | 17 条（3 high、6 medium、8 low）＋ 一条"没报但顺手修" | **17/17** ＋1 |

三个视角的产物（原始 JSON、逐条证据、复现命令）都在会话的 `/tmp/wecert-r11/` 下，本文件只保留结论与修法。

**这一轮最值钱的三条都不是"新代码写错了"，而是"程序对运维说的话与它做的事不一致"**：`-dry-run` 说"一切都好"却没构建任何会读凭证的组件；`-once` 在一张证书卡在退避窗口里退出 0，而 README 把退出码写成 timer 唯一的报警通道；重复 `-revoke` 的 WARN 说"之前那张只有在请求还在时才被吊销"，而下一行 SQL 正好把那个请求换掉了。三者都已被真实的复现钉住（见 §1、§3）。

---

## 1. 视角 A：真实运维走过的路

### 1.1 已修（8 条，全部有复现）

| 严重度 | 位置 | 缺陷 | 修法 |
|---|---|---|---|
| high | `internal/reconcile/reconcile.go` | **`-once` 在"每张证书都在退避窗口里"时退出 0**。`Trouble()` 检查的是 `Skipped`，而 `ErrBackoff` 那一支只 `rep.Backoff++`、从不 append 到 `Skipped`，所以这个守卫对**它自己注释里说的那个场景**永远不会触发。可达性不是理论：退避是 `1m<<n` 上限 6h，连续失败七八次后就超过 timer 的 1h 间隔，从那以后 unit 一直绿，而 fleet 不被续期 —— README 与 `docs/lifecycle-acceptance.md` 都把退出码写成 timer 唯一的报警通道 | 守卫改为覆盖 `Backoff`；每张证书的跳过行从 Debug 提到 Info（否则默认级别下这句"这一轮什么都没做"没有任何解释）；`onceExit` 的报错补上 `backoff=` |
| medium | `cmd/wecert/main.go` | **`-dry-run` 说"配置、ACME 账号、期望状态都没问题"，但它在这三个之后 5 行就 return，从不构建 DNS provider 与 deployer** —— 而静态凭证正是在那里被校验（`internal/config` 故意把校验推给 `deploy.NewCredentialSource`）。于是"空的 secretId/secretKey"能通过安装前唯一的那道检查并退出 0，等到第一次真实 pass 才失败，此时生产账号已经注册、一个 interval 已经过去。`install.sh` 的最后一步正是这条命令 | dry-run 分支现在真的构建两者（不发起任何 API 调用：CVM 角色的凭证获取仍推迟到首次使用）；把 README 里"绿灯意味着凭证可用"收敛为它真正能验证的范围，并把"凭证是否真的能用"明确交给 `wecert-preflight`（两份 README 都改） |
| medium | `config.example.yaml` / `README.md` | 随包发布的 `email: ops@example.com` 被 Let's Encrypt **注册时**拒绝（`400 invalidContact: contact email has forbidden domain`），于是文档里的快速开始**在文档里写的那一步就绿不了**，而错误信息既不指文件也不指行 | 在 `internal/config` 里本地拒绝保留域名（example.com/net/org/edu 及其子域、`.invalid/.test/.example/.localhost` 与单标签保留名），错误信息说明"CA 会在注册账号时拒绝它，所以一张证书都发不出来"；两份 README 与 `config.example.yaml` 都写明这一行必须换成自己的邮箱 |
| medium | `install.sh` | `make release` 产出的是 `wecert-onboard_linux_amd64`，而 `install.sh` 找的是同目录下的 `wecert-onboard`（注释还写着"release tarball 两个都有"）。于是 README 里那条 `sudo ./install.sh ./dist/wecert_linux_amd64` 走 else 分支，打印"onboard unit 起不来"后**退出 0** | 按 wecert 二进制自己的后缀找同名 onboard（`dist/wecert_linux_amd64` → `dist/wecert-onboard_linux_amd64`），三个目录形状都验过 |
| medium | `cmd/wecert/revoke.go` | **CA 目录不可达时，吊销请求什么都不会被记录**：CLI 先 `EnsureAccount`（要读目录）再调 `RequestRevocation`，而文档承诺的是"先写状态库，CA 暂时失败由守护进程重试"。密钥泄露时正好是最可能碰上网络问题的时刻，结果 `revoke_requests` 为空、没有重试、`wecert_revocation_pending` 为 0 | `RequestRevocation` 拆成 `RecordRevocation`（纯状态库，零网络）+ 立即尝试；CLI 先记录再读目录，CA 不可达时报错明说"请求已记录、守护进程会继续重试"。用例驱动**整个 `runRevoke`** 打一个无法解析的 directory |
| low | `internal/state/state.go` | 损坏数据库的三条报错让运维"连着 `-wal` 一起恢复 `state.db`"，而快照（`VACUUM INTO`）根本没有 sidecar —— 读者会去找两个文件，而 `docs/recovery.md` 现在说的是"停守护进程，`wecert -restore latest`" | 三条报错统一指向最新快照与 `wecert -restore latest` |
| low | `cmd/preflight`、`cmd/clbverify` | 用法错误退出码不一致：preflight 无参数退 1、未知 flag 退 2（flag 默认），clbverify 无参数退 1，而 wecert/onboard/probe 用 64。仓库自己的文档把 1 定义为"程序跑了但失败"、2 定义为"有意冻结，需要人看" | 两个工具都改用 `ContinueOnError` + 64，未知 flag / 缺参数 / `-h` 三种情况都验过 |
| low | `README.md` | 英文 README 把"期望状态从哪里开始"指向 `docs/desired-state.md`，而那份文档**只有中文** | 明确标注该文档为中文，并给出英文侧对应章节的锚点 |

### 1.2 实测成立、因此不改的 11 条（这一轮可信度提高的部分）

跨进程锁的拒绝信息与退出码、`docs/recovery.md` 第 3 节的"数据库被删"警告逐字一致、WAL 被删的警告与真实数据丢失、**第 2 节的恢复流程**（账号密钥逐字节一致）、`quick_check` 两种损坏形态都拒绝启动、`docs/test-cases.md` 第 2 节整张 probe CLI 契约表（退出码 0/1/2/64、重试次数、NDJSON 形态）、webhook 的 401/400/413/202/429 与"正确 token 穿过锁定窗口"、`-revoke` 的确认交互与 reason 白名单、onboard 生成的文档形状/名字映射/守卫/退出码 0-2/冻结报告、onboard→wecert 的 enforce 往返（含 revision 检查）、preflight 的只读检查在缺凭证时**拒绝而不是猜**。

### 1.3 本机跑不了的 8 条（未验证，不是"通过"）

腾讯云相关的全部手工步骤（没有该账号的凭证，元数据也不可达）、真实 CA 侧 DNS-01 校验（pebble 对自定义 resolver 强制 TCP，而本机 53/tcp 被 limactl 占着，仓库自己的用例在这里是 SKIP）、把二进制指向本机 pebble（darwin 上 Go 不认 `SSL_CERT_FILE`，没有 CA 覆盖开关）、`make test-pebble`（另一个 reviewer 的桩占着 14000）、`install.sh` 端到端（要 Linux + root）、`wecert-preflight -prune-certs` 的非交互 stdin 视为 no。

---

## 2. 视角 B：规模与资源

方法：在一个**独立副本**里加最小测量缝隙（一个 harness + 两处 seam），把 fleet 合成到 500 张证书 × 20 个名字（= 500 个注册域名、500 个标识符集合、10 000 个标识符、336 KB 文档），全程用假 manager（不发网络请求），逐轮采样 SQL 语句数、pass 墙钟、RSS、goroutine、fd、指标序列数与 WAL 大小。**5 条实测成立、4 条带数字驳回**。

### 2.1 已修（4 条）

| 严重度 | 位置 | 缺陷 | 修法 |
|---|---|---|---|
| high | `internal/reconcile/reconcile.go` | **webhook 全量触发的配额发布是"每张证书一次"，于是整个触发是 fleet 的平方**：一次发布要对期望状态推出的每个 scope 做 2 次读，500×20 时 `POST /hook/reconcile` 是 **11 001 500 条 SQL、84.4 秒**（同一 fleet 的定时 pass 是 23 003 条 / 0.234 秒），4 倍规模 → 4 倍开销：50/100/200/500 张时 11 万 / 44 万 / 176 万 / 1100 万条，2000×5 时 5600 万条、433 秒 —— 把唯一的 SQLite 连接和一颗 CPU 按住几分钟，所有其他数据库使用者排在后面 | 配额指标改为**每个触发发布一次**：一批 pass 里最后一个完成的负责发布整批（用 deferred 调用，这样"等 slot 时遇到 shutdown 提前返回"的路径也会把计数减回去 —— 计数卡在 0 以上会让这个进程此后再也不发布） |
| high | `internal/reconcile/reconcile.go` | **回收陈旧探针序列时，每个 host 都把整份期望状态文档重新解析一遍**（一次文件读 + YAML 解码 + 全量校验 + 文档 sha256）。默认探针上限下 500 张证书时：**27.8 秒 vs 无回收时 0.18 秒（155 倍）**，且正是 O(陈旧 host 数 × fleet)：25/50/100/200 张时 0.41/1.48/5.66/22.9 秒。触发条件很日常 —— 删掉一张证书或一个名字就会留下 host | 解析提到循环外，一次解析建 `host → 证书` 映射，逐个 host 只查一次映射（+ 一次 `GetCert`）。同一证书名被多张证书覆盖时保持"文档里靠前的那张说了算"，与原实现的顺序语义一致 |
| medium | `internal/acme/ratelimit.go` + `internal/state/ratelimit.go` | **每个标识符都发布一条配额序列**：这是唯一无界的族（"每张证书的每个 SAN"随 fleet 增长），500×20 时占 17 052 条序列里的 **11 001 条**、抓取体 **1.67 MB**，普通定时 pass 也要 22 002 条 SQL | 该族改为**从状态库读"花过额度的标识符"**（正是可能被耗尽的那批）：没验证过的名字额度是满的，那条序列不携带任何可行动信息。另两族仍按期望状态发布 —— 它们才是运维做批量变更时要计算的数字。读失败时回落到旧的全量列表并打出警告 |
| low | `internal/acme/manager.go` | `bindingChecked` 与 `identifierCooldown` **每个见过的证书名/标识符各留一条永不清理**：前者只有"再来问同一个名字"时才会删，后者从来没人删（600 个churn 过的名字 → 50 增长到 600 条） | 两张表都在写入路径上、超过 512 条时清扫过期项（前者"过期"= 超过检查间隔，后者 = 冷却已到期） |

另外，**孤儿回收的日志洪泛**在本轮早前已修（§3 的第 4 条）：2 999 个孤儿 = 每轮 2 999 行 ERROR，现在是前 10 行 + 一行计数汇总，其余降到 Debug。

### 2.2 带数字驳回的 4 条（因此保持原样）

- **`SetMaxOpenConns(1)` 不会让整个 fleet 排在一张慢证书后面**：某张证书的 pass 睡 3 秒期间，无关的状态库读仍是 0.08–0.14 ms。
- **WAL 不会跨 pass 无限增长**：200 轮写密集的 pass 后固定在 4 120 032 字节（autocheckpoint）。
- **长时间运行没有泄漏**：600 轮后 goroutine 恒为 2、RSS 峰值平台 38.5 MB、堆在 6–10 MB 间震荡、序列数 6 448 与每轮 SQL 9 203 条都不变，探针的几张表都被回收。
- **`maxConcurrentStarts=8` 完全成立**：峰值恰好 8、500/500 接受、无丢弃；7 个同伴在 1 ms 内完成而 1 个花了 3 秒 —— 大触发的代价是"找到 1 个空位"，不是"抢不到空位"。

### 2.3 保持原样、写进报告的两条

- **pass 严格串行**：一张 3 秒的证书会把 200 张证书的 pass 从 0.097 秒变成 3.07 秒（其余证书仍会收敛）。这是**文档化的取舍**（同一证书最多一个在飞订单，且 fleet 的额度算术依赖它），实测代价是一张慢证书的时延，不是整个 fleet 的。
- **被保留的孤儿行每轮都会被重新回收一次**：2 999 个孤儿 = 每轮 15 051 条 SQL。日志那一半已经收敛（见上），但要让 SQL 与"真正需要清理的东西"成比例，需要一个持久化的"已清理"标记 —— 那是 schema 变更，不该夹在这一轮里。记在 `docs/backlog.md`。

---

## 3. 视角 C：所有面向运维的文案

方法：grep 出全部 `log.*`/`slog.*` 与四个辅助工具的 `fmt.Print*`，逐条把文案与它引用的东西对照 —— 指标名对着 `internal/metrics/metrics.go`，doc 指针对着文件树，flag 对着各自的 flag set，config key 对着 `internal/config` —— 并能复现的就用真实二进制复现。**17 条全部核实并修复**，其中三条 high：

| 严重度 | 位置 | 缺陷 | 修法 |
|---|---|---|---|
| high | `cmd/wecert/main.go` | 同 §1.1 的 `-dry-run`（两位复审者独立命中同一条） | 见 §1.1 |
| high | `internal/reconcile/reconcile.go` | 同 §1.1 的 `-once` 退出码（两位复审者独立命中） | 见 §1.1 |
| high | `internal/acme/revoke.go` | 重复 `-revoke` 的 WARN 说"之前那张只有在它的请求还在时才被吊销" —— 而**下一行** `AddRevokeRequest` 是 `ON CONFLICT(cert_name) DO UPDATE`，每个证书名只有一行，那个请求在这句话之后就被覆盖了。实测：WARN 打出旧 identity，随后日志打 `CERTIFICATE REVOKED`，而吊销掉的是**健康的新证书**，泄露的那张 wecert 再也不会去吊销 | 措辞改为陈述真实后果（旧目标不会被 wecert 吊销）并给出该做什么（在 CA 控制台用现有材料吊销，或先恢复那份材料再续期）；顺带把请求的 `RequestedAt` 一起打出来 |
| medium | `internal/metrics/metrics.go` | `wecert_ratelimit_remaining_tokens` 的 Help 写"**下**界"，而 `internal/ratelimit/tracker.go` 用第 8 轮定稿的话写着相反方向（"UPPER BOUND…at most this much"）。第 8 轮改了包文档与 README，漏了**随二进制发布的 Help** | Help 与声明注释都改成上界，并指明"CA 自己拒绝过什么"要看 `wecert_ratelimit_blocked` |
| medium | `internal/probe/runner.go` | 四个**方向完全不同**的判定类别（名字不覆盖 / SAN 不一致 / notAfter 不一致 / 有效期低于 `minValidFor`）共用一句硬编码的"服务的不是部署的那张证书"。`minValidFor` 那一类里服务的就是部署的那张，于是 ERROR 与 CRITICAL 告警把运维指向重绑/SNI，而真实答案是"续期还没跑" | `Verdict.Problems` 改为带 `Kind` 的结构（`Problem`），转换行按实际类别措辞；告警注解同步改写，并说清 probe 家族按 host 打标签、desired 家族按 cert 打标签、**两者没有可 join 的 label** |
| medium | `internal/metrics/metrics.go` + `internal/probe/runner.go` | `probe_trusted` 与 `probe_not_after` 在探针**再也连不上**该 host 之后保留最后一次握手的值：实测 `probe_errors=3`、`probe_match=0` 的同时 `probe_trusted` 仍是 1、not_after 还是旧的 —— 第 6 轮为 `probe_match` 修掉的同一个 false green，两个"兄弟"被留下了 | 新增 `metrics.ClearProbeAnswer`（只清这两个，不动错误计数），三条"连不上/只答了一部分地址"的分支都调用它；两个 Help 都写明"序列缺失=没有答案，而不是旧答案" |
| medium | `internal/acme/manager_done.go` | 提示运维"用 `wecert-preflight prune` 删除" —— **没有这个调用**（preflight 只有 flag，`prune` 走到 usage 后退出 1），而它真正对应的 `-prune-certs` 是**批量删除**所有 `wecert/` 别名的证书，包括这条消息刻意留下的、可能还在服务的那个 | 改为"先在控制台解绑再删，或明确地用 `wecert-preflight -prune-certs`（它会删掉每一张 wecert 上传的证书，确认前先读它的告警和列表）" |
| medium | `cmd/wecert/main.go` | "快照被 DISABLED" 这条**没有任何属性**，但它同时覆盖两种情况：运维写了 `enabled: false`，或者没写（默认开）而目录不可写。后者的修法是改目录，而消息里连目录都没有（隔壁分支是打 `dir=` 的） | 按 `cfg.StateBackup.Enabled` 区分两种情况，不可写那条带上 `dir` 与 hint |
| medium | `cmd/wecert/main.go` | enforce 模式下 banner 与 dry-run 摘要都打 `certificates=0`（该模式下 `cfg.Certificates` 按定义就是空），而证书在文档里；启动后的前十行里没有任何地方说真实数量 | 该字段在 enforce 模式改为"来自期望状态文档（数量见下）"，并在 `Prime` 之后补一行报文档里解析出的证书数（为 0 时 WARN） |
| low | `internal/metrics/metrics.go` | ARI 窗口 Help 写"0 表示还没取到"，而代码在未设置时**删除该序列**，所以 `== 0` 的告警永远匹配不到东西 | Help 改为"序列缺失即未取到，请对缺失告警，而不是对 0" |
| low | `deploy/prometheus/wecert-alerts.yml` | 告警注解让运维"把 probe 的 not_after 与 `wecert_certificate_not_after_timestamp_seconds` 按同一个 host 对比"，而两个族**没有共享 label**，这个 PromQL 写不出来 | 注解改成可执行的路径（按 SAN 找到证书，再读它的 `not_after{cert=...}`），并说明为什么不能 join |
| low | `internal/metrics/metrics.go` | `fallback_dropped_names` 的 Help 说"当前服务的证书丢掉了几个名字"，而它是在**决策时刻**设置的（第 10 轮刚给兄弟指标修过同一处措辞） | 改为"生效中的 fallback 丢掉了几个名字"，并说明第一次 pass 时服务的仍是旧的完整证书 |
| low | `internal/reconcile/reconcile.go` | "无法解析已存证书；回落到配置里的名字" —— 这句话所在函数**没有配置里的名字**；孤儿路径调用它时更是完全没有，于是"回落"没发生、该证书的 per-host 探针序列永远不被回收（`probe_match=0` 的告警会永久响） | 警告移到真正的回落点（`probeCert`），并在孤儿路径上明确说出后果（无法自动回收，需要手工删序列） |
| low | `internal/onboarding/onboard.go` | 冻结理由写 `guards.requireCLBRule` —— **不存在 `guards:` 这个配置段**，真正的 key 是 `onboarding.requireCLBRule` | 改成真实 key |
| low | `cmd/preflight/main.go` | `-list-certs` 用 `derefU64` 打印总数，SDK 明确说该字段可能为 null，于是"表里一堆行 + `0 total`"并顺带压掉了"列表可能不完整"的提示 —— 而同一个文件 180 行前刚拒绝把 null 当 0 | 改用同文件的 `certificateCount`，读不到时打印"已列出 N 张；账号总数未知（原因）" |
| low | `cmd/clbverify/main.go` | "query failed, retrying shortly" 由**预算检查之前**的 callback 打印，所以最后一次失败也承诺重试，然后直接返回（同族的 `wecert-probe` 是先查预算再打印） | 预算判定提前，callback 拿到"这是最后一次"的信息并改说"不再重试" |
| low | `cmd/wecert/main.go` | `wecert -nope` 退出 2（flag 包默认），而仓库的约定是 64，且 2 在本仓库文档里是 onboard 的"有意冻结" | 自己拿 `FlagSet` + `ContinueOnError`，用法错误退 64（`-h` 仍 0）；`-restore` 与 `-once/-dry-run/-revoke` 冲突同样归为用法错误 |
| low | `cmd/wecert/main.go` | 生产环境警告的两个字符串字面量拼接时少了一个空格："environment.run the whole flow…" | 补空格与句首大写 |

复审者还留了一份 `checked_clean`：健康的 static/enforce 启动序列、五种已文档化的错配、14 条配置错误文案（用真实二进制逐条跑过）、约 25 个指标 Help 与发布点逐个对照（只有上面 4 个是错的）、onboarding 报告的字段与 guard 分类、webhook 的 accepted/skipped/unknown 与 `/hook/status` 的读错误语义。

---

## 4. 本轮做掉的被推迟产品缺口：一条命令恢复快照

背景（`docs/backlog.md` 第 3、4 项）：恢复一份快照原本是 `docs/recovery.md` 里的五步，而**真正的风险不在那五步里** —— 快照里的限额账本停在快照写入那一刻，之后启动的守护进程会以为自己什么都没花；而"同一标识符集合每 7 天 5 张"没有豁免。第 8–10 轮把它记为待办，这一轮实现。

`wecert -restore <快照文件|目录|latest>`：

- **守护进程持锁时拒绝**。在运行的守护进程下面恢复不会响亮地失败：它继续写自己已经打开的那个 inode，于是它此后写的一切都不会出现在恢复后的库里。
- **先验证，再动线上库**：16 字节 SQLite 魔数 → `PRAGMA integrity_check` → 是否真有 wecert 的表。任一条不过就**点名拒绝**，路径写错或快照没拷完都不付出代价。
- **先拷贝、后交换**：快照先落到 `state.db` 旁边的暂存名并 fsync，暂存副本**再验一次**，然后才把旧库移开。磁盘满时部署与之前完全一样。
- **被替换的库连同 `-wal`/`-shm` 一起保留**（`state.db.replaced-<UTC 戳>`），且这个命名不会被保留策略回收 —— 恢复是往回走一步，被它替换掉的文件里可能有快照之后下的单。名字被占用时用 `~N` 后缀，绝不 `rename` 覆盖（那是运维唯一的一份）。
- **statePath 是符号链接时顺着链接恢复**，而不是把链接本身换成普通文件（否则"成功"了但守护进程读到的还是旧库）；记录写在**配置里那个路径**旁边，因为下一次启动就是去那里找。
- **`state.db.restored`**：下一次启动读它，并在 7 天内 WARN —— 7 天是我们建模的最长窗口（exact-set 与 per-registered-domain 都是 7 天），过了这段时间所有可能少算的桶都已自行回填，账本重新完整。这条警告是恢复这件事唯一会说出来的一句话，所以写不进去时命令会报错（"快照已就位，但记录失败"）。

同时更新：`docs/recovery.md`（一条命令的短路径 + 保留手工路径并说明它**不会**留下记录）、`docs/staging-checklist.md` 新增 §7（恢复演练：含"持锁时被拒"、"非快照文件被拒"、"回退到被替换的库"）、两份 README 与 CLI 参考表（顺带补上此前完全没写进 flag 表的 `-revoke`/`-revoke-reason`/`-yes`）。

`docs/backlog.md` 第 3、4 项据此改写：第 3 项只剩"把快照自动送离主机"，第 4 项记录剩下的那半 —— **手工 `cp` 恢复无法被发现**，并写清楚为什么那个看起来很诱人的信号（"文件 mtime 比内容新得多"）是个假阳性制造机（SQLite 在打开与关闭时会 checkpoint WAL，因此一个只写了一次、然后空闲一周的守护进程在正常重启后正好长这样）。

---

## 5. 门禁与提交

本轮每个门禁都跑过并绿（下面"未跑"的除外）：

- `gofmt -l .`、`go vet ./...`、`go vet -tags "pebble lego_dns" ./...`、`staticcheck ./...`
- `python3 scripts/check-english.py`（**193 个源文件**；这一轮先被它抓到自己的一处中文引文，已改）
- `python3 scripts/test-check-alerts.py` 与 `scripts/check-alerts.py`（17 条规则，引用的序列都存在）
- `python3 scripts/test-check-cam-policies.py` 与 `scripts/check-cam-policies.py`
- `bash scripts/test-e2e-wildcard.sh`（5/5）
- `go test -race -count=1 ./...`：**20/20 包**
- `make test-tags`（`-tags "pebble lego_dns"` 下的全套 + vet）：绿。第一次尝试失败是环境冲突 —— 某个复审者留在 `/tmp` 的桩 ACME 服务器一直占着 14000 端口（用例报 `bind: address already in use`），确认那是残留进程后结束它，重跑即绿。
- `make e2e`：**2/3 通过，第 1 个套件在本机 SKIP**（`limactl` 的 DNS 代理占着 53/tcp，Go 侧写的是 `cannot bind TCP port 53 ... address already in use`）。按 #68 定下的语义，SKIP 就是门禁失败，所以这条命令在本机**退出 1**，HTML 报告里也这么写（`docs/e2e-run-2026-09-18.html`，报告页明确标注"这个套件没跑"）。pebble 上的订单协议（13.8 秒）与通配符/apex 共享名（22 秒）两个套件通过。

  值得记一笔的是**这一轮差点把 SKIP 当成通过**：rebase 之前的分支用的还是旧 `e2e.sh`，它对 SKIP 套件打印 `pass in 9s`；本轮的 #68 修好之后同一条命令才如实报"缺 Go 报告 + 退出 1"。这条修正本身就是上一轮那类缺陷（"跳过的套件被写成通过"）在真实环境里再抓到一次。

提交：本轮 13 个提交都在 `test/e2e-tlsserver-renewal` 上（恢复功能 → 两个视角的修复 → CI 门禁补强 → 规模修复 → 本报告）。**分支基底需要留意**：这一轮开始时该分支的基底早于 `main` 上的 #66/#68，直接推上去会把 #68（"SKIP 的套件算失败"+ 缺 Go 报告不再 traceback）在合并时**回退**；发现后已把本轮 13 个提交 rebase 到当时的 `origin/main` 上，并确认 `docs/stage-c-cvm-systemd.md`、`scripts/e2e-sni.sh`、`scripts/e2e-report.py` 的修复都还在。恢复功能与两轮 review 的修复在同一提交里，因为它们是同一轮的工作。

---

## 6. 精度说明（这一轮的可信度边界）

- **修复也要有红过的测试**：新增/改动的用例逐条做过变异验证 —— 把锁检查、sidecar 迁移、快照校验、记录写入、7 天窗口、`-restore` 的符号链接解析、`-revoke` 的"先记录"顺序分别破坏掉，确认对应用例确实变红（`Trouble()` 那条则是把"退避算不算没收敛"钉在两处：单元用例与 `onceExit` 的报文）。
- **两位复审者独立命中了同两条缺陷**（`-dry-run` 的凭证、`-once` 的退出码），这不是重复劳动：A 是从"文档承诺的旅程"走到的，C 是从"这句话引用了什么"走到的，两条路径都指向同一处，可信度更高。
- **驳回与未验证分开写**：§1.2 是"我实测它成立"，§1.3 是"我没跑"，两者都不是"没问题"。此外仍与前面各轮合并的未验证项：真机生产 LE、自然到期续期、云端对 `IsCheckResource` 的真实执行、真实断电/掉页、CA 是否真的会在同一 authz URL 上换挑战、DNSPod 是否真的返回非规范记录名、`docs/certificate-lifecycle*.html` 里的若干陈旧陈述（那两页由 `make diagrams` 从中文源生成，本轮没有重新生成）。
- **仍然刻意留着的两处**：第五个 CA 限额（连续授权失败导致标识符暂停）没有建模；降级集合的"证据过期后自动重试完整集合"没有实现（第 11 轮评估过，结论是"退避窗口之后本来就不该下整集订单"，只改了四处误导性文案）。
- **`Verdict.Problems` 的 JSON 形态变了**（从字符串数组变成 `{kind,text}` 对象数组）。仓库内没有消费方，`docs/test-cases.md` 的 probe 契约表只约束 `result`/`verdict` 的存在性；但外部若有脚本解析 `problems`，需要跟着改 —— 这是本轮唯一一处对外输出形态变化。
