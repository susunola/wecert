# wecert

一个 cert-manager 风格的 ACME 证书自动续期器，面向 **TLS 在腾讯云 CLB 终结** 的部署形态。

一台机器、一个二进制、一个 SQLite 文件。因为解密发生在 CLB，整个系统**不需要节点 agent，也不需要分发证书文件**。

```
┌────────────────────────────────────────────────────┐
│  wecert（单二进制，跑在一台 CVM 上）                │
│                                                    │
│  ├─ ACME 层（lego 低层 api.Core）                  │
│  │    ├─ account key + order URL 落盘（重启复用）  │
│  │    ├─ ARI: GetRenewalInfo → 续期窗口            │
│  │    └─ NewWithOptions{Profile, ReplacesCertID}   │
│  ├─ DNS-01 solver（DNSPod + 权威 NS 传播等待）     │
│  ├─ State store（SQLite）                          │
│  └─ Deployer（腾讯云 UpdateCertificateInstance）   │
└────────────────────────────────────────────────────┘
                        │ 腾讯云 API
                        ▼
              CLB（TLS 终结，SNI 多证书）
                        │
                        ▼
              多台 CVM（只跑业务）
```

## 为什么是这么设计的

Let's Encrypt 的速率限制里，最要命的不是那 100 个 SAN 上限，而是：

| 限制 | 值 |
|---|---|
| New Orders per Account | 300 / 3 小时 |
| New Certificates per Registered Domain | 50 / 7 天（全局，跨账号共享） |
| **New Certificates per Exact Set of Identifiers** | **5 / 7 天（无 override）** |
| Authorization Failures per Identifier | 5 / 小时 |

而 **ARI（RFC 9773）协调的续期豁免所有速率限制**。官方文档点名了最常见的踩坑方式：*"重复安装客户端排障，或者每次部署都删掉 ACME 客户端的配置数据"*。

所以本项目的四条不变量是：

1. **每张证书任何时刻最多一个进行中的订单，order URL 必须落盘。**
   reconcile 进来先看有没有未过期的 pending order，有就推进它，绝不新建 ——
   **除非配置里的 `domains` 变了**，那样这个订单已经签不出你要的东西，
   继续推进它只会在 finalize 时被 CA 反复拒绝，卡到订单过期为止。
2. **ARI 优先，且下单必须带 `replaces`。** 不带就拿不到那个豁免。
3. **wildcard 与 apex 会写到同一个 `_acme-challenge` 名字上**，必须"全部写入 → 全部验证 → 才统一清理"。
4. **期望状态是 `domains`，不是时间。** 生效证书的 SAN 与配置不一致就立刻重签，
   不等 ARI 窗口；丢弃订单之前必须先把 DNS 里的 TXT 收干净 ——
   授权行一删，那些记录就永远回收不了了。

第 3 条是实际写代码时最容易踩的坑：签 `example.com` + `*.example.com` 时，两个授权的 challenge 值都落在 `_acme-challenge.example.com` 上。如果按"写一条 → 验一条 → 删一条"的直觉实现，第二个必然失败。

## 域名随时改：这是设计目标，不是补充场景

每张证书的 SAN 可以有很多个域名，而且随时会增删。这套逻辑有三处专门为它设计：

**改完就生效，不等续期窗口。** 每轮 reconcile 都会把配置里的 `domains`
和生效证书里实际的 SAN 做集合比对（顺序、大小写、重复都不影响判定）。
不一致就立刻重签 —— 而不是傻等到 `notAfter - renewBefore`。
如果没有这一步，往 90 天的 classic 证书里加一个域名，最长要等 60 天才生效，
而你会以为它已经生效了。

**在飞的订单不会卡住新的域名集合。** 订单的 identifier 集合在下单那一刻就固定了。
如果配置在订单还没走完时又改了域名，程序会把这张订单丢掉重建，
而不是死守着"绝不新建订单"去推进一张终将被拒的订单。
`orders` 表里存的 `identifiers` 就是用来做这个判断的。

**域名规范化。** 小写化、去重之后再判 profile 的 Max Names 上限 ——
SAN 多的列表大多是从别处整段复制的，100 个域名外加一个手误重复
不该被判成超限。

> ⚠️ **改域名是有配额代价的。** ARI 的续期豁免要求"同名续期"（identifier 集合不变）。
> 一旦增删域名，这次签发就变成了一张新证书，要走
> **Certificates per Registered Domain（50 / 7 天，跨账号共享）**。
> 频繁改动同一个注册域下的域名集合时，请留意这条上限 ——
> 把不相关的业务拆到不同注册域下，可以避免互相挤占。

另外两个刻意的设计选择：

- **不用 lego 高层的 `certificate.Obtain`。** 它在内部自己 `newOrder`，无法把 order URL 持久化并跨重启复用。用低层 `acme/api` 自己掌控状态机。
- **新私钥挂在订单上，不直接覆盖生效私钥。** 否则部署失败就会连回滚的资本都没有。只有新证书成功上线后，才把订单私钥提升为生效私钥。

## 关于 profile 和 SAN 数量

"每个 SAN 最多 100 个域名"是 profile 相关的，不是固定值：

| profile | 有效期 | Max Names |
|---|---|---|
| `classic`（默认） | 90 天 | 100 |
| `tlsserver` | 45 天 | **25** |
| `shortlived` | 160 小时 | 25 |

CA/Browser Forum 已排期 **2027-03-15 起证书 ≤100 天，2029-03-15 起 ≤47 天**。也就是说"90 天证书 + 人工兜底"这条路两年内就没有了。

建议**每张证书不超过 25 个域名**：既对齐 `tlsserver` 的上限（将来切 profile 不用改架构），也控制住爆炸半径 —— 同一张证书里的域名是"生死与共"的，会一起成功、一起失败、一起过期。

> 通配符只覆盖一层标签：`*.example.com` 不包含 `a.b.example.com`。多层命名需要为每个子区单独申请 `*.b.example.com`，或显式列出。`*.*.example.com` 不被允许。通配符只能走 DNS-01。

## 快速开始

```bash
# 1. 编译
make build

# 2. 建运行用户与目录
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wecert
sudo mkdir -p /etc/wecert && sudo chown root:wecert /etc/wecert && sudo chmod 750 /etc/wecert

# 3. 配置（含 DNSPod token，务必 0600）
sudo cp config.example.yaml /etc/wecert/config.yaml
sudo chown root:wecert /etc/wecert/config.yaml
sudo chmod 640 /etc/wecert/config.yaml

# 4. 先指向 staging 验证配置和账号
sudo -u wecert ./bin/wecert -config /etc/wecert/config.yaml -dry-run

# 5. 装服务
sudo cp bin/wecert /usr/local/bin/
sudo cp deploy/systemd/wecert.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wecert
```

### 首次签发需要人工绑一次

首次签发时腾讯云侧还没有"旧证书 → 云资源"的绑定关系可查，所以 wecert 只会上传证书并打印出 CertId。需要你在 CLB 控制台手动绑定一次：

```
证书已续期并生效 cert=example-com deployedCertId=xxxxxxxx
```

之后每次续期由 [`UpdateCertificateInstance`](https://www.tencentcloud.com/zh/document/product/1007/57981) 自动完成 —— 腾讯云自己会去找绑定了旧证书的 CLB 监听器并换掉。**我们不需要维护监听器清单，同一监听器上的 SNI 多证书也不会被误覆盖。**

> 腾讯云另有一个 `UploadUpdateCertificateInstance`，能让证书 ID 保持不变、内容原地替换，但**需要提工单开白名单**且只支持 CLB。属于锦上添花，不必等 —— 公开的 `UpdateCertificateInstance` 已经够用。

## 配置

见 `config.example.yaml`，字段都有注释。几个要点：

- `acme.directory`：上线前请用 staging。生产环境的失败重试会消耗真实配额。
- `tencent.regions`：**CLB 是分地域资源，必须列出所有有 CLB 的地域**，漏掉的地域会静默不更新。
- `dnspod.propagationTimeout`：写完 TXT 后等待全部权威 NS 可见的上限。

### 强烈建议：`_acme-challenge` CNAME 委派

把所有域名的 `_acme-challenge.example.com` CNAME 到你自己的集中 zone（如 `acme-auth.yourdomain.com`）：

- 新域名接入只需加一条 CNAME，**不用改程序、不用给程序新 zone 的权限**
- CAM 权限只需授权**一个 zone** 的写权限，不用给几十个域名逐个授权
- 换 DNS 服务商时只需改 CNAME

程序已经支持：`GetChallengeInfo` 会跟随 CNAME 给出真正的 `EffectiveFQDN`，传播等待也是针对委派后的 zone 做的。

## 腾讯云权限（最小化）

用 **CVM 角色**（默认配置），从实例元数据取临时凭证，密钥不落盘：

```
dnspod:DescribeRecordList / CreateRecord / DeleteRecord   scope: 你那一个 acme-auth zone
ssl:UploadCertificate
ssl:DescribeCertificate
ssl:DeleteCertificate
ssl:UpdateCertificateInstance
```

若必须用长期密钥，把 `tencent.credentialMode` 改成 `static`（仅建议本地调试）。

## 监控与告警

`/metrics` 暴露：

| 指标 | 用途 |
|---|---|
| `wecert_certificate_not_after_timestamp_seconds` | **到期告警的主指标** |
| `wecert_certificate_deployed` | 是否**已在云资源上生效**（0 = 还没绑，或只上传了还没绑） |
| `wecert_certificate_consecutive_failures` | 持续 > 0 需要人工介入 |
| `wecert_certificate_ari_window_start_timestamp_seconds` | ARI 窗口起点 |
| `wecert_reconcile_total{cert,result}` | 收敛轮次计数 |

到期告警应该基于 `not_after` 做，而**不要**基于"续期任务有没有报错"：

```promql
# classic（90 天）提前 21 天告警
(wecert_certificate_not_after_timestamp_seconds - time()) / 86400 < 21

# tlsserver（45 天）提前 10 天告警
(wecert_certificate_not_after_timestamp_seconds - time()) / 86400 < 10
```

强烈建议再加一个**外部黑盒探测**：从另一台机器拨 443 读 `notAfter`。这能抓出"程序以为成功、但实际没生效"这类最隐蔽的故障 —— 只信自己的状态库是不够的。

> `wecert_certificate_deployed` 反映的是 `deploy_confirmed`，不是"有没有上传过"。
> 上传成功 ≠ 已经绑到监听器上：首次签发上传完还要人工绑一次，那之前它是 0。
> 不区分这两件事的话，指标会在证书其实还没生效时就变绿。

## 开发

```bash
make check      # 提交前的完整门禁：fmt-check + vet + test -race
make test       # 单元测试
make test-race  # 带竞态检测（SAN 多时 DNS 探测与授权轮询都是并发的）
make fmt-check  # 只检查不修改，CI 用的就是这个
make vet        # 静态检查
make build      # 产出 bin/wecert
make release    # 交叉编译 linux/amd64、linux/arm64、darwin/arm64
```

CI（`.github/workflows/ci.yml`）跑的就是 `gofmt` + `vet` + `test -race` + 交叉编译。
`gofmt` 单独设门禁是有必要的：`go vet` 不检查格式，未格式化的文件能一路通过本地检查。
更实际的理由是：一个一行类型错误就能让 9 个包里的 4 个编译不过（含主程序），
而 `go vet` / `go test` 都会因此失败 —— 没有 CI 就没人会发现。

状态机的代码分布（按职责拆开，便于定位）：

| 文件 | 内容 |
|---|---|
| `manager.go` | `Manager` 结构、构造、`Reconcile` 决策入口 |
| `manager_flow.go` | 挑战流程：`advance` / `solveChallenges` / 授权轮询 / TXT 清理 |
| `manager_done.go` | 收尾：`download` / 部署 / `discardOrder` / 退避 |
| `manager_renew.go` | 续期决策：ARI / `issue` |

## 测试

测试钉住的是最容易被后续改动破坏的性质，而不是行覆盖率：

- 订单与私钥的跨重启往返（丢了 order URL 就会撞 7 天限额）
- ARI 续期时刻的确定性（每次重启都重新随机会把续期时刻无限往后推）
- 同名 TXT 的独立保存（wildcard + apex 共用一个名字）
- **丢弃订单前先清 TXT**，以及无订单时的自愈回收（以前只删行不清 DNS，
  每走一次"订单 ready 直接 finalize"的路径就在 DNSPod 上攒一条僵尸记录）
- **域名集合漂移触发重签**，以及"集合一致时一张订单都不产生"（防误报刷满限额）
- 配置变更时丢弃 identifier 集合已不匹配的在飞订单
- 老版本状态库的原地升级（`orders.identifiers` 与 `certificates.deploy_confirmed`
  都是后加的字段，升级绝不能要求用户删库）
- 存量库文件的权限是 0600（里面对 ACME 账号私钥和全部证书私钥）
- 多记录并发探测的下标映射（串了会表现成"某几个域名的验证一直不通过"）

`Manager` 的**完整**状态机仍然没有全覆盖 —— 挑战流程需要真实的 ACME 服务端。
已经能用假 ACME 目录驱动 `Reconcile` 的**决策路径**（断言"有没有去下单"），
要覆盖签发全流程，可以在 CI 里起
[pebble](https://github.com/letsencrypt/pebble)（LE 官方的测试 ACME 服务端，
不消耗任何真实配额）。

> 每个新增的回归测试都做了**变异验证**：把修复改回坏的样子、确认测试变红，
> 再从校验过哈希的备份还原。没红过的测试不算数 ——
> 断言写反、被 `t.Skip` 吞掉、循环一次都没进，都会让它永远通过而看起来很正常。

## 实测踩过的坑

以下每一条都是**真跑一次**才暴露出来的 —— 单元测试一条都抓不到。

### 腾讯云 CLB：开了 SNI 就不绑主证书（最阴险的一个）

`SniSwitch=true` 时，CLB 会**静默忽略** CreateListener 里的主 `certificate_id`。
证书必须走 `multi_cert_info` 配置。

"静默"体现在：

| 现象 | 你以为的 |
|---|---|
| 监听器创建成功，无报错 | 绑好了 |
| Terraform state 里 `certificate_id` 有值 | 绑好了 |
| `terraform plan` 报 `No changes` | 绑好了（provider 不回读绑定，漂移不可见） |
| `DescribeListeners` 返回里连 `Certificate` 字段都没有 | —— |
| `UpdateCertificateInstance` 报 `CertificateDeployInstanceEmpty` | **这才是唯一能暴露它的信号** |

后果：HTTPS 监听器是裸的，但所有常规检查都显示正常。

### DNSPod 免费套餐的 TTL 下限是 600

配 `ttl: 60` 会被 API 以 `LimitExceeded.RecordTtlLimit` 拒绝。默认值已改为 600。

### 权威 NS 不能要求"全部可达"

DNSPod 有 9 台权威 NS。要求 9 台全部响应且一致，只要有一台从你的网络不可达
就永远等不到"传播完成" —— 而这跟记录有没有传播开是两件事（LE 是从它自己的
位置校验的）。现在的判定是：**没有任何可达 NS 否认该值，且至少 2 台确认**。

实测日志：`确认 8 / 否认 0 / 不可达 1` —— 按最初的严格实现这次会失败。

### lego 的两个 API 陷阱

- `Orders.UpdateForCSR` 的参数名叫 `orderURL`，但它**直接往你给的 URL POST**。
  必须传 `finalize` URL，传 order URL 会被 LE 当成 POST-as-GET 并报
  `POST-as-GET requests must have an empty payload`。
- `Orders.Get` **不填充** `ExtendedOrder.Location`（只有 newOrder 的响应头里有），
  不能拿它当 order URL 用。
- `UpdateForCSR` 会自己对传入字节做 base64url，所以要给 **DER** 不是 PEM。
  给 PEM 会让 LE 报 asn1 `tags don't match`。

### `UpdateCertificateInstance` 是异步的，而且**不是原子的**

调用返回只代表任务创建成功，真正重绑定要等后台跑完。

更关键的是：一次调用会重绑定所有绑了旧证书的资源，但**各资源生效时间不同**。
实测一张 2-SAN 证书绑在两条 CLB 转发规则上：

| 时刻 | test.alpha | test.beta |
|---|---|---|
| 调用返回后 30s | 新证书 | **旧证书** |
| 60s 后 | 新证书 | 新证书 |

存在 30~60 秒的窗口，期间不同端点服务的证书版本不一致。

续期场景下无害（新旧证书都有效），但**任何验证都必须带轮询**，
不能只测一次就下结论 —— 我们第一次就是这么误判成"只重绑定了一半"的。
首次签发全新域名时这个窗口更值得注意：那段时间内该域名可能还拿不到证书。

### 不要用"没有漂移"推断"证书已生效"

`DescribeListeners` **不回读**证书绑定，Terraform provider 也不回读
`certificate_id`。所以 `terraform plan` 会一直报 `No changes`，
哪怕实际一个证都没绑上。

唯一的权威证据是**直接做一次 TLS 握手读证书**：从外部
`openssl s_client -servername <域名>` 打 CLB，看实际服务的
`notBefore/notAfter`。这不依赖任何一方的自述。

---

## 曾经踩过的坑（已修复，有回归测试）

### 丢弃订单时不先清 TXT，会攒下一堆僵尸记录

`cleanup` 只在一条路径上被调用（`solveChallenges` 全部授权 valid 之后），
而 `discardOrder` 有三条路径会走到。最容易撞上的那条是：
授权验证超过 3 分钟的上限 → 下一轮订单已经变 `ready` →
`advance` 直接走 finalize，**整个 `solveChallenges` 被跳过** →
收尾时 `discardOrder` 删掉授权行，而清理 DNS 所需的 token 就在那些行里。

DNSPod 免费套餐 TTL 下限 600、9 台权威 NS、一轮传播要 2 分钟以上 ——
"授权验证跨轮次"是常态而不是异常，所以这条路径会被反复走到。

修法是把清理提到删行之前，并且做成幂等的自愈：每轮 reconcile 在没有在飞订单时
扫一遍 `presented=1` 的授权，把 DNS 上还挂着的记录收掉。

### systemd timer 的单元名必须和 service 对上

`wecert.timer` 会被 systemd 隐式解析成同名服务 `wecert.service` ——
也就是那个常驻守护进程。如果本意是定时跑 `wecert-once.service`，
文件名就必须是 `wecert-once.timer`，或者显式写 `Unit=wecert-once.service`。
不写 `Unit=` 只是依赖"文件名恰好等于目标服务名"这种隐式约定，
一旦有人把 timer 改名，它就会静默指向守护进程，定时模式从此不再生效。

### `UpdateCertificateInstance` 失败时，上传成功的证书会漏成孤儿

`Deploy` 的约定是出错时仍然返回已经上传成功的 CertId。调用方如果因为
"反正报错了"就把它丢掉，这张证书既不在 `certificates` 表、也不在
`retired_certificates` 表里，`ReapRetired` 永远看不到它。
叠加上传时带的 `Repeatable=true`（不去重），失败几次就漏几张，
最后撞上腾讯云账号的上传证书配额 —— 而回收机制的存在意义正是防这个。

### `state.db` 是 SQLite 按 umask 建的，默认 0644

库里有 ACME 账号私钥和全部生效证书的私钥。systemd 那条路有
`StateDirectoryMode=0700` 挡着，但手工执行（README 的 `-dry-run`、两个 e2e 脚本
把库放在 `/tmp`）时没有这层保护。现在 `state.Open` 会预创建目录和文件并显式
设成 0600 —— 权限不应该依赖调用方的 umask。

## 现状与下一步

**已在真实环境验证通过（Let's Encrypt staging + 真实腾讯云账号 + 真实域名
`atomwangnus.com`）：**

- [x] **阶段 A：wildcard 签发**
  - wildcard + apex 共用同一 `_acme-challenge` 名字的路径正常
  - 权威 NS 传播等待（实测 78s，9 台 NS，仲裁逻辑容忍 1 台不可达）
  - 证书成功上传到腾讯云 SSL 证书服务
  - **ARI certID 构造成功、ARI 窗口查询成功**（豁免速率限制的前提）
  - 幂等性：未到续期窗口时一张订单都不产生；失败时复用同一订单而非重建
- [x] **阶段 B：`UpdateCertificateInstance` 重绑定 CLB**
  - 监听器原绑 `apJRqDsC` → wecert 签发新证书 → 自动重绑定到 `apJdfyPa`
  - 从 CLB API 独立取证确认生效（异步任务约 15s）
  - 验证了核心假设：**腾讯云自己找绑定资源，wecert 不需要维护监听器清单**

**待办：**

- [ ] 外部黑盒探测（拨 443 校验实际生效的 `notAfter`）
- [ ] DNSPod token 支持从文件 / systemd `LoadCredential` 读取，避免 config.yaml 里放明文
- [ ] 切 `profile: tlsserver`（45 天）并验证 ARI 全自动跑满一个完整续期周期
- [ ] 用 `multi_cert_info` 测 SNI 多证书场景（"换一张不误伤另一张"）
- [ ] 阶段 C：CVM + systemd + CVM 角色凭证路径（`testenv/` 里已备好，`create_cvm=true`）
- [ ] 签发失败降级策略：到期前 N 天仍未成功时，自动拆成更小子集先签（部分可用好过全挂）
- [ ] 给 `state.db` 加跨进程排他锁（`flock`）。现在"每张证书最多一个在飞订单"
      只在一个进程内成立，daemon 与 timer 两种模式同时启用就会并发下单，
      而后果是 7 天不可恢复的限额
- [ ] 把 `Manager` 对 `*api.Core` 的依赖也抽成窄接口，或引入 pebble，
      让完整签发流程进入单测（目前抽了清理路径需要的 `challengeSolver` /
      `keyAuthProvider`，并用假 ACME 目录覆盖了 `Reconcile` 的决策路径）
- [ ] `state.Store` 缺少事务能力，`download()` 收尾的
      "提升新证书 → 记录退役证书 → 丢弃订单" 三步是各自独立提交的；
      中间失败会留下孤儿云证书或一次假故障告警

**已修复：**

来自 PR #1（`fix/deploy-order-safety`，已合入 main）：

- [x] `DeployConfirmed`：区分"上传成功"和"已在云资源上生效"。首次上传后还要人工
      绑一次，在那之前不置位 —— 否则指标和到期告警都会以为证书已经生效
- [x] 只有确认换证完成才把旧证书挂进待回收列表（避免删掉人手刚绑上的那张）
- [x] 等 `UpdateCertificateInstance` 的任务真正跑完（`DescribeHostUpdateRecordDetail`），
      不再"调用返回即认为成功"
- [x] 单台权威 NS 的 zone 能通过传播检查（原先要求 2 台确认，这种 zone 永远等不到）
- [x] `DeleteCertificate` 恢复资源检查（`IsCheckResource=true`）：宁可删不掉占着配额，
      也不误删还在被引用的证书
- [x] 订单 `expires` 缺失/不可解析时用保守 TTL，避免落成零值被当成"已过期"

本轮：

- [x] **`internal/deploy/tencent.go` 编译错误**：`DeployRecordId` 抄了别的结构体的
      `*int64`，而 `UpdateCertificateInstanceResponse` 里是 `*uint64`。
      一行类型错误让 9 个包里的 4 个编译不过（含主程序 `cmd/wecert`），
      而 `go test` 也因此跑不起来 —— 这正是本轮补 CI 的直接理由
- [x] 域名集合与生效证书不一致时立即重签，不再等到续期窗口
- [x] `orders` 表记录 identifier 集合，配置变更时丢弃在飞订单；老库自动补列
- [x] 丢弃订单前先清理 DNS 里的 TXT，并增加幂等的残留回收
      （PR #1 已经在 `discardOrder` 里补了清理，本轮把它统一到可自愈的
      `cleanupOrphanTXT`，覆盖"删订单成功、删授权失败"和进程被 kill 的情况）
- [x] `download` 的幂等兜底：上一轮已下载部署、只是收尾失败时，不再被自己的
      `notAfter` 闸门挡下并报一整周的假故障
- [x] 域名小写化 + 去重后再判 profile 上限；坏域名的本地校验加强
- [x] 部署失败时把已上传的 CertId 记入待回收列表，不再漏成孤儿
- [x] `state.db` 及其 `-wal` / `-shm` 显式 0600，父目录自动创建
- [x] `wecert.timer` 更名为 `wecert-once.timer` 并显式声明 `Unit=`
- [x] `config.example.yaml` 默认改为 staging（install.sh 会直接把它装成生产配置）
- [x] `clbverify -wait` 改用独立 ctx，不再静默吞掉查询错误
- [x] 多记录并发探测 + 授权状态并发拉取，并给出真实等待时长
- [x] ARI 查询失败也记账并遵守 `Retry-After`（原先每轮都会重打）
- [x] `preflight -prune-certs` 增加确认门禁；补上缺失的 NS 委派检查
- [x] 指标端口绑定失败时 fail fast，不再静默失去唯一的到期告警通道
- [x] 补 `gofmt` 门禁与 CI（`gofmt` + `vet` + `test -race` + 交叉编译）
- [x] 还原被 PR #1 删掉的设计注释（`state.go` 52→1、`dns.go` 57→14、
      `tencent.go` 28→3、`manager.go` 69→21、`metrics.go` 10→1、`reconcile.go` 10→1）。
      注释里写的是"为什么这么做"，删掉之后这些取舍就只剩代码可猜了

