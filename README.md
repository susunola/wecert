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

所以本项目的三条不变量是：

1. **每张证书任何时刻最多一个进行中的订单，order URL 必须落盘。**
   reconcile 进来先看有没有未过期的 pending order，有就推进它，绝不新建。
2. **ARI 优先，且下单必须带 `replaces`。** 不带就拿不到那个豁免。
3. **wildcard 与 apex 会写到同一个 `_acme-challenge` 名字上**，必须"全部写入 → 全部验证 → 才统一清理"。

第 3 条是实际写代码时最容易踩的坑：签 `example.com` + `*.example.com` 时，两个授权的 challenge 值都落在 `_acme-challenge.example.com` 上。如果按"写一条 → 验一条 → 删一条"的直觉实现，第二个必然失败。

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
| `wecert_certificate_deployed` | 是否已成功部署（0 = 还没绑过） |
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

## 开发

```bash
make test    # 单元测试
make vet     # 静态检查
make build   # 产出 bin/wecert
```

测试覆盖了三条不变量里最容易被后续改动破坏的部分：订单与私钥的跨重启往返、ARI 续期时刻的确定性（每次重启都重新随机会把续期时间无限往后推）、以及同名 TXT 的独立保存。

`internal/acme/manager.go` 的完整状态机没有单测 —— 它需要真实的 ACME 服务端。验证方式是先对 staging 跑通全流程。

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

### `UpdateCertificateInstance` 是异步的

调用返回只代表任务创建成功，真正重绑定要等后台跑完（实测约 15 秒）。
断言必须带轮询，否则会误判成失败。

### `DescribeListeners` 不回读证书绑定

所以不能只靠它验证部署结果。可靠的独立信号是 `UpdateCertificateInstance`
返回里的 `UpdateSyncProgress.TotalCount`（"这张旧证书绑了几个资源"），
以及 `CreateCertificateBindResourceSyncTask`。

---

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

