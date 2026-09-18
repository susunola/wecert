# SNI 多证书：续期一张不能动另一张

> ## 脚本未跑（被测行为已用另一种形态观测到）
>
> 本文配套的 [`scripts/e2e-sni.sh`](../scripts/e2e-sni.sh) **尚未在任何真实 listener 上执行过**：
> 脚本本身的机器可验部分（参数门禁、凭证拒绝、证据解析、五条断言的成败路径）用桩数据跑过（第 4 节），
> **云端那一段一次都没跑**，所以脚本里没有一条断言是实测通过的。
>
> 但**"续期 A 不动 B"这个行为本身已经在真机上观测到**（2026-09-17 / 09-18），只是形态与本文设想的不同：
> 本账号**完全忽略监听器级绑定**（`extCertIds` 恒空），证书挂在转发规则的主 `CertId` 上，走的是
> "一条监听器上两条规则、每条规则一张证书"的路径，而不是 `multi_cert_info` + `ExtCertIds`。证据来自
> **独立的 TLS 握手机位**：[`e2e-run-2026-09-17-credentialed.md`](e2e-run-2026-09-17-credentialed.md)
> §4.3（换掉 alpha 的证书后 beta 的 subject/issuer/指纹与基线逐字节一致）与 §4.9（两个独立执行者、
> 两张证书，同一条监听器互不影响）；换绑本身见
> [`e2e-run-2026-09-18-credentialed.md`](e2e-run-2026-09-18-credentialed.md) §4.4。
>
> 仍然没有验证的是**本文这条断言路径**：监听器级的 `multi_cert_info` 读回表示
> （`Certificate.CertId` + `ExtCertIds`）、真实 `DescribeListeners` 返回的 JSON 结构、以及
> `-not-expect` 在真实 listener 上的判定 —— 那需要一个**不忽略监听器级绑定**的账号。
>
> 要跑起来需要：一个多证书 SNI listener（两张证书，其中一张由 wecert 管）、一个能改 DNS 的测试域名、
> 腾讯云 CAM 凭据（`clb:DescribeListeners` 即可），以及一次真实的续期。

---

## 1. 要证的是什么

`README.reference.md` 在讲首次签发时写了一句很强的话：

> **There is no listener inventory to maintain here**, and other certificates on the same listener (SNI)
> are not disturbed.

同文的 Roadmap 里，另一处把它列为**待办**：

> - [ ] Test the SNI multi-certificate case with `multi_cert_info` ("replacing one doesn't disturb another")

也就是说：**这句话原先只是设计意图**；2026-09-17/09-18 的真机运行已经在"规则级绑定"这条路径上观测到
它成立（顶部横幅里那两处证据）。本文与 `scripts/e2e-sni.sh` 仍然有价值：它们要把它变成**监听器级
`multi_cert_info` / `ExtCertIds`** 这条路径上一次可复核、带断言的观测。

为什么它值得单独验：这件事**错了不会报错**。如果 `UpdateCertificateInstance` 在重绑时把 listener
的证书集合整体重写，A 换新是成功的、日志是成功的、指标是绿的，而 B 悄悄消失 —— 直到 B 的域名
被浏览器拒掉才会有人发现。这与 `staging-checklist.md` 第 4 节是同一件事，只是把它从"人工看一眼"
变成"有断言、有原始证据、有明确 PASS/FAIL"。

---

## 2. 先读 SDK：能保证什么，不能保证什么

**这一节所有引用都来自本地模块缓存里的 SDK 源码**，不是凭记忆：

```
/Users/atom/Documents/dsh/.gopath/pkg/mod/github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/
  ssl@v1.3.147/v20191205/models.go
  clb@v1.3.176/v20180317/models.go
```

### 2.1 `UpdateCertificateInstance` 的文档说的是"换一张证书"，没说"其他证书怎么办"

`ssl@v1.3.147/v20191205/client.go` 里 `UpdateCertificateInstance` 的方法注释原文：

> 一键更新旧证书资源，本接口为异步接口， 调用之后DeployRecordId为0表示任务进行中， 重复请求这个接口，
> 当返回DeployRecordId大于0则表示任务创建成功。 未创建成功则会抛出异常

请求字段（`models.go`，`UpdateCertificateInstanceRequest`）：

```go
// <p>一键更新的旧证书ID。 通过查询该证书ID绑定的云资源，然后使用新证书对这些云资源进行更新</p>
OldCertificateId *string `json:"OldCertificateId,omitnil,omitempty" name:"OldCertificateId"`
...
// <p>一键更新的新证书ID。 不传该参数，则公钥证书和私钥证书必传</p>
CertificateId *string `json:"CertificateId,omitnil,omitempty" name:"CertificateId"`
```

**可以据此断言的**：这个接口的模型是"以 `OldCertificateId` 为锚点，找出绑着它的云资源，
再用 `CertificateId` 去更新那些资源"。**它从头到尾没有"listener 的证书列表"这个概念。**

**不能据此断言的**：因此**不能**从文档推出"B 一定不受影响"。文档既没承诺保留、也没承诺重写 ——
它是**没提**。所以 B 是否原样保留，只能靠**读回 listener 来观测**，这正是脚本要做的事，
也是本文第 5 节要求人工核对原始 JSON 的原因。

顺带一个与脚本设计直接相关的点：`DeployRecordId == 0` 表示"任务还在创建中"，要重复请求到 > 0
才算创建成功；`wecert` 自己也是这么实现的（`internal/deploy/tencent.go` 的 `updateInstance`，
带 2 分钟上限的循环）。这解释了为什么"调用返回了"不能当成"换好了"。

### 2.2 写路径与读路径用的是**不同**的字段

| | 字段 | 出处与文档 |
|---|---|---|
| 写（创建/修改 listener） | `MultiCertInfo.CertList []*CertInfo` | `clb@v1.3.176/v20180317/models.go`，`MultiCertInfo`：*"监听器或规则证书列表，单双向认证，多本服务端证书算法类型不能重复；若SSLMode为双向认证，证书列表必须包含一本ca证书。"* |
| 读（`DescribeListeners`） | `Listener.Certificate.CertId` + `.ExtCertIds` | 同文件 `CertificateOutput`：`CertId` = *"服务端证书的ID。"*；`ExtCertIds` = *"多本服务器证书场景扩展的服务器证书ID。"* |

`Listener.Certificate` 的类型就是 `CertificateOutput`（`models.go`，`Listener` 结构体）：

```go
// 证书相关信息。
Certificate *CertificateOutput `json:"Certificate,omitnil,omitempty" name:"Certificate"`
```

**所以"B 在 `multi_cert_info` 里"这句话，读回来是这样核对的**：
`B ∈ {Certificate.CertId} ∪ Certificate.ExtCertIds`。

> ⚠️ **`multi_cert_info` 是写侧参数名，不是读侧字段名。** 本文按用户/控制台的说法沿用了
> `multi_cert_info`，但断言落在读侧的 `CertId` / `ExtCertIds` 上。这两者的对应关系是
> **推断**（同一个概念的两侧），不是 SDK 明写的 —— 脚本因此把原始 JSON 原样打印出来，
> 让人可以自己核对。

### 2.3 `wecert-clbverify` 已经站在这个模型上

`cmd/clbverify/main.go` 的注释写明了它为什么不能只看主证书：

> They are also part of the ASSERTION, not just the output. The SDK documents `ExtCertIds` as
> "additional server certificate IDs for the multi-certificate case" ... so a check that only compared
> the primary ID certified a rebind that had not happened -- and failed one that had, when the managed
> certificate is an extension cert.

它的 `boundCertIDs()` 返回"主证书 + 全部扩展证书"，`-expect` / `-not-expect` 都在这个集合上判定。
`scripts/e2e-sni.sh` 复用这个工具取数，不自己写 CLB 客户端。

---

## 3. 怎么跑

```bash
make build tools          # 需要 bin/wecert-clbverify

./scripts/e2e-sni.sh <region> <clb-id> <listener-id> <cert-id-A> <cert-id-B> [--yes] [--wait <seconds>]
```

| 参数 | 含义 |
|---|---|
| `region` | 例 `ap-guangzhou` |
| `clb-id` | CLB 实例 ID，例 `lb-xxxx` |
| `listener-id` | 承载两张证书的 HTTPS listener，例 `lbl-yyyy` |
| `cert-id-A` | **wecert 管的、要续期的那张**，起始时是主证书 |
| `cert-id-B` | 同一 listener 上的另一张，续期 A 时**必须不受影响** |
| `--yes` | 真的去读腾讯云。**不加只打印计划，一次 API 都不发** |
| `--wait` | 续期后轮询主证书变化的上限秒数，默认 180 |

凭证按 `run-stage-ab.sh` 的同一套约定：读 `WECERT_CREDS`（默认 `~/.wecert/tencent.env`）里的
`TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY`，**只抽取这两个变量，绝不 source 整个文件**
（那个文件里通常还有别的密钥）。

**没有凭据时它拒绝运行并退出非 0，而不是 skip。** 这是刻意的：`scripts/e2e.sh` 那类套件在缺凭据时
跳过是对的（跳过会在报告里留痕），而**人工验收流程的"跳过"和"通过"在发布记录里长得一模一样**，
所以这里必须响亮地失败，并在消息里点名缺的是哪一个变量。

### 3.1 四步

| 步 | 谁做 | 做什么 | 断言 |
|---|---|---|---|
| 1 | 脚本 | `-raw` 读一次 listener | 主证书是 A；B 在 listener 的证书集合里；调用 `wecert-clbverify -expect B` 走一遍工具自己的判定 |
| 2 | **人** | 触发一次真续期 | 脚本不代劳：它消耗真实 CA 配额，且触发方式取决于被测部署 |
| 3 | 脚本 | 轮询到主证书不再是 A（上限 `--wait`） | 换绑是异步的（README 实测 ~15s，区间 30s–2min），不轮询会把"还没换完"误报成失败 |
| 4 | 脚本 | 再读一次并断言 | 主证书是一个**新的** id；B 仍绑定且 **certificate id 未变**；`wecert-clbverify -not-expect A` |

第 2 步的提示文本会给出两种触发方式：

- **域名集合变化立刻重签**（在测试 session 里唯一可靠的办法）：给证书的 `domains` 加一个测试子域，
  `sudo systemctl restart wecert`，等日志出现
  `the live certificate's SANs no longer match the config; reissuing now`；
- **ARI 窗口打开**：等常规 pass 自己续期（`sudo systemctl start wecert-once.service` 或等 daemon 那一轮）。

脚本会在继续前要求你**逐字输入 `renewed`**。stdin 不是终端时（`read` 失败）直接判失败并退出 1 ——
不允许"无人值守地假装续过期"。

### 3.2 证据

每次读取都会**把 `-raw` 的原始 JSON 原样打印到 stdout**，同时落盘到
`dist/sni-<时间戳>-<pid>/listener-{before,after}.json`（`dist/` 已在 `.gitignore` 里）。
脚本末尾再打印两个目录路径。**"B 没被动过"这个结论要由人对着这两份 JSON 复核**，脚本的 OK 只是机械判定。

另外脚本会在两次读取之间做一次**不参与判定**的对比：把 A、B、以及新的主证书都排除掉之后，
如果 listener 上还有别的扩展证书发生变化，打印 `WARN` 和差异。之所以只 WARN 不 FAIL：
"主证书 + `ExtCertIds`"并不是一个有文档保证的稳定表示，硬做成集合相等会产生假失败 ——
而假失败会训练人忽略红色。

---

## 4. 这个脚本验证到了什么程度（**机械可验的部分**）

在没有凭据、没有 `bin/wecert-clbverify` 的机器上，能验的只有脚本自身的逻辑。用桩替换
`wecert-clbverify`（`WECERT_CLBVERIFY` 环境变量）跑过下面这些路径，**每条都实测**：

| 场景 | 期望 | 实测 |
|---|---|---|
| 无参数 | 用法 + 退出 1 | ✅ |
| 缺 `TENCENTCLOUD_SECRET_ID` / `_KEY` | 点名列出缺的变量 + 退出 1 | ✅ |
| 不加 `--yes` | 只打印计划，**一次 API 都不发**（桩的调用计数为 0）+ 退出 0 | ✅ |
| 正常一轮（主 A → 新 A，B 不变） | PASS + 退出 0 | ✅ |
| 续期后 B 掉了 | FAIL："Renewing A disturbed B" + 退出 1 | ✅ |
| 续期后主证书仍是 A | FAIL："did not reach this listener" + 退出 1 | ✅ |
| 续期后主证书变成 B | FAIL + 退出 1 | ✅ |
| 起始就没有主证书 | FAIL，并列出两种已知形态 + 退出 1 | ✅ |
| 操作者输入的不是 `renewed` / stdin 关闭 | FAIL + 退出 1 | ✅ |
| 过滤查询丢 `Certificate` 字段 | 打 WARN、改用不过滤的查询、并跳过工具自身的断言（说明原因） | ✅ |
| 未知参数 / `--wait` 非数字 / A==B | 退出 1 | ✅ |

**没验的**（`未跑` 的真正含义）：真实 `DescribeListeners` 返回的 JSON 结构、`-not-expect` 在真实
listener 上的判定、以及**监听器级** `multi_cert_info` / `ExtCertIds` 这条表示路径。至于"续期 A 确实
不动 B"这个被测行为本身，已经在真机上按**规则级绑定**观测到（见顶部横幅与
[`e2e-run-2026-09-17-credentialed.md`](e2e-run-2026-09-17-credentialed.md) §4.3/§4.9）。

---

## 5. 跑完要人来判的几件事

脚本给出机械 PASS 之后，下面这些它**没有**也不会替你回答：

1. **读到的是不是你以为的那个 listener。** 第 3 步的 `-raw` 里 `ListenerId`、`Protocol`、`Port`、
   `SniSwitch` 都要看一眼。`wecert-clbverify` 的注释记录过一个真实现象：**按 `ListenerIds` 过滤时，
   返回的条目可能没有 `Certificate` 字段**。脚本对此有兜底（检测到就改用不过滤的查询，
   并按 `ListenerId` 从结果里挑），但兜底会把工具自身的断言跳过 —— 那时判定完全依赖脚本的解析，
   更该人工看原始 JSON。
2. **主证书是不是 A。** 这是脚本唯一"按预期模型"下的强断言。如果真实 listener 把两张证书
   **都**报成 `ExtCertIds`（`CertId` 为空），脚本会 FAIL —— 那个 FAIL 不是 bug，而是一个**关于
   服务端表示方式的新事实**，应当先记下来，再决定断言怎么改。
3. **B 同一张证书是否还在服务。** 控制面说 B 还绑着，不等于 B 的域名还能握手成功。
   真要证，得对 B 的 SNI 名字拨一次真连接：
   ```bash
   openssl s_client -connect <clb-vip>:443 -servername <B 的域名> -showcerts </dev/null 2>/dev/null \
     | openssl x509 -noout -subject -issuer -dates
   ```
   或 `./bin/wecert-probe -host <B 的域名>`。
4. **新主证书是不是真的在服务。** 同理，对 A 的域名拨一次。`wecert_certificate_probe_match{host}`
   是这条的持续化版本 —— 控制面与真实握手不一致时它会是 0。
5. **这次到底是不是一次"续期"。** 脚本的断言在"新签了一张并换上去"和"续期换绑"下都会通过。
   `journalctl` 里的 `certificate renewed and live cert=... deployedCertId=...` 才是路径证据。

---

## 6. 与其它文档的分工

| 文档 | 管什么 |
|---|---|
| 本文 + [`scripts/e2e-sni.sh`](../scripts/e2e-sni.sh) | SNI 多证书：**带断言的、可复核的**一次验证 |
| [`docs/staging-checklist.md`](staging-checklist.md) §4 | 同一件事的人工清单形态（两张表，无脚本） |
| [`docs/stage-c-cvm-systemd.md`](stage-c-cvm-systemd.md) | L4 的另一半：真机 + systemd + CVM 角色 |
| [`testenv/README.md`](../testenv/README.md) Stage B2 | 建一个 SNI listener + 多 SAN 证书 + CVM 后端的环境 |
| [`docs/test-plan.md`](test-plan.md) §6 | 为什么这件事结构上只能人工 |

---

## 变更记录

| 日期 | 变更 |
|---|---|
| 2026-09-17 | 首版。**未跑**：本机无腾讯云凭据；脚本的机器可验部分用桩验证（见第 4 节） |
| 2026-09-18 | 顶部横幅与第 1、4 节按实跑更正：**脚本仍未在任何真实 listener 上执行**（本账号忽略监听器级绑定，`extCertIds` 恒空），但"续期一张不动另一张"已在 2026-09-17 §4.3/§4.9 与 2026-09-18 §4.4 的真机运行中、按**规则级绑定**加独立 TLS 握手观测到；未验的改为监听器级 `multi_cert_info` / `ExtCertIds` 这条表示路径 |
