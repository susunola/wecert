# wecert 真实云 E2E 实跑报告（带凭据 · 2026-09-17）

> 范围：一轮针对**真实 Let's Encrypt staging** 与**真实腾讯云账号**的端到端实跑，外加本轮暴露的缺陷。
>
> 记号约定：**通过** / **失败** / **未完成** 都指本文件记录的那一次执行；没有证据的一律写 **未跑** 或 **未验证**，不写成"应该可以"。
>
> 配套文档：离线 pebble 轮见 [`docs/e2e-run-2026-09-17.html`](e2e-run-2026-09-17.html)（那一轮证明协议与 profile 选择，不证明真实 DNS 与真实 CLB）；部署侧分层见 [`testenv/README.md`](../testenv/README.md)；用例编号见 [`docs/test-plan.md`](test-plan.md)。

---

## 1. 一句话结论

本轮用真实 LE staging 签出了证书，首次在真实 CLB 上证明了**只换掉一张证书不会动到同一监听器上的另一张**（SNI 按规则隔离，独立 TLS 握手机位复核），并在一台真机 Ubuntu 上跑通了 **systemd + CVM 角色**的一轮完整签发（`install.sh` 装出的路径约定与加固项都成立，机器上没有任何静态密钥）；但同时也证明了两件事在**当前账号条件**下不可用：DNS 传播判据会因权威节点对本机**瞬时不可达**而放行尚未全局传播的记录（第一次 L1 因此被 CA 判 `NXDOMAIN`），以及部署校验的 30s 固定预算会让**云端已经成功**的换绑永远无法回写成功状态，`deployed_cert_id` 停留在旧证书、`not_after` 停留在 0（该缺陷已修复，并在同一账号同场景复跑一次即收敛，见 4.6 与 5.2）。

---

## 2. 环境与凭据

| 项 | 本轮取值 |
|---|---|
| ACME | `https://acme-staging-v02.api.letsencrypt.org/directory`（**仅 staging**，未使用 production 配额） |
| 云账号 | 一个**共享**的腾讯云账号；存在他人资源，本轮只操作自己创建的对象 |
| 凭据 | AK/SK 来自仓库外的 `0600` 文件，由环境变量注入；**全程未回显、未入库、未写入任何被测文件** |
| CLB | **INTERNAL** 实例（避免 EIP 与公网计费），region `ap-guangzhou` |
| DNS | 真实 DNSPod，DNS-01 |
| 收尾 | 本轮创建的 CVM / CLB / 证书 / CAM 角色与策略 / TXT 全部按 ID 删除，见第 8 节 |

命令与配置：`scripts/e2e-test.sh` + 临时配置 `/tmp/wecert-e2e/l1-config.yaml`（`statePath` 指向一次性库，`credentialMode: static`，凭据只从环境读）。

---

## 3. 用例与结果

| 用例 | 命令 / 入口 | 结果 | 证据 |
|---|---|---|---|
| L1 单域名真实签发 | `scripts/e2e-test.sh atomwangnus.com /tmp/wecert-e2e/l1-config.yaml` | **通过**（第 2 次尝试） | 证书签发成功、`ari_cert_id` 已写入、`orders left behind: 0`、上传证书 ID `ariMhKEO`、notAfter `2026-12-16`；第二轮未复用订单（幂等 ok） |
| L1 首次尝试 | 同上（11:55 那次） | **失败** | 传播检查 21s 即返回 `TXT propagated`，随后 CA 回 `NXDOMAIN looking up TXT for _acme-challenge.atomwangnus.com` |
| 双 SAN 泛域名 + SNI 隔离 | `testenv/` + 规则级证书绑定 + `UpdateCertificateInstance` | **通过** | 换绑后 alpha 变为 `CN = *.alpha.atomwangnus.com`，beta 指纹与基线逐字节一致（见 4.3） |
| 部署状态回写 | 上述换绑后 wecert 的校验阶段 | **失败** | 连续 3 次 `success=1 failed=0` 但枚举超时；`deployed_cert_id=ariXUn7n`、`not_after=0`、`consecutive_failures=3` |
| 部署状态回写（修复后复跑） | 同上，二进制 `355655e` | **通过** | 一次 pass 内收敛：`deployed_cert_id=asH7jREM`、`not_after=2026-12-16`、`consecutive_failures=0`、`orders=0`，旧证书 `asGojB81` 进入回收清单；规则级握手复核新证书已在服务（见 4.6） |
| Stage C 安装 + systemd + 角色 | `install.sh` on Ubuntu 22.04 CVM + `systemctl enable --now wecert` | **通过** | `install.sh` 装出 `/usr/local/bin/wecert`（sha256 与本机交叉编译产物逐字节一致）、`/etc/wecert/config.yaml 0640 root:wecert`、`/var/lib/wecert 0700 wecert:wecert`；unit `active`；`credentialMode=cvm-role` 下完成一轮真实签发并上传（见 4.5） |
| apex + `*.apex` 单证书（真实 LE） | — | **未跑** | 本轮未执行 |
| `profile: tlsserver`（45 天）真实续期 | — | **未跑** | 真实 LE 侧未跑；profile 选择仅由离线 pebble e2e 覆盖 |
| 共享 apex + wildcard TXT 名（真实 DNSPod） | — | **未跑** | 本轮未执行 |

---

## 4. 关键证据

### 4.1 第一次 L1：传播判据说"好了"，CA 说 NXDOMAIN

```
TXT propagated zone=atomwangnus.com. nameservers=10 records=1
```

21s 就得出这个结论，紧接着 CA 侧：

```
validation failed ... DNS problem: NXDOMAIN looking up TXT for _acme-challenge.atomwangnus.com
```

第二次等待 66s 后通过。两次命令完全相同，差别只在等待时长——所以这不是"偶发网络抖动"一句可以带过的现象，而是判据本身的性质问题。

### 4.2 受控实验：滞后节点 + 本机可见性抖动

自建采样器 `/tmp/wecert-e2e/lagsampler`（Go，`github.com/miekg/dns`）每 2s 轮询 `atomwangnus.com` 的 **全部 10 个权威地址**（`a/b/c.dnspod.com` 三个 NS 名解析出 10 个 A）外加 3 个公共递归。经 DNSPod API 写入一条 TXT `_wecert-lagtest.atomwangnus.com`（日志 `/tmp/wecert-e2e/lagtest-add.log`）：

```
# a.dnspod.com -> 101.227.168.75:53 117.135.128.175:53 43.130.172.75:53 43.134.249.74:53
# b.dnspod.com -> 163.177.5.79:53 220.196.136.75:53 43.161.3.75:53
# c.dnspod.com -> 112.80.181.175:53 125.94.59.175:53 43.134.249.75:53
12:01:00 t+4.0    s 112.80.181.175:53        UNREACHABLE
12:01:06 t+6.7    s 101.227.168.75:53        NOERROR AA lagtest-17
12:01:06 t+6.7    s 117.135.128.175:53       NOERROR AA lagtest-17
12:01:06 t+6.7    s 43.134.249.74:53         NOERROR AA lagtest-17
12:01:06 t+6.7    s 163.177.5.79:53          NOERROR AA lagtest-17
12:01:06 t+6.7    s 220.196.136.75:53        NOERROR AA lagtest-17
12:01:06 t+6.7    s 43.161.3.75:53           NOERROR AA lagtest-17
12:01:06 t+6.7    s 112.80.181.175:53        NXDOMAIN AA no-value
12:01:06 t+6.7    s 125.94.59.175:53         NOERROR AA lagtest-17
12:01:06 t+6.7    s 43.134.249.75:53         NOERROR AA lagtest-17
12:01:06 t+6.7    s rec/8.8.8.8:53           NOERROR lagtest-17
12:01:06 t+6.7    s rec/223.5.5.5:53         NOERROR lagtest-17
12:01:06 t+6.7    s rec/119.29.29.29:53      NOERROR lagtest-17
12:02:13 t+76.2   s 112.80.181.175:53        NOERROR AA lagtest-17
```

读法：**10 个权威地址里 9 个、以及 3 个递归解析器，都在约 7s 内看到了值**；而 `112.80.181.175`（`c.dnspod.com`）在 t+6.7s 用 **AA 标志**回答 `NXDOMAIN`，直到 **t+76.2s** 才确认。同一条日志还显示这些地址在"能回答"与 `UNREACHABLE` 之间反复切换（`112.80.181.175` 在 t+76.2 / 135.8 / 141.8 / 191.1 / 194.4 … 多次翻转），也就是说**探针能否看见某个权威节点本身就是不确定的**。

事后佐证：失败那一轮的 TXT 被刻意留在原处（清理只在 Phase 5、且要求所有 authorization 已 valid 时才跑，见 `internal/acme/manager_flow.go`），几分钟后 `112.80.181.175` 仍**同时**拿着失败轮与通过轮的两个旧值，而 `a.dnspod.com` 两个都不再提供；同时 DNSPod API 列出的 `_acme-challenge` 记录数为 **0**（源站侧的删除确实发生了）。

### 4.3 SNI 隔离：独立机位的 TLS 握手

环境：`testenv/` terraform，region `ap-guangzhou`，**INTERNAL** CLB `lb-emeum3re`（VIP `10.99.1.8`），HTTPS 监听器 `lbl-jamh4yjs` 开启 SNI，两条规则 `test.alpha.atomwangnus.com` / `test.beta.atomwangnus.com`。

该账号**无法关闭 SNI**（`ModifyListener` 传 `SniSwitch=0` 返回 `FailedOperation: Can't turn off SNI`），且**监听器级证书被静默忽略**，因此证书只能挂在规则上。两条规则**故意绑两张不同证书**：alpha -> `ariXUn7n`（自签占位 `placeholder.wecert-test.invalid`），beta -> `arqTe8Wv`（自签占位 `placeholder2.wecert-test.invalid`），通过 `ModifyDomainAttributes` 绑定。

基线（VPC 内 CVM 上经 TAT 执行握手）：alpha `CN=placeholder.wecert-test.invalid`，beta `CN=placeholder2.wecert-test.invalid`。

随后 wecert 用 LE staging 签出**一张带两个泛域名 SAN** 的证书（`*.alpha.atomwangnus.com`、`*.beta.atomwangnus.com`），上传为 `arqodPGa`，并以 `oldCertificateId=ariXUn7n` 调 `UpdateCertificateInstance`；一键更新返回 `success=1 failed=0 running=0 pending=0`。

换绑后**同一机位、同一条握手命令**的输出（`/tmp/wecert-e2e/sni-after.txt`）：

```
== SNI test.alpha.atomwangnus.com
subject=CN = *.alpha.atomwangnus.com
issuer=C = US, O = Let's Encrypt, CN = (STAGING) Baloney Bulgur YE2
sha256 Fingerprint=84:55:E5:79:34:C2:A3:67:EB:63:B2:39:84:49:56:70:F8:C1:D8:3C:43:BD:7B:15:82:11:E7:BC:79:93:C6:AA
== SNI test.beta.atomwangnus.com
subject=CN = placeholder2.wecert-test.invalid
issuer=CN = placeholder2.wecert-test.invalid
sha256 Fingerprint=66:59:E7:BD:23:F9:30:F6:29:AC:7C:50:F5:8B:84:72:8C:DD:7E:82:E2:C2:3C:43:53:77:E7:F9:D0:25:93:7D
```

beta 的 subject / issuer / 指纹与基线**逐字节一致**：换掉 alpha 的证书没有扰动 beta。这个结论来自**独立的 TLS 握手机位（VPC 内）**，而不是部署 API 自己的回执。

附带发现的约束：部署 API 会把**新证书的域名**与**资源的域名**做匹配。当规则名还是 terraform 默认的 `test.alpha.wecert-test.invalid` / `test.beta.wecert-test.invalid`、而证书是 `*.alpha.atomwangnus.com` 时，`UpdateCertificateInstance` 直接失败：

```
FailedOperation.CertificateDeployInstanceEmpty
系统未检测到可用实例…请您核对证书域名与云资源实例是否匹配
```

只有把 `clb_rule_domains=["test.alpha.atomwangnus.com","test.beta.atomwangnus.com"]` 对齐之后，换绑才成立。

### 4.4 部署校验：云端成功，状态库说没成功

`internal/deploy/tencent.go` 给异步枚举 `DescribeCertificateBindResourceTaskResult` 的预算是**固定 30s**：

```go
deadline := d.now().Add(30 * time.Second)
...
return bindingCount{}, fmt.Errorf("the bind-resource enumeration did not finish within 30s (taskId=%s)", taskID)
```

本账号上的实测：同一次枚举**已缓存时约 25s**，冷的时候更久；本轮 wecert 的三次 pass 都撞到 30s 上限（`taskId=2562464`、`2562489`，以及 L1 轮较早的 `2562034`，那次只是 warning）。`2562464` 的抓取里，连续 6 次 poll 返回的 `CacheTime` 全部是 `2026-09-17 14:05:19`，即直到抓取结束都还停在同一个缓存快照上。

状态库直读（`/tmp/wecert-e2e/state-sni.db`，只读打开）：

```
cert: ('two-san-wildcard', 'ariXUn7n', 0, 3)
        name                deployed_cert_id  not_after  consecutive_failures
```

即：`deployed_cert_id` 仍是**旧的、此刻已经不绑任何规则**的 `ariXUn7n`，`not_after` 仍是 **0**（1970），`consecutive_failures` 已达 **3**。

观察到的循环（连续 3 次 pass，退避 60s -> 120s -> 240s）：每次 pass 都复用仍然有效的 ACME 订单，部署记录报 `success=1`，随后校验超时，pass 被判失败，状态不留新证书 ID。

### 4.5 Stage C：真机 systemd + CVM 角色，一轮完整签发

安装（`install.sh`，Ubuntu 22.04，`img-487zeit5`）：

```
-rwxr-xr-x 1 root   root   16410434 /usr/local/bin/wecert        # 截断后 sha256 与本机产物一致
drwxr-x--- 2 root   wecert     4096 /etc/wecert
drwx------ 2 wecert wecert     4096 /var/lib/wecert
-rw-r----- 1 root   wecert    16305 /etc/wecert/config.yaml
sha256(installed) = e9a3d0f9a5f53013580484333fb1ca2c...          # 与本机交叉编译产物相同
```

> 传输方式说明：runbook 的三条路里，"在 CVM 上编译"因为该实例**出方向被限速**（模块里 Go module 缓存 25 分钟只下了 124K）而不可行；改用本机交叉编译 + 通过实例入方向 HTTP 分块推送（63 × 256KB），落盘后 `sha256sum` 与本机一致才安装。

systemd 单元（`systemctl show wecert`）：

```
ActiveState=active
User=wecert
StateDirectory=wecert
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=            # 空集：没有任何 capability
Environment=                      # 空：单元里没有任何密钥
```

第一轮的真实签发（`journalctl -u wecert`）：

```
level=INFO msg="Tencent Cloud deploy enabled" credentialMode=cvm-role resourceTypes=[clb] regions=[ap-guangzhou]
level=INFO msg="ACME order created" cert=stage-c status=pending names=1 profile=classic replaces=false
level=INFO msg="TXT presented" cert=stage-c identifier=atomwangnus.com name=_acme-challenge.atomwangnus.com.
level=INFO msg="TXT propagated" zone=atomwangnus.com. nameservers=10 records=1
level=INFO msg="certificate uploaded; waiting for a one-time manual bind in the CLB console" cert=stage-c notAfter=2026-12-16T05:36:29.000Z uploadedCertId=art3KPze
level=INFO msg="reconcile pass finished" duration=1m12.931s
```

这一段同时证明了角色凭证路径可用：写 DNSPod 记录（`TXT presented`）与调用 SSL `UploadCertificate`（`certificate uploaded`）都发生在**机器上不存在任何静态密钥**的前提下 —— `/etc/wecert` 与二进制里 grep `SECRET_ID` / `SECRET_KEY` 均无命中，单元的 `Environment` 为空。

指标（`curl http://127.0.0.1:9800/metrics`）：

```
wecert_certificate_not_after_timestamp_seconds{cert="stage-c"} 1.797399389e+09
wecert_last_reconcile_timestamp_seconds 1.7896269037932992e+09
wecert_reconcile_total{cert="stage-c",result="ok"} 1
```

状态库：`/var/lib/wecert/state.db`（`0600 wecert:wecert`，目录 `0700`），另有 `state.db.lock`、`state.db-shm`、每日快照各一份，全部归 `wecert` 所有。

注意：`certificate uploaded; waiting for a one-time manual bind in the CLB console` 是产品设计的**首签行为**（CLB 控制台手工绑定一次，之后靠 `UpdateCertificateInstance` 自动换绑）；本轮未做这次手工绑定，所以 Stage C 的"之后自动重绑"这一段仍未跑，见第 6 节。


### 4.6 修复后在真实账号上的复核（同一场景重跑）

同一账号、同一场景（内部 CLB + 两个规则绑着一张占位证书 + 双泛域名 SAN），换成带修复的二进制（`main.version=355655e`）重跑一次签发 + 换绑：

```
level=INFO msg="TXT propagated" zone=atomwangnus.com. nameservers=9 records=2
level=WARN msg="the one-click update reported nothing to switch, but the new certificate is bound and the old one is not; treating the switch as done (the rebind succeeded without being recorded)" oldCertId=asGojB81 newCertId=asH7jREM boundResources=1
level=INFO msg="certificate renewed and live" cert=two-san-wildcard notAfter=2026-12-16T11:26:57.000Z daysLeft=90 deployedCertId=asH7jREM ariCertId=true
```

状态库（`/tmp/wecert-e2e/state-fix.db`）：

```
two-san-wildcard|asH7jREM|2026-12-16 11:26:57|0|      # name | deployed_cert_id | not_after | consecutive_failures
orders|0                                              # 订单已收尾，不再每轮重跑
retired|asGojB81                                      # 旧证书进入回收清单
```

独立机位复核（CVM 内 TLS 握手，VIP `10.99.1.16`）：

```
== SNI test.alpha.atomwangnus.com
subject=CN = *.alpha.atomwangnus.com   issuer=C = US, O = Let's Encrypt, CN = (STAGING) Artificial Amaranth YE1
== SNI test.beta.atomwangnus.com
subject=CN = *.alpha.atomwangnus.com   issuer=C = US, O = Let's Encrypt, CN = (STAGING) Artificial Amaranth YE1
```

收尾幂等：紧接着再跑一次 `-once`，没有新订单、`deployed_cert_id` 与 `not_after` 不变，只刷新了 ARI 窗口。

两点如实说明：

- 这次**修复后的真实路径不是哨兵分支**：预算放宽到 3 分钟后，枚举在预算内给出了答案，于是走的是既有的"旧证书 0 绑定、新证书有绑定 -> 认定切换已发生"的恢复判定（上面那条 WARN）。哨兵分支（枚举超时 / 未覆盖全部 region）本轮在真实账号上**没有被触发**，它只有单元测试与变异校验覆盖。
- 本轮 `TXT propagated` 报的是 `nameservers=9`（前几次是 10），即探测时有一个权威地址不可达；结论仍要求"无否认 + >= 2 个 NS 名确认"，5.1 描述的口径问题不因这次通过而消失。

---

## 5. 发现的问题

### 5.1 DNS 传播判据把"看不见"当成"没问题"

- **现象**：第一次 L1 在 21s 就宣布 `TXT propagated`，CA 随即以 `NXDOMAIN` 拒绝；同一命令第二次等 66s 即通过。
- **证据**：4.1 的两条日志行；4.2 的采样器结果（9/10 权威 + 3 递归在 ~7s 内可见，`112.80.181.175` 在 t+6.7s 以 AA 回答 `NXDOMAIN`、t+76.2s 才确认）；同批地址在本机反复 `UNREACHABLE`；失败轮 TXT 残留后 `112.80.181.175` 仍同时持有两个旧值，而 DNSPod API 侧记录数为 0。
- **根因**：判据是"**没有可达的权威服务器否认该值，且至少 1 个确认**（多权威时要求 >= 2 个 NS 名）"（`internal/acme/dns.go`，`probeReadyWithExchange`）。一个**此刻从 wecert 主机不可达**的滞后节点贡献不了任何信息，于是判据可以在它其实还在发 `NXDOMAIN` 的时候判过。**该判据是全局传播的下界，且其结论依赖于 wecert 所处的网络机位**；而 CA 的解析器恰恰能到达那个节点。
- **影响**：授权验证失败会消耗 **5 authorization failures per identifier / 小时** 这一不可恢复配额；更糟的是它表现为"偶发"，容易被误判成 CA 侧抖动而重试，从而继续烧配额。
- **已实现（本轮，零风险的一半）**：`TXT propagated` 这条**成功**日志现在带上它据以判断的证据，而不只是服务器数量——每轮的完整 summary（`confirmed N/M server(s) / denied … / non-authoritative … / unreachable …`）都会打印出来。理由是这条判定是全局传播的**下界**、且来自本机视角，出了事故回头看日志时，"当时有多少权威地址其实是看不见的"必须可查；此前只有 `nameservers=10 records=1`，看不出来。已加测试 `TestPropagatedVerdictLogsItsEvidenceIncludingUnreachableAuthorities` 并做变异校验（把该字段去掉，测试立刻变红）。
- **建议修法（仍未实现）**：把"看不见"从"没问题"里拆出来。（a）在 `probeReadyWithExchange` 里区分"**明确否认**"与"**不可达**"，并对**不可达**单独设阈值：当可达权威地址数低于该 zone 的一个比例（例如写死一个下限，或要求 >= 2/3 的 NS 名）时，**不判过**而是继续等，并把 `unreachable` 计入决策而不是只计入 summary 文本。（b）对同一地址做**连续多轮确认**，用"连续 N 轮一致"代替单轮快照，避免一次 ICMP/UDP 抖动就改变结论。（c）把每条记录的实测等待时长与最终 `unreachable` 计数写进日志与指标，让"这次是靠运气过的"在事后可查。

### 5.2 部署校验的 30s 固定预算，把"未验证"写成"失败"（最严重）

- **现象**：连续 3 次 pass 都一样——复用有效订单 -> 部署记录 `success=1` -> 枚举超时 -> pass 失败；`deployed_cert_id`/`not_after` 永远不更新。
- **证据**：4.4 的代码行、三次 `taskId`（`2562464` / `2562489` / `2562034`）、6 次 poll 同一 `CacheTime`、状态库读出 `('two-san-wildcard','ariXUn7n',0,3)`、退避 60s -> 120s -> 240s。
- **根因**：`internal/deploy/tencent.go` 里延迟枚举的预算是**常量 30s**，而本账号的同一枚举**已缓存时约 25s**、冷启动更久——预算与真实耗时同一个量级，必然间歇性击穿。而击穿的处理方式是 `return ... error`，于是一次**校验超时**被当成一次**部署失败**：云端早已成功，状态层却退回旧状态。代码里"拒绝在未经验证的切换上报告成功"的意图是对的，错在把两种不同的东西合并成了同一种失败。
- **影响**：状态库显示"未部署 / 到期时间 1970"，而 CLB 实际在服务新证书。真实的续期**永远不会被记为完成**，到期类指标与告警会对着一个健康证书报过期（告警不可信，正是 `docs/test-plan.md` 列为最高代价的失效形态）；同时因为 `deployed_cert_id` 指向旧证书，后续 pass 仍会认为"该换绑"而重复动作。**在当前账号上，"继续失败"这条路径可证明不收敛**：同一枚举耗时稳定压在 30s 附近，重试只会重复同一个超时。
- **修法（已实现，见 4.6 的真实账号复核）**：两件事一起做，一个改动对应一条性质。
  1. **预算可配且足够长**：30s 常量换成部署器上的 `enumerationBudget`（默认 `defaultEnumerationBudget = 3 * time.Minute`，测试可缩短）。理由写在常量注释里：枚举是服务端的异步缓存，耗时不属于我们；一个"永远答不上来"的校验比"多等一会儿"更糟，而它每次部署只跑一次。
  2. **把"已成功但未验证"建成显式结果**：新增哨兵错误 `deploy.ErrSwitchUnverified`（`internal/deploy/deployer.go`）。枚举**超时**、或**没覆盖全部 region** 这两种"不知道"的情况返回它，而**"枚举已完成且绑定数为 0"仍然是硬失败**——那确实是一次没有发生的切换。ACME 层（`internal/acme/manager_done.go`）识别该哨兵后：记录新证书 ID、**完成订单**（不再每轮重跑同一个 deploy）、`DeployConfirmed` 保持 `false`（部署指标在确认前不说谎），下一轮由既有的绑定探测（`confirmBinding`）确认后自动置真。
  两条性质各自被测试钉住（`TestAdoptedTaskWhoseEnumerationNeverAnswersIsUnverifiedNotFailed`、`TestUnverifiedSwitchIsRecordedAsDeployedButUnconfirmed`），并做了变异校验：把哨兵换掉、或把 `unverified` 分支关掉，测试立刻变红。

### 5.3 默认镜像不带 TAT agent，Stage C runbook 起不来

- **现象**：`wecert-tatrun` 每次调用都失败 `ResourceUnavailable.AgentNotInstalled`，`DescribeAutomationAgentStatus` 返回空集。
- **证据**：本模块默认的公共 Ubuntu 镜像 `img-487zeit5` 启动后**没有 TAT agent**；`testenv/README.md` 与 `docs/stage-c-cvm-systemd.md` 却把整个 Stage C 流程都建立在 TAT 之上。在 `testenv/cvm.tf` 的 `runcmd` 里补上官方安装步骤后重建实例，agent 报 `AgentStatus: Online`（版本 1.2.2），TAT 命令才可执行：

  ```sh
  wget -qO - https://mirrors.tencentyun.com/install/tat_agent/tat_agent_installer.sh | sh
  ```

- **根因**：镜像选型与 runbook 假设不一致——文档假定 TAT 可用，而该镜像不带 agent，且没有任何一处校验"agent 在线"就进入 TAT 步骤。
- **影响**：Stage C 的所有步骤在第一步就失败，且失败信息（`AgentNotInstalled`）指向的是"命令没跑成"，容易被误读成权限或参数问题。
- **建议修法**：保留 `cvm.tf` 里的安装步骤（已生效），并把"agent 在线"做成 runbook 的**前置断言**：进入 TAT 步骤前先 `DescribeAutomationAgentStatus`，非 `Online` 就直接失败并给出安装/重建指引；同时在 `testenv/README.md` 注明该镜像需要自装 agent。

### 5.4 环境前置条件未文档化：CAM 角色需预建，Stage B 在本账号不可达

- **现象（角色）**：`terraform apply` 失败 `AuthFailure.CamRoleNameAuthenticateFailed: The specified CamRoleName wecert-test-role authenticate failed.`
- **现象（Stage B）**：`scripts/run-stage-ab.sh` 在 pre-rebind 检查处中止，`wecert-clbverify` 报 "the listener has no certificate bound"。
- **证据**：`testenv/` 需要 `cam_role_name` 指向的角色**预先存在并已挂策略**，terraform 只引用、不创建；账号内原本没有任何角色，手动创建 `wecert-test-role`（信任策略允许 `cvm.qcloud.com`）并挂上 `deploy/cam-policy-runtime.json`（策略名 `wecert-test-runtime`）之后 CVM 才能创建。Stage B 侧：因为该账号 SNI 被强制开启、监听器无法关闭 SNI，监听器上**根本没有证书**（证书只能挂在规则上），因此文档里"`terraform apply` 之后监听器已绑占位证书"的前提不成立，Stage B 的换绑路径只能走本轮使用的**规则级**设置。
- **根因**：两处都是"文档假设的环境"与"真实账号状态"不一致：一个是 External 前置资源（CAM 角色）未列入 apply 前置检查，一个是"监听器可绑主证书"的假设在强开 SNI 的账号上不成立。
- **影响**：新环境按 README 走会在 `terraform apply` 或 Stage B 第一步失败，且两次失败的报错都不直接指向根因（角色缺失 / SNI 强制）。
- **建议修法**：把 CAM 角色与策略的创建写成可选 terraform 资源（或独立的 `bootstrap` 目录）并在 README 里列为步骤 0；在 Stage A/B 脚本里加一条前置探测——读监听器的 SNI 开关与证书绑定状态，若"SNI 强开且监听器无证书"就直接跳过 Stage B 并提示改用规则级绑定，而不是等到 pre-rebind 检查再中止。

### 5.5 一个按"到期时刻"变红的测试：断言边界用了错误的时钟

- **现象**：本轮加修复后跑 `go test -race ./...` 时，`TestRenewalArchivesTheOutgoingCertificateMaterial` 变红（`expected the outgoing certificate on the reclaim list, got []`），而该行为在当时的提交上并没有被改动；把工作区回到 HEAD 单独跑，它同样变红。
- **证据**：该测试把 manager 的时钟钉在 `fixed = 2026-09-16 12:00 UTC`，却用 `ListRetiredCertsBefore(fixed.Add(24 * time.Hour))` 去查回收清单；而 `internal/state/state.go` 的 `addRetiredCertExec` 写 `retired_at` 用的是**存储层自己的** `time.Now().Unix()`。临时插入的调试输出（验证后已删）说明了一切：

  ```
  fixed=2026-09-16 12:00:00 +0000 UTC   bound=2026-09-17 12:00:00 +0000 UTC   realNow=2026-09-17 12:20:00 +0000 UTC
  ```

  即：它只在真实时钟早于 `2026-09-17 12:00 UTC` 时通过，本轮跑到 12:20 UTC 时它自己到期了。
- **根因**：断言的时间边界来自被测对象**注入的**时钟，而被断言的状态由存储层**自己的**时钟写入——两个时钟不同源，测试里因此埋了一个绝对的"到期时刻"（正是 `docs/test-plan.md` 里"墙钟语义"那一类问题的测试侧版本）。
- **影响**：套件会在某个固定时刻之后无条件变红，与代码质量无关；这类失败最容易被误读成"上一个提交改坏了"，本轮确实先花时间排除了自己的改动。
- **修法**：已把边界改成存储层时钟（`ListRetiredCertsBefore(time.Now().Add(time.Hour))`）并写明理由——断言关心的是"旧证书的材料有没有被归档"，不是"何时归档"。同时确认它仍在测该测的东西：把 `retireOld` 置为 `false` 后该测试立刻变红。一般规则：断言带时间戳的状态时，边界要用**写状态的那个时钟**，不要用被测对象注入的时钟反推。

---

## 6. 未跑 / 不能证明的东西

以下每项都**未跑**或**未验证**，不应从本轮结果外推：

| 项 | 状态 | 说明 |
|---|---|---|
| apex + `*.apex` 单证书（真实 LE staging） | **未跑** | 本轮只跑了单域名与双泛域名 SAN；共享 TXT 名的合并逻辑仅由离线 pebble 轮覆盖 |
| 共享 apex + wildcard TXT 名（真实 DNSPod） | **未跑** | 真实 DNSPod 上未验证两个值是否同时在线 |
| `profile: tlsserver`（45 天）真实 LE 续期 | **未跑** | 真实 LE 侧未跑完整自动续期；profile 选择只有离线 pebble e2e 覆盖 |
| Stage C 安装 / systemd / 角色凭证路径 | **通过** | 见 4.5：`install.sh` 装出的路径约定、加固项、`cvm-role` 下的一轮真实签发与上传都成立 |
| Stage C 的"首签后手工绑定 → 之后自动换绑" | **未跑** | 本轮未在 CLB 控制台做那次一次性手工绑定，因此这一段链路未验证 |
| 传播判据在其它域名/网络机位是否同样偏乐观 | **未验证** | 只有 `atomwangnus.com` 一个 zone 的采样数据 |
| 5.2 的修法能否在本账号收敛 | **已验证** | 修复后同场景复跑一次即收敛（见 4.6）；但触发的是恢复判定而非哨兵分支，哨兵分支仅有单元测试覆盖 |
| 关闭 SNI 后 Stage B 原路径是否可用 | **未验证** | 本账号无法关闭 SNI，因此这条路径无法被本账号证伪或证实 |
| 生产（非 staging）LE 配额与签发行为 | **未跑** | 全程 staging |

另外要明确：**"L1 通过"只说明第二次那一条命令在该时刻成功**，不说明传播等待时长是确定的；两次尝试的差异恰恰是本报告 5.1 的主题。

---

## 7. 复现步骤

凭据一律从仓库外的 `0600` 文件读入，命令中只出现占位符，不出现任何真实值。

```sh
# 0) 凭据：写在仓库外、权限 0600，仅通过环境变量注入；不要写进任何配置文件
export TENCENTCLOUD_SECRET_ID=<your-ak>
export TENCENTCLOUD_SECRET_KEY=<your-sk>

# 1) 构建
make build

# 2) L1：单域名真实签发（staging + 真实 DNSPod DNS-01 + 上传腾讯云 SSL）
#    配置样例见仓库根目录 e2e-config.example.yaml；statePath 指向一次性库
cp e2e-config.example.yaml /tmp/wecert-e2e/l1-config.yaml
$EDITOR /tmp/wecert-e2e/l1-config.yaml   # statePath / acme.email / 域名自行替换
scripts/e2e-test.sh <your-domain> /tmp/wecert-e2e/l1-config.yaml
#    e2e-test.sh 会强制校验 directory 必须是 acme-staging，避免误用生产配额

# 3) 传播滞后采样：直接观测"某个权威节点还没跟上 + 本机看不见它"
cd /tmp/wecert-e2e/lagsampler && go build -o lagsampler .
./lagsampler -name _wecert-lagtest.<your-domain>. -ns a.dnspod.com,b.dnspod.com,c.dnspod.com \
  -interval 2s -duration 10m > /tmp/wecert-e2e/lagtest-add.log 2>&1
#    另开一个终端，用 DNSPod API 写入一条同名 TXT，日志里就能看到各地址首次确认的时间差

# 4) SNI 双证书隔离：testenv 需要预先存在的 CAM 角色（见 5.4）
cd testenv
terraform init
terraform apply \
  -var 'cam_role_name=wecert-test-role' \
  -var 'clb_rule_domains=["test.alpha.<your-domain>","test.beta.<your-domain>"]'
#    规则级绑定（监听器级证书在强开 SNI 的账号上会被忽略）：
#    ModifyDomainAttributes 把 alpha/beta 分别绑到两张不同的证书

# 5) 换绑：oldCertificateId 传当前绑在规则上的旧证书
#    wecert 的部署路径会走 UpdateCertificateInstance，随后进入部署校验阶段

# 6) VPC 内独立机位复核握手（TAT 需 agent 在线，见 5.3）
wecert-tatrun --instance <instance-id> --command 'openssl s_client -servername test.alpha.<your-domain> ...'

# 7) 收尾
cd testenv && terraform destroy -var 'cam_role_name=wecert-test-role'
```

注意：**不要**使用会按别名前缀批量删除证书的开关（`-prune-certs`）——共享账号上存在他人的、可能是生产在用的证书。

---

## 8. 清理

本轮结束后的清理动作，逐项列出：

| 动作 | 对象 |
|---|---|
| `terraform destroy` | `testenv/` 整套栈（CVM、CLB 及规则、相关网络资源） |
| 按 ID 删除上传的测试证书 | `ariMhKEO`、`arqodPGa`、`ariXUn7n`、`arqTe8Wv` |
| 删除 CAM | 角色 `wecert-test-role`、策略 `wecert-test-runtime` |
| 删除 DNS | 本轮写入的临时 DNSPod TXT 记录（`_wecert-lagtest`，以及各轮 `_acme-challenge`） |
| 清理历史遗留（非本轮创建） | 上一轮遗留的**公网 CLB** `lb-hwjdqjk4`（其监听器上没有任何证书）、**仍在计费的 CVM** `ins-nlqekrba`（2026-09-15 创建）、以及对应的旧 VPC `vpc-4lfl22wd` 与其子网 |

收尾复核（逐条命令的输出）：

```
wecert-preflight -domain atomwangnus.com
  [1/4] SSL certificate service read access      OK - the account already holds 36 certificates
  [2/4] DNSPod domain ownership                  OK - atomwangnus.com found, status ENABLE, plan DPG_FREE
  [3/4] _acme-challenge leftover check           OK - no leftover TXT records
  [4/4] authoritative nameserver delegation      OK - 3 nameservers, all pointing at DNSPod

clb-list  -> total=0          # 没有遗留 CLB
vpc-list  -> 无 wecert-test-*  # 旧 VPC 已删
DescribeInstances -> 空        # 没有遗留 CVM
DescribeRecordList(_acme-challenge) -> NoDataOfRecord
```

**未触碰**：共享账号上已存在的 `wecert/two-san-wildcard`、`wecert/jerryzhou-live` 等证书，以及他人的任何资源。**刻意未使用** `-prune-certs`：它会删除所有以 `wecert/` 为别名前缀的证书，其中可能包含正在线上服务的证书。
