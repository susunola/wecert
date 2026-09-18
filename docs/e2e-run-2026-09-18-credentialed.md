# wecert 真实云 E2E 实跑报告（带凭据 · 2026-09-18）

> 范围：在**真实 Let's Encrypt staging**、**真实 DNSPod**、**真实 CLB / CVM**（同一个共享腾讯云账号）上，用 `b72d1e3`（含本轮全部修复）重跑一轮端到端，覆盖 09-17 报告 §6 里「已跑但需要复核」的路径，并顺带验证本轮改动的行为。
>
> 记号约定：**通过** / **失败** / **未跑** 都指本文件记录的这一次执行；没有证据的一律写 **未跑** 或 **未验证**。
>
> 配套：上一轮带凭据报告见 [`docs/e2e-run-2026-09-17-credentialed.md`](e2e-run-2026-09-17-credentialed.md)；离线 pebble 轮见 [`docs/e2e-run-2026-09-18.html`](e2e-run-2026-09-18.html)；代码复审报告见 [`docs/code-review-ocr-2026-09-17.md`](code-review-ocr-2026-09-17.md)。

---

## 1. 一句话结论

本轮把「真实签发 → 真实续期 → 真实一键换绑 → 真实吊销」这条主链在同一个账号上完整跑通了：单域名签发、apex + `*.apex` 共用一个 TXT 名（两个值同时在 8–10 个权威地址上）、`profile: tlsserver`（45 天）签发、ARI 驱动的续期（订单带 `replaces=true`）、`UpdateCertificateInstance` 把两条 CLB 规则从占位证书切到新证书（并用**机内心跳**做了 TLS 握手复核）、以及**吊销归档副本**这条本轮新写的逻辑（CA 先接受，再回 `alreadyRevoked`，随后现网证书仍可正常吊销）。Stage C 在真机 systemd + `cvm-role` 下装好并跑完一次真实签发与上传，全程磁盘上没有任何凭据。

本轮真实运行**暴露了两个缺陷**：一个是仓库里的 e2e 脚本（`scripts/e2e-wildcard.sh` 的清理断言没有等待传播，属于**脚手架**，已修 + 自测 5/5），一个是产品工具 `wecert-tatrun`（失败任务的输出没做 Base64 解码，属于**产品**，已修 + 变异校验）。另有一条**行为观察**（从未被绑定的证书在续期时会被云端拒绝换绑）留给你决定，见 §5.3。

---

## 2. 环境与凭据

| 项 | 本轮取值 |
|---|---|
| ACME | `https://acme-staging-v02.api.letsencrypt.org/directory`（**仅 staging**，未使用生产配额） |
| 云账号 | 一个**共享**的腾讯云账号；账号内有他人资源，本轮只操作自己创建的对象，并按 ID 删除 |
| 凭据 | AK/SK 来自仓库外的 `0600` 文件 `~/wbenv`，只经环境变量注入；CVM 侧用实例角色（`wecert-test-role`），配置文件里**没有任何密钥字段** |
| 测试域名 | `atomwangnus.com`（真实 DNSPod zone） |
| CLB | terraform `testenv/` 起的**内网** CLB（`lb-5ymvy3t0`，VIP 10.99.1.4，HTTPS:443，SNI 开），两条规则 `test.alpha.atomwangnus.com` / `test.beta.atomwangnus.com`，一张自签占位证书 `asZ4oo5B` |
| CVM | `ins-84aarw86`（Ubuntu 22.04，S5.MEDIUM2，公网 114.132.153.103，CAM 角色 `wecert-test-role`），全程用 TAT 驱动，无需 SSH |
| 二进制 | `wecert` / `wecert-onboard` / `wecert-tatrun` 均由本机 `make build` + `make tools` 在 `b72d1e3` 构建；CVM 上的 `wecert` 与本机交叉编译产物 **sha256 逐字节一致**（`6cfcec89…f15b18`） |

---

## 3. 用例与结果

| 用例 | 入口 | 结果 | 证据 |
|---|---|---|---|
| L1 单域名真实签发（classic 90 天 + 真实上传） | `scripts/e2e-test.sh atomwangnus.com l1-config.yaml` | **通过**（第 1 次尝试） | 传播 86s、3/3 权威确认；上传 `asXpdG7X`；`orders left behind: 0`；`✅ end-to-end test passed`（§4.1） |
| apex + `*.apex` 共用一个 TXT 名 | `scripts/e2e-wildcard.sh atomwangnus.com wildcard-config.yaml` | **通过**（第 2 次执行） | 峰值 2 个不同值同时在权威上；清理后 0 残留（"deletion took 60s"）；第 1 次执行因**脚手架断言过早**判失败，见 §5.1（§4.2） |
| `profile: tlsserver`（45 天）真实签发 | `wecert -config tls-config.yaml -once` | **通过** | 订单 `profile=tlsserver`；`notAfter=2026-11-01`（09-17 签发 → 恰好 45 天）；上传 `asYt2vjw`（§4.3） |
| 续期（ARI 驱动、带 `replaces`） | 同上，把 ARI 窗口推到过去后 `-once` | **通过（协议层）** | `starting renewal … ariReplaces=true`、`ACME order created … replaces=true`；随后**换绑失败**（当时没有任何绑定），见 §5.3（§4.3） |
| 一键换绑 `UpdateCertificateInstance`（真实规则） | `wecert -config fix-config.yaml -once`（种子：`deployed_cert_id=占位证书`） | **通过** | 两条规则 `cert=asZSMfYB`（新证书）；`deployed_cert_id=asZSMfYB`、`deploy_confirmed=1`；旧证书进回收清单**且带 5148 字节归档材料**；机内 TLS 握手 `subject=CN = *.alpha.atomwangnus.com`、`notAfter=Dec 16 15:53:58 2026`（§4.4） |
| **吊销归档副本**（本轮新逻辑） | 手工插入 `revoke_requests`（身份=旧证书），跑一轮 | **通过** | `the certificate stored for this name is not the one this request targets, so the archived copy is revoked instead of the live certificate` → `CERTIFICATE REVOKED … outstandingFor=10m0s` → 行被清空（§4.5） |
| CA 侧确认旧证书真的被吊销 | 再插一次同身份请求 | **通过** | `the CA reports the certificate already revoked; the request is cleared`（§4.5） |
| 现网证书未被误吊销 | `wecert -revoke two-san-wildcard -revoke-reason superseded -yes` | **通过** | `CERTIFICATE REVOKED … outstandingFor=0s`（不是 alreadyRevoked，说明它此前仍然有效）（§4.5） |
| onboard 守卫 1 在真实 CLB 规则上的 carry 语义 | `wecert-onboard`（`requireCLBRule: true`，真实 `_wecert.` 声明） | **通过** | 第 1 轮两个名字都被服务：`revision sha256:390371e08e674fae`；第 2 轮删掉 `carry-test` 的规则：`mode=unchanged`、`carriedForward=1`、reason 点明 guard 1 且**名字仍在文档里**；第 3 轮恢复规则：`revision` 不变（§4.6） |
| Stage C：install.sh + systemd + `cvm-role` 真实签发 | TAT 推二进制 → `install.sh` → `systemctl enable --now wecert` | **通过** | `credentialMode=cvm-role`；`/usr/local/bin/wecert` sha256 与本机一致；`wecert.service active`、`User=wecert`、`StateDirectory=wecert`；`/etc/wecert/config.yaml 0640 root:wecert`、`/var/lib/wecert 0700 wecert:wecert`；真实签发 `cvm-role.atomwangnus.com` 并上传 `asaUflOn`；配置里 `SecretId/SecretKey/loginToken/password` **零匹配**（§4.7） |
| 配额指标（本轮 `Unreadable`/记账改动的落点） | CVM 上 `curl 127.0.0.1:9800/metrics` | **通过** | `wecert_ratelimit_remaining_tokens{limit="certs-per-exact-identifier-set"} 4.000068…`（容量 5，签发花 1）、`{limit="certs-per-registered-domain",scope="atomwangnus.com"} 49.0006…`、`{limit="new-orders",scope=""} 300`（§4.7） |
| Stage C：首绑 → 自动换绑（09-17 报告 4.9） | — | **未重跑** | 本轮的换绑是在 Stage B 用同样的 `UpdateCertificateInstance` 路径验证的；CVM 侧没有重复"手工绑定"这一步 |
| 自然到期续期（等 30/45 天） | — | **未跑** | 续期窗口都是推出来的 |
| 生产（非 staging）LE | — | **未跑** | 全程 staging |

---

## 4. 关键证据

### 4.1 L1：单域名真实签发

```
00:28:31 level=INFO msg="TXT propagated" zone=atomwangnus.com. nameservers=9 records=1
        evidence="_acme-challenge.atomwangnus.com. = AhPo97Qs… (confirmed 3/3 server(s) / denied 0 /
                  non-authoritative 0 / unreachable 2 (of 9 addresses))"
00:28:50 level=INFO msg="certificate uploaded; waiting for a one-time manual bind …" uploadedCertId=asXpdG7X
orders left behind: 0    ARI certID: 3tpCJfI0wCebZhbPZWqQrCHVMIc.LBIPpubZr_bEo7aHtLg8IyuF
 ✅ end-to-end test passed
```

注意 `unreachable 2 (of 9 addresses)`：9 个权威地址里有 2 个当时不可达，判据仍然给出结论（要求"无否认 + ≥2 个 NS 名确认"）——与 09-17 报告 5.1 的口径一致。

### 4.2 apex + `*.apex` 共用一个 TXT 名

```
time=00:33:17 level=INFO msg="TXT propagated" nameservers=9 records=2
        evidence="… = sKrB_kTXdZPcVtDXJq_-mS_cPbhDZgm6n6EMutF8kxw (confirmed 3/3 …)
                  | … = Og2XqG0OWCI7XdVjkpXbDjd0G0WBbKa8DiKXbvV1dqg (confirmed 3/3 …)"
  ✅ two distinct TXT values were present at _acme-challenge.atomwangnus.com at the same time
  ✅ no TXT values remain at _acme-challenge.atomwangnus.com (the deletion took 60s to reach every authority)
 ✅ wildcard + apex end-to-end: PASS
```

### 4.3 `tlsserver` 45 天 + ARI 续期

```
00:41:58 level=INFO msg="ACME order created" cert=tls-renewal status=pending names=1 profile=tlsserver replaces=false
00:44:17 level=INFO msg="certificate uploaded; waiting for a one-time manual bind in the CLB console"
        cert=tls-renewal notAfter=2026-11-01T15:45:37.000Z uploadedCertId=asYt2vjw
（把 ARI 窗口与 not_after 推到过去后）
00:45:08 level=INFO msg="starting renewal" cert=tls-renewal renewAt=… ariReplaces=true
00:45:09 level=INFO msg="ACME order created" cert=tls-renewal status=ready profile=tlsserver replaces=true
```

09-17 → 11-01 是 45 天，`profile: tlsserver` 在真实 LE staging 上生效；续期订单带 `replaces=true`（ARI 豁免的前提）。

### 4.4 一键换绑：两条真实规则 + 机内握手

```
00:55:30 level=WARN msg="another update task is already in progress; waiting for it and then verifying that
        this certificate is the one that got bound" oldCertId=asZ4oo5B newCertId=asZSMfYB deployRecordId=15409
00:59:49 level=WARN msg="the one-click update reported nothing to switch, but the new certificate is bound and
        the old one is not; treating the switch as done (the rebind succeeded without being recorded)"
        oldCertId=asZ4oo5B newCertId=asZSMfYB boundResources=1
00:59:49 level=INFO msg="certificate renewed and live" cert=two-san-wildcard notAfter=2026-12-16T15:53:58.000Z
        daysLeft=90 deployedCertId=asZSMfYB ariCertId=true
```

云侧独立复核（`DescribeListeners`）：

```
rule loc-1wecg8b2 domain=test.alpha.atomwangnus.com cert=asZSMfYB
rule loc-gwizh3ew domain=test.beta.atomwangnus.com  cert=asZSMfYB
```

机内（CVM，经 TAT）握手复核：

```
subject=CN = *.alpha.atomwangnus.com
notBefore=Sep 17 15:53:59 2026 GMT   notAfter=Dec 16 15:53:58 2026 GMT
serial=2C755EC395A2898CE55613810665325E0B8F
--- beta ---  subject=CN = *.alpha.atomwangnus.com  serial=2C755EC395A2898CE55613810665325E0B8F
```

两条规则的域名都被证书的泛域名覆盖，所以 `UpdateCertificateInstance` 能按域名匹配到实例；这条路径（"云侧自己找绑定并逐个切换"）在真实账号上再次成立。

### 4.5 吊销归档副本（本轮新逻辑，真实 CA）

旧证书（签发时的身份 `s8yDbB3mnRCnevccUfGafmSl5vU.LMKO9PDXE9TAI5Pni9Xh1zqk`）在换绑时进入回收清单，归档材料 5148 字节；把该身份写进 `revoke_requests` 模拟"操作员早先的请求活过了续期"：

```
01:00:27 level=WARN msg="the certificate stored for this name is not the one this request targets, so the
        archived copy is revoked instead of the live certificate"
        requested=s8yDbB3mnRCnevccUfGafmSl5vU.LMKO9PDXE9TAI5Pni9Xh1zqk
        stored=s8yDbB3mnRCnevccUfGafmSl5vU.LHVew5WiiYzlVhOBBmUyXguP
01:00:28 level=ERROR msg="CERTIFICATE REVOKED" cert=two-san-wildcard reason=keyCompromise outstandingFor=10m0s
（revoke_requests 行数 → 0）

（再问一次同一身份）
01:00:34 level=INFO msg="the CA reports the certificate already revoked; the request is cleared"

（现网证书仍然可吊 —— 证明上一步没有误吊它）
01:00:42 level=ERROR msg="CERTIFICATE REVOKED" cert=two-san-wildcard reason=superseded outstandingFor=0s
```

归档材料的身份是从 PEM 独立算出来的（openssl 取 AKI + DER serial，再 base64url），与状态库在它"在世"时记下的 `ari_cert_id` **完全一致**——`certIdentity()` 与真实 ARI certID 同源这一点得到了实测。

### 4.6 onboard 守卫 1：真实 CLB 规则抖动，覆盖不丢

真实声明两条（`_wecert.test.alpha` 由 terraform 规则服务、`_wecert.carry-test` 由我用 API 临时加的规则服务）：

```
第 1 轮（两条规则都在）： mode=written revision=sha256:390371e08e674fae carriedForward=0
第 2 轮（删掉 carry-test 的规则，声明留着）：
  mode=unchanged  revision=sha256:390371e08e674fae  previousRevision=sha256:390371e08e674fae  carriedForward=1
  carry-test.atomwangnus.com -> included  reason="no CLB rule serves this name (guard 1 not satisfied);
      the declaration is still there, so the name keeps its coverage (removing coverage means removing the declaration)"
第 3 轮（规则加回来）： mode=unchanged revision=sha256:390371e08e674fae carriedForward=0
```

文档（`desired-state.yaml`）三轮都覆盖这两个名字，revision 三轮不变 = **零次签发、零次失去覆盖**。改动前第 2 轮会改 revision（摘掉名字 → 触发一次不带该名字的签发），第 3 轮再改一次。

### 4.7 Stage C：真机 systemd + `cvm-role`

```
/etc/wecert/    drwxr-x--- root:wecert    config.yaml -rw-r----- root:wecert
/var/lib/wecert drwx------ wecert:wecert  state.db -rw------- + state.db.backup-…Z.db -rw-------
wecert.service  active   User=wecert  Group=wecert  StateDirectory=wecert
journalctl: msg="Tencent Cloud deploy enabled" credentialMode=cvm-role resourceTypes=[clb] regions=[ap-guangzhou]
            msg="TXT propagated" zone=atomwangnus.com. nameservers=10 records=1 (confirmed 3/3)
            msg="certificate uploaded; waiting for a one-time manual bind …" uploadedCertId=asaUflOn
grep -nE "SecretId|SecretKey|loginToken|password" /etc/wecert/config.yaml → (none)
metadata.tencentyun.com/…/cam/security-credentials/ → wecert-test-role
metrics: wecert_ratelimit_remaining_tokens{limit="certs-per-exact-identifier-set",scope="cvm-role.atomwangnus.com"} 4.000068258132091
         wecert_ratelimit_remaining_tokens{limit="certs-per-registered-domain",scope="atomwangnus.com"} 49.0006893359712
         wecert_ratelimit_remaining_tokens{limit="new-orders",scope=""} 300
```

`certs-per-exact-identifier-set` 从 5 变成 4、`certs-per-registered-domain` 从 50 变成 49，说明本轮"真正记账"的改动在真机上生效；`new-orders` 保持 300（本轮这一张证书没有新订单，因为它是首签）。

---

## 5. 本轮暴露的问题

### 5.1 `scripts/e2e-wildcard.sh` 的清理断言没等传播（脚手架，已修）

第 1 次真实执行判 **FAIL**：

```
  ❌ TXT values were left behind at _acme-challenge.atomwangnus.com:
       Og2XqG0OWCI7XdVjkpXbDjd0G0WBbKa8DiKXbvV1dqg
       sKrB_kTXdZPcVtDXJq_-mS_cPbhDZgm6n6EMutF8kxw
```

但两分钟后同一批权威地址全部返回空，DNSPod API 也是 `No records on the list` —— 记录**确实被删了**，只是删除的传播还没到所有权威（DNSPod TTL 下限 600s，删除同样要传播）。断言在进程退出瞬间就跑，等于把"最终一致"读成"泄漏"。

修法（`b7a1544`）：加一个有界等待窗口（`SETTLE_SECONDS`，默认 120s，轮询 5s），窗口内变空即通过并报出耗时；`SETTLE_SECONDS=0` 保留旧行为给罐装自测用。自测 5/5 通过，第 2 次真实执行：

```
  ✅ no TXT values remain at _acme-challenge.atomwangnus.com (the deletion took 60s to reach every authority)
```

**这是脚手架缺陷，不是产品缺陷**：产品的清理路径工作正常（§4.2 两个值都清掉了）。

### 5.2 `wecert-tatrun` 失败任务的输出没解码（产品，已修）

用 TAT 在 CVM 上跑命令时，一条最后一句非零退出的命令，工具把它的输出按 **Base64 原文**打了出来：

```
LXJ3eHIteHIteCAxIHJvb3QgICByb290ICAgMTYzNDcyOTggU2VwIDE4IDAxOjAzIC91c3IvbG9jYWwvYmluL3dlY2VydAo…
error: TAT task FAILED
```

成功分支早就修过（同一份报告链路上），失败分支漏了 —— 而失败恰恰是"输出就是全部意义"的场合。修法（`3bba02b`）：失败分支同样走 `decodeRemoteOutput`；`TestAFailedTaskPrintsItsOutputDecoded` 走 `os.Pipe` 抓 stdout，把解码去掉即变红（打印出的就是 Base64）。修好后同一类命令的输出直接可读。

### 5.3 行为观察（**待你决定**）：从未被绑定的证书，续期会被云端拒绝换绑

场景：`deploy.enabled: true`，首签上传了 `asYt2vjw`（此时没有任何绑定，工具也如实提示"bind it once in the CLB console"），随后证书续期：

```
level=ERROR msg="pass failed; a retry has been scheduled" err="deploy to Tencent Cloud:
  UpdateCertificateInstance: [TencentCloudSDKError] Code=FailedOperation.CertificateDeployInstanceEmpty,
  Message=系统未检测到可用实例，无法更新证书，请您核对证书域名与云资源实例是否匹配。"
consecutiveFailures=1 nextAttemptAt=…
```

这一次**没有**造成损坏，机制上都对：

- 已上传的新证书 id 落在 `orders.deployment_cert_id`（resume anchor），下一次用 `ResumeDeploy` 继续，**不会重复上传**（实测：失败前后账号证书数都是 39）；
- 状态里 `deployed_cert_id` 保持旧值、`deploy_confirmed=0`，"未部署"的语义没有被写坏；
- 重试有 backoff（1 分钟起、上限 6 小时），不会打爆云端 API；
- **（本节写于 770d018 之前，那之后的正确动作见下面的更正）**

> **更正（770d018 及之后的版本）**：**不要**去绑旧证书。这一情形已经被实现成"按首签处理"
> （`deploy.ErrNothingBoundYet`）：新证书被提升为当前证书，被替换的那张上传（没有任何绑定）
> 进回收清单，提示语点名新证书的 `certId`。照旧文去绑**旧**证书会让程序跟踪的那一行仍然处于
> 未绑定状态 —— 下一轮再次判定"无人绑定"、再上传第三张、每个续期周期烧掉一次签发额度。
> 所以正确的动作是绑**新**证书（日志里的 `certId`，也是状态里的 `deployed_cert_id`）。
> 语义问题也已拍板：不再算失败（见 `docs/code-review-round4-2026-09-18.md` §2.1 第 4 条与
> §6.1 第 4 条）。

当时的两种读法（作为历史记录保留）：

| 读法 | 代价 |
|---|---|
| 保持现状（失败）：配置要求部署，而部署确实没发生 —— 失败是诚实的；`consecutive_failures` 与日志都在喊"有人没做那一步" | 一个"还没人用"的证书会长期报失败；如果这个账号/证书本来就不打算绑（例如先上传、以后再绑），日志噪声会持续 |
| 改成"仍等首次绑定"（最终采用）：当 `deploy_confirmed=false` 且旧证书**可证明无绑定**时，不走 `UpdateCertificateInstance`，而是像首签那样上传新证书、记录新 id、重新打印"bind it once"提示 | 需要一次"旧证书有没有绑定"的枚举（已有 `bindingsWith`，但要接受"枚举不完整"这种答案）；并且"上传成功"与"部署成功"必须在状态里继续分得清楚（`deploy_confirmed` 已经是这个开关） |

### 5.4 DNSPod 传播时延（数据点，不是缺陷）

本轮 5 次真实签发的传播等待（从 TXT 提交到判据给出结论）：86s（L1，00:27:05→00:28:31）、3m13s（wildcard，00:36:39→00:39:52）、1m59s（tlsserver，00:41:58→00:43:57）、3m22s（Stage B 首次，00:47:56→00:51:18）、2m18s（CVM，01:05:07→01:07:25）。删除的传播到所有权威最长观察到 60s。这解释了 09-17 报告 5.1 的"判据说好了、CA 说 NXDOMAIN"为什么会发生，也说明**等待预算不能按最好情况设定**。

---

## 6. 未跑 / 不能证明的东西

| 项 | 状态 | 说明 |
|---|---|---|
| 真实时间流逝下的自然续期（等 30/45 天） | **未跑** | 所有续期窗口都是推到当下触发的 |
| 生产（非 staging）LE 的配额与签发行为 | **未跑** | 全程 staging |
| 「归档副本也没了」的报错分支（保留期已回收） | **未跑（仅单元测试）** | 真实账号上归档材料还在，没构造回收后的场景 |
| 「枚举超时/未覆盖全部 region」的部署哨兵分支 | **未跑（仅单元测试）** | 本轮换绑走的是"adopted task + 恢复判定"（§4.4 的两条 WARN） |
| Stage C 的"首绑 → 自动换绑"（09-17 报告 4.9） | **未重跑** | 换绑路径本身在 Stage B 上复核过；CVM 侧只跑到"首签上传 + 提示手工绑定" |
| SNI 关闭时 Stage B 老路径 | **未验证** | 本账号无法关闭 SNI |
| 5.3 的两种读法哪个更好 | **未决定** | 见 §5.3 |

---

## 7. 复现步骤

```bash
# 0. 构建（本机）
export GOCACHE=… GOPATH=… PATH="$GOPATH/bin:$PATH"
make build && make tools
go build -trimpath -ldflags "-s -w" -o bin/wecert-clbverify ./cmd/clbverify
go build -trimpath -ldflags "-s -w" -o bin/wecert-tatrun    ./cmd/tatrun
eval "$(grep -E '^export TENCENTCLOUD_SECRET_(ID|KEY)=' ~/wbenv)"

# 1. 单域名真实签发
bash scripts/e2e-test.sh atomwangnus.com /tmp/wecert-e2e/l1-config.yaml

# 2. apex + *.apex 共用一个 TXT 名
bash scripts/e2e-wildcard.sh atomwangnus.com /tmp/wecert-e2e/wildcard-config.yaml

# 3. tlsserver 45 天 + 推窗续期
./bin/wecert -config /tmp/wecert-e2e/tls-config.yaml -state /tmp/wecert-e2e/state-tls.db -once
python3 /tmp/wecert-e2e/force_renewal.py     # 指向该 state 的等价 SQL
./bin/wecert -config /tmp/wecert-e2e/tls-config.yaml -state /tmp/wecert-e2e/state-tls.db -once

# 4. Stage B/C 环境（内网 CLB + 规则 + 占位证书 + CVM + CAM 角色）
python3 /tmp/wecert-e2e/tc.py cam-create-role
cd testenv && terraform init && \
  terraform apply -var create_cvm=true -var enable_cvm_role=true \
    -var 'clb_rule_domains=["test.alpha.atomwangnus.com","test.beta.atomwangnus.com"]'

# 5. 一键换绑（把占位证书种成 deployed_cert_id，推到期的窗口，再跑一轮）
./bin/wecert -config /tmp/wecert-e2e/fix-config.yaml -state /tmp/wecert-e2e/state-fix.db -once

# 6. 吊销（归档副本 / 现网证书）
sqlite3 /tmp/wecert-e2e/state-fix.db "INSERT INTO revoke_requests … cert_identity='<旧证书身份>' …"
./bin/wecert -config /tmp/wecert-e2e/fix-config.yaml -state /tmp/wecert-e2e/state-fix.db -once
./bin/wecert -config /tmp/wecert-e2e/fix-config.yaml -state /tmp/wecert-e2e/state-fix.db \
  -revoke two-san-wildcard -revoke-reason superseded -yes

# 7. onboard 守卫 1（真实 CLB 规则 + 真实 _wecert 声明）
./bin/wecert-onboard -config /tmp/wecert-e2e/onboard/config.yaml -json

# 8. Stage C：推二进制 → install.sh → systemd
python3 /tmp/wecert-e2e/chunk-push.py <cvm-public-ip> /tmp/wecert-e2e/wecert_linux_amd64
./bin/wecert-tatrun -region ap-guangzhou -instance <cvm-id> -cmd './install.sh /root/wecert-install/wecert_linux_amd64'
./bin/wecert-tatrun -region ap-guangzhou -instance <cvm-id> -cmd 'systemctl enable --now wecert'
```

---

## 8. 收尾（按 ID 删除，可核对）

| 对象 | 处理 | 复核 |
|---|---|---|
| CVM / VPC / 子网 / 安全组 / CLB / 监听器 / 两条规则 / 占位证书 | `terraform destroy -auto-approve`（17 个资源） | `terraform state list` 为空；`tc.py clb-list` total=0；`vpc-list` 中 `vpc-g428phc9` 为 0 |
| 本轮上传的证书：`asXpdG7X`（L1）`asYt2vjw` `asYxaBT0`（tlsserver）`asZO95i0` `asZSMfYB`（Stage B）`asaUflOn`（CVM） | 逐个 `DeleteCertificate`（**从未**使用 `-prune-certs`，避免动到账号里他人的证书） | 6 个 ID 在 `cert-list` 中均已消失 |
| CAM 角色 `wecert-test-role` + 策略 `wecert-test-runtime` | Detach + DeleteRole + DeletePolicy（策略需用 `PolicyId` 数组形式删除） | `ListPolicies` 中已无 `wecert-test*` |
| `_acme-challenge*` / `_wecert.*` 记录 | 产品自己清掉（onboard 测试的两条声明由我手工删） | 五个前缀查询全部 `NoDataOfRecord` |

**没有使用 `wecert-preflight -prune-certs`**；共享账号里他人的资源未被触碰。
