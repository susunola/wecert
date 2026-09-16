# 证书全生命周期验收用例（TC-LIFECYCLE-01）

> **实跑记录**：2026-09-16 在真实 DNSPod + Let's Encrypt staging 上完整跑过一轮，
> 结论与逐阶段证据见 [实跑报告](lifecycle-acceptance-run-2026-09-16.html)。
> 那次跑出了一个会让证书永久无法更换域名的缺陷（已修），并暴露了本用例自身的 6 处错误（已修正）。

这份文档是一份**可执行的验收清单**：在真实 DNSPod + Let's Encrypt **staging** 上，把一张证书
从"声明"一路走到"退役"，每个阶段都给出**可观测的判据**。

它测的不是"能不能签发"。签发能不能成功，`scripts/e2e-test.sh` 已经回答了。它测的是：

> **每一步之后，系统留下的状态是否和设计一致** —— 订单有没有多下、TXT 有没有残留、
> SAN 有没有跟着配置收敛、续期有没有走 ARI、中断之后能不能自己恢复、下线之后是不是真的停了。

这类问题在"能签发"的绿灯下完全不可见，但它们的代价是配额、是漏在外面的 DNS 记录、
是某天突然无法续期。

---

## 0. 覆盖范围与边界

| | 内容 |
|---|---|
| **覆盖** | DNS-01 挑战全过程、订单状态机、SAN 增删收敛、wildcard+apex 共享 TXT 名、多证书并发同名、续期的两条路径（ARI / 时间回退）、中断自愈（续跑同一订单 / 回收未持久化的记录）、`_wecert` 声明 → 期望状态 → enforce 收敛、域名下线与宽限期、空期望状态熔断、证书级孤儿 |
| **不覆盖** | CLB 绑定/重绑、SNI 切换、真实 TLS 握手（那是 `testenv/README.md` 的 Stage B / B2 / B3）、生产 Let's Encrypt、云证书配额（本用例全程 `deploy.enabled: false`，不上传任何云证书） |

用例分两部分，**各自独立、各有自己的 state 库**：

- **Part A（A0–A9）**：`wecert` 侧，`desiredState.mode: static`，域名直接写在配置里。
  这是每天真正跑的那条路径。
- **Part B（B0–B5）**：声明层，`_wecert` TXT 记录 → `wecert-onboard` → 期望状态文档 →
  `wecert` 以 `enforce` 模式收敛。回答"域名从哪来、怎么下线"。

两部分的证书名不同，是设计使然，不是笔误：

| | 证书名从哪来 | 例子 |
|---|---|---|
| Part A | 配置文件里手写 | `lifecycle` |
| Part B | 注册域派生（`group.CertName`） | `example-com` |

**为什么 Part A 用 `deploy.enabled: false`**：staging 签出来的证书没有部署价值，
而且每次签发都上传一张云证书会消耗账号配额。部署路径由 `testenv/` 的 Stage B 单独覆盖，
那里有真正的 CLB 可以断言绑定结果。本用例断言的是"云部署关闭"这条分支的行为。

---

## 1. 前置条件

### P1 域名与 DNS

一个你能改的测试域（记为 `$APEX`，例如 `example.com`），NS 已指向 DNSPod。
下面这些子域**不需要**任何 A 记录（DNS-01 只用到 TXT）：

- Part A：`$APEX`、`sub.$APEX`、`*.$APEX`、`other.$APEX`
- Part B：`alpha.$APEX`、`beta.$APEX`、`gamma.$APEX`

Part B 的 B5b（证书级孤儿）还需要**第二个注册域** `$APEX2`；没有的话跳过那一步即可，
文档里已标注。

### P2 凭据

从环境读，**不要写进配置文件**：

```bash
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
```

`dns.provider: tencentcloud` 与 `tencent.credentialMode: static` 共用这一组 CAM 凭据
（`wecert-onboard` 也用它来枚举 `_wecert` 记录）。换成 DNSPod 原生 token 也可以，
那要改 `dns.provider: dnspod` + `dns.loginToken`，本用例其余部分不受影响。

### P3 安全闸：必须指向 staging

每次运行前先过这道闸。和 `scripts/e2e-test.sh` 用的是同一条锚定规则 ——
锚定 `directory:` 这个**键**，注释里出现 "acme-staging" 不算数：

```bash
A_CFG=/tmp/wecert-lifecycle/a.yaml

grep -qE '^[[:space:]]*directory:.*acme-staging' "$A_CFG" \
  || { echo "拒绝运行：acme.directory 不是 staging" >&2; exit 1; }
```

理由：一次失败的续期会烧掉**每个 identifier 每小时 5 次**的授权失败配额，
而 staging 的失败不花钱。

另外在 A0 的启动日志里确认一次 `production=false`（`wecert` 每次启动都会打印这个字段），
这是对上面那道闸的第二重校验。

### P4 工具

```bash
for t in dig sqlite3 curl openssl; do command -v "$t" >/dev/null || echo "缺少 $t"; done
```

### P5 全新状态，干净基线

```bash
ST=/tmp/wecert-lifecycle
rm -rf "$ST" && mkdir -p "$ST"

# 基线：这些名字下面不应该有任何 TXT
for n in "$APEX" "sub.$APEX" "other.$APEX" "alpha.$APEX" "beta.$APEX" "gamma.$APEX"; do
  printf '%-30s %s\n' "_acme-challenge.$n" "$(dig +short TXT "_acme-challenge.$n" | tr '\n' ' ')"
done
```

**判据**：全部为空。若不为空，先在 DNSPod 控制台删干净再开始 ——
否则后面"TXT 已清理"的断言全部不可信。

### P6 构建

```bash
make build   # 产出 ./bin/wecert 与 ./bin/wecert-onboard
```

### P7 配置文件

Part A 用这一份（`$A_CFG`）。把 `REPLACE_ME` 换成 `$APEX`，`email` 换成你能收信的地址
（LE 拒绝 `example.com` 这类保留域）：

```yaml
statePath: /tmp/wecert-lifecycle/a.db

acme:
  # 安全闸锚定的就是这一行
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: REPLACE_ME

dns:
  provider: tencentcloud
  ttl: 600
  propagationTimeout: 5m
  pollingInterval: 5s

tencent:
  credentialMode: static
  resourceTypes:
    - clb
  regions:
    - ap-guangzhou

metrics:
  listen: 127.0.0.1:9800

webhook:
  listen: 127.0.0.1:9801
  token: "0123456789abcdef0123456789abcdef"

certificates:
  - name: lifecycle
    profile: classic
    keyType: ecdsa-p256
    domains:
      - REPLACE_ME
    deploy:
      # 本用例不上传云证书；部署路径由 testenv/ Stage B 覆盖
      enabled: false
```

```bash
./bin/wecert -config "$A_CFG" -state "$ST/a.db" -dry-run
```

**判据**：退出码 0。**失败说明**：配置字段错误（会打印具体字段），或 staging 不可达 / 凭据无效。

> ⚠️ 端口与锁：`-once` 和守护模式**都会**绑定 `metrics.listen` 与 `webhook.listen`，
> 所以同一时刻只能有一个 `wecert` 在跑；state 库还有跨进程独占锁
> （`<statePath>.lock`）。换阶段时先确认上一个进程已经退出。

---

## 2. 阶段总览

| # | 阶段 | 一句话 | 主要判据 |
|---|---|---|---|
| A0 | 首签 | 冷启动签发第一张 | `not_after`≈+90d、`ari_cert_id` 非空、`orders`=0、TXT 清空 |
| A1 | 幂等 | 再跑一轮不该开单 | 无 `ACME order created`、`orders`=0、`not_after` 不变 |
| A2 | SAN 扩张 | 配置加域名立刻重签 | 漂移告警、新 SAN 含新域、`not_after` 前移 |
| A3 | SAN 收缩 | 配置删域名立刻重签 | 新 SAN 集合与配置**完全相等** |
| A4 | wildcard+apex | 两条 TXT 同时活在同一名字下 | 中断法直接观测到 2 条 TXT + 2 行同 `txt_name` 的授权 |
| A4b | 整组换域名 | 与旧证书零重叠也必须能签发 | 签发成功、**不带** `replaces` |
| A5 | 中断续跑 | 半途失败后复用同一订单 | 恢复时 `order_url` 不变、无新订单 |
| A6 | 并发双证书 | 同名 TXT 不互删 | 两张证书都签发成功（这正是被修复的缺陷类） |
| A7 | 续期·ARI | 走 ARI 窗口 + `replaces` | `starting renewal`、`replaces=true`、window 归零 |
| A8 | 续期·回退 | ARI 不可用时按时间阈值 | `replaces=false`、仍成功 |
| A9 | 孤儿回收 | 未持久化的记录被找回 | `reclaiming it before deleting the row`、TXT 与行都被清掉 |
| B0 | 声明→契约 | `_wecert` 记录生成文档 | 证书名=`example-com`、SAN=声明集合、revision 稳定 |
| B1 | observe | 影子对比不改变行为 | 仍按配置收敛、`shadow_diff` 正确 |
| B2 | enforce | 文档说了算 | 按文档签发、`certificates: []` 被接受 |
| B3 | 新增声明 | 加一条 `_wecert` 记录 | 文档出现新 SAN、**证书名不变** |
| B4 | 域名下线 | 移除声明 → 宽限期 → 移除 | 第一次 carry、超期后从文档消失 |
| B5a | 空期望状态 | 声明全删光 | **冻结**（退出码 2），文档不被清空 |
| B5b | 证书级孤儿 | 只删第二个注册域（可选） | 文档里那张证书消失、wecert 报孤儿 |

每个阶段的格式统一为：**目的 / 操作 / 期望 / 判据 / 失败说明**。
`判据` 全部成立才算 PASS。

---

## 3. Part A — wecert 侧生命周期

```bash
A_CFG=/tmp/wecert-lifecycle/a.yaml
DB=/tmp/wecert-lifecycle/a.db
```

小工具（后面反复用）：

```bash
q() { sqlite3 "$DB" "$1"; }

# 叶证书的 SAN（cert_pem 存的是 fullchain，openssl 读第一张就是叶证书）
sans() {
  q "SELECT writefile('/tmp/wecert-leaf.pem', cert_pem) FROM certificates WHERE name='$1';" >/dev/null
  openssl x509 -in /tmp/wecert-leaf.pem -noout -ext subjectAltName | tail -n +2
}

# 这个挑战名下现在有哪些 TXT（直接问权威 NS，绕开递归缓存）
txt() {
  local ns; ns="$(dig +short NS "$APEX" | head -n1)"
  dig +short TXT "$1" @"$ns"
}

# 清掉退避，让下一轮立刻可以动手（见 A4 的说明）
clear_backoff() {
  q "UPDATE certificates SET next_attempt_at=0, consecutive_failures=0 WHERE name='$1';"
}
```

---

### A0 — 首签（冷启动）

**目的**：从零开始的路径：没有证书、没有订单、DNS 里没有任何挑战记录。

**操作**

```bash
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a0.log
```

**期望**

- 启动行 `wecert starting` 里 `production=false`
- 之后按顺序出现：`first issuance` → `TXT presented` → `TXT propagated` →
  `ACME order created` → `certificate issued and recorded locally (cloud deploy is off)`
- `ACME order created` 一行里 `replaces=false`（首次签发没有旧证书可以替换）

```bash
q "SELECT name, datetime(not_after,'unixepoch') AS not_after, length(cert_pem) AS pem_len,
          ari_cert_id, deployed_cert_id, deploy_confirmed, consecutive_failures, last_error
   FROM certificates;"
q "SELECT count(*) FROM orders;"
q "SELECT count(*) FROM authorizations;"
```

**判据**

| 检查 | 期望 |
|---|---|
| `certificates` 行数 | 1 |
| `not_after` | 约等于现在 + 90 天（classic 档；±1 天以内） |
| `pem_len` | 明显大于 0（fullchain 至少含叶证书） |
| `ari_cert_id` | **非空**，形如 `<AKI>.<serial>` 两段 base64url |
| `deployed_cert_id` / `deploy_confirmed` | 空 / 0（`deploy.enabled: false`） |
| `consecutive_failures` / `last_error` | 0 / 空 |
| `orders` 行数 | **0**（成功的签发会把订单丢掉） |
| `authorizations` 行数 | **0**（TXT 已清理、行也删了） |
| `txt _acme-challenge.$APEX` | 空 |

**失败说明**

- `ari_cert_id` 为空 → 叶证书没有 AKI，或 `CertID` 解析失败。后果是**后续所有续期都拿不到
  限流豁免**，这是本系统最重要的一条豁免（`internal/acme/ari.go`）。
- `authorizations` 不为 0 → 清理路径没跑完，看有没有 `failed to clean up TXT` 告警。
- `orders` 不为 0 而签发其实成功了 → 订单没有被丢弃，下轮会去"续跑"一个已作废的订单。

---

### A1 — 幂等：不在窗口内开单

**目的**：这是**配额安全的核心不变量**。刚签发的证书不该再下一单 —— 一旦这里漏了，
每轮巡检都会撞上"每 7 天、每个精确 identifier 集合 5 张"这条**没有 override** 的限制。

**操作**

```bash
BEFORE="$(q "SELECT not_after FROM certificates WHERE name='lifecycle';")"
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug > /tmp/a1.log 2>&1
q "SELECT count(*) FROM orders;"
q "SELECT not_after FROM certificates WHERE name='lifecycle';"
grep -c 'ACME order created' /tmp/a1.log || true
grep 'not yet due for renewal' /tmp/a1.log || true
```

**判据**

| 检查 | 期望 |
|---|---|
| `ACME order created` 出现次数 | **0** |
| `orders` 行数 | 0 |
| `not_after` | 与 `BEFORE` 完全相同 |
| 日志 | 出现 `not yet due for renewal`（debug 级） |

**失败说明**：`not_after` 变了说明重签发生了 —— 检查 `renewBefore` 与 ARI 窗口。
`Reconcile` 里的判断顺序是有意设计的，顺序被动过就会出现这里之外的行为。

---

### A2 — SAN 扩张：配置加域名立刻重签

**目的**：证明"域名变更不等到续期窗口"这条设计成立。
如果这里不动，新加的域名要等最多一个完整有效期（classic 档 90 天）才生效。

**操作**

```bash
# 在 a.yaml 的 domains 里加上 sub.$APEX，然后：
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a2.log

sans lifecycle
q "SELECT datetime(not_after,'unixepoch') FROM certificates WHERE name='lifecycle';"
q "SELECT count(*) FROM orders;"
txt "_acme-challenge.sub.$APEX"
```

**期望**

- 日志出现 `the live certificate's SANs no longer match the config; reissuing now`，
  `detail` 为 `required by the config but missing: sub.$APEX`
- 新叶证书的 SAN **同时**包含 `$APEX` 和 `sub.$APEX`
- `not_after` 比 A0 的晚；`orders`=0；`_acme-challenge.sub.$APEX` 为空

**判据**：以上全部成立。额外记录（**不作为判据**）：`ACME order created` 可能出现
`replaces=true` —— 代码把 ARI certID 一并带上；若 CA 不接受 `replaces`，
lego 会自动去掉并重试一次，最终签发成功仍算通过。

**失败说明**：没有漂移告警却重签了，说明判断落在续期窗口上（那不是这条设计）；
有告警但 SAN 没变，说明 CSR 用的还是旧的域名集合。

---

### A3 — SAN 收缩：配置删域名

**目的**：反方向。删掉一个域名后，证书里**必须**不再有它 ——
多留一个名字就是多一份攻击面，而"悄悄多留"最容易发生在只做增量合并的实现里。

**操作**

```bash
# 从 domains 里删掉 sub.$APEX，然后：
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a3.log
sans lifecycle
```

**期望**：`detail` 为 `certificate present but removed from the config: sub.$APEX`；
新 SAN 只剩 `$APEX`。

**判据**：SAN 集合与配置**完全相等**（不是"包含"）。比较时用规范化形式
（小写、排序、去重 —— 即 `config.DomainKey` 的语义）。

---

### A4 — wildcard + apex：两条 TXT 同时活在一个名字下

**目的**：DNS-01 最容易写错的一处。`$APEX` 和 `*.$APEX` 的挑战值都写在
**同一个** `_acme-challenge.$APEX` 上，必须**同时存在**。
任何"写一条 → 验证一条 → 删一条"的实现，在这里必然失败。

**方法**：在**传播确认之后、验证完成之前**把进程杀掉。

为什么不用"把递归解析器指向黑洞地址"这种看似更干净的做法：`dns.recursiveNameservers`
会被灌进 lego 的全局解析器（`internal/acme/dns.go` 里的 `dns01.AddRecursiveNameservers`），
而 lego 的 provider 在写记录**之前**要用它查一次 zone。黑洞地址会让 provider 直接失败
（`failed to get hosted zone: could not find zone`），TXT 根本没写下去 ——
想要的"记录在 DNS 里、进程已经死掉"那一刻永远不会出现。实测踩过这个坑。

**窗口有多大**（实测一次完整签发）：

```
TXT presented    t+0.0s
TXT propagated   t+11.2s    <- 就绪检查通过
证书落地          t+23.5s    <- 这一轮结束
```

从 `TXT presented` 到这一轮结束有 **23.5 秒**，其中 12.2 秒是 LE 自己的验证时间
（数字取自实测日志的逐行时间戳，不是估算）。
所以做法是：后台启动、盯着日志等 `TXT presented`，立刻 `kill -9`。
**杀完必须验证前置态**（授权行 `presented=1` 且 TXT 真在 DNS 里）：
若那一轮在信号到达前就跑完了，前置态不成立，删掉残留记录重来一次即可（步骤幂等）。

> ⚠️ **必须用一对从未验证过的标识。**
> Let's Encrypt 会**复用仍然有效的授权**（同账号 + 同 identifier，约 30 天），
> 所以如果拿 `$APEX` + `*.$APEX` 来跑，而 apex 在 A0 里已经验证过，
> 这次只会有一个挑战需要写 —— 本阶段"一个名字下两条 TXT"的前提就不成立了。
> 用一对全新的子域：`wild.$APEX` 和 `*.wild.$APEX`
> （通配的 `*.` 会被剥掉，两者的挑战名都是 `_acme-challenge.wild.$APEX`）。
>
> 同理，`TXT propagated` 里的 `records=N` 是**本轮实际写的挑战数**，不是 SAN 个数 ——
> 域名多的订单经常只写一两条，那不是缺陷。

**操作（制造中断）**

```bash
# 1) 配置改成一对全新的子域 + 它的通配（见上面的告警）
#    domains:
#      - wild.$APEX
#      - "*.wild.$APEX"

# 2) 后台跑一轮，看到第二条 TXT presented 就 kill -9
rm -f /tmp/a4-interrupt.log
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug > /tmp/a4-interrupt.log 2>&1 &
PID=$!
for i in $(seq 1 1200); do
  n=$(grep -c 'TXT presented' /tmp/a4-interrupt.log 2>/dev/null || true)
  [ "${n:-0}" -ge 2 ] && break
  kill -0 $PID 2>/dev/null || break     # 进程自己跑完了 → 前置态不成立，重来
  sleep 0.1
done
kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null

# 3) 先确认前置态成立，再往下断言（不成立就删掉残留记录重跑第 2 步）
grep -c 'TXT propagated' /tmp/a4-interrupt.log            # 期望 0：验证还没走完
```

**期望（中断态）**

```bash
q "SELECT identifier, txt_name, substr(txt_value,1,12)||'…' AS v, presented, challenge_sent
   FROM authorizations ORDER BY identifier;"
txt "_acme-challenge.$APEX"
q "SELECT consecutive_failures, datetime(next_attempt_at,'unixepoch') FROM certificates WHERE name='lifecycle';"
```

| 检查 | 期望 |
|---|---|
| `authorizations` 行数 | **2** |
| 两行的 `txt_name` | **相同**，都是 `_acme-challenge.$APEX.` |
| 两行的 `txt_value` | **不同**（两个 key authorization 的哈希） |
| 两行的 `presented` | 都是 1 |
| 两行的 `challenge_sent` | 都是 0（还没走到通知 CA 那一步） |
| `txt` 查询 | 返回**两条** TXT 值 |
| `orders` | 1 行，仍在（订单没做完） |
| `certificates.not_after` | 未变（还停在 A3 的结果） |
| `consecutive_failures` | **0**（`kill -9` 什么都没来得及记） |
| `next_attempt_at` | 0（同上：没有退避，恢复轮不需要清） |
| 日志 | `TXT presented` ×2，且**没有** `TXT propagated` |
| 退出码 | 被杀时是 137。**顺带记住**：`-once` 即使这一轮失败也是 **0**（`RunAll` 刻意丢弃单张证书的错误），所以永远不要用退出码判断单张证书的成败 |

**这一条是整个 A4 的核心**：直接看到"一个名字下两条 TXT 并存"，
而不是靠"签发成功"去反推。

**操作（恢复）**

```bash
# kill 不留下退避；只有上一轮是"自己失败"的（例如手工试过黑洞变体）才需要 clear_backoff

./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a4-resume.log
sans lifecycle
q "SELECT count(*) FROM authorizations;"
txt "_acme-challenge.$APEX"
```

**期望（恢复态）**：签发成功；SAN 同时含 `$APEX` 与 `*.$APEX`；
`authorizations`=0；`_acme-challenge.$APEX` 为空。

**失败说明**

- 如果恢复那一轮重新写了 TXT 而没有 adopt，会在同一个名字下留下重复值 ——
  看日志里有没有 `the TXT from the interrupted pass is already up; adopting it instead of
  writing a duplicate`。
- 如果恢复后 TXT 还在，是清理路径的问题（`cleanup` / `removeAuthzTXT`）。

---

### A4b — 整组域名更换：与旧证书零重叠

**目的**：**本次实跑发现的缺陷的验收回归**。把一张证书换到一组完全不同的域名
（迁移服务、把名字在证书之间挪动），新订单的标识集合与旧证书**零重叠**。

旧实现在漂移分支无条件把 `st.ARICertID` 当 `replaces` 发出去，而 Let's Encrypt 会拒绝：

```
malformed :: Could not validate ARI 'replaces' field ::
identifiers in this order do not match any identifiers in the certificate being replaced
```

这个错误来自 `newOrder`，**订单根本没建起来**；又因为 `ari_cert_id` 不会变，
之后每一轮都会发同样的 `replaces`、以同样的方式失败 —— 证书再也换不了域名。
（ARI 的 `replaces` 只对"同一 identifier 集合的续期"有意义，换过的集合本来也拿不到豁免，
所以这里不发才是对的。）

**操作**

```bash
# 把 domains 换成另一组全新的名字（与当前证书 {wild.$APEX, *.wild.$APEX} 零重叠）
#    domains:
#      - moving.$APEX

./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a4b.log
```

**判据**

| 检查 | 期望 |
|---|---|
| 结果 | **签发成功**（这是本阶段唯一真正重要的一条） |
| 日志 | `ACME order created` 存在，且其中 **没有** `replaces=true` |
| 日志 | **没有** `Could not validate ARI 'replaces' field` |
| 日志 | 没有 `the CA refused the ARI replaces field; retrying the order without it`（走的是"一开始就不发"，不是"发了被拒再重试") |
| 新 SAN | `{moving.$APEX}` |
| `consecutive_failures` | 回到 0（这个缺陷的症状就是它一直卡在 ≥1） |

**失败说明**：如果在 `newOrder` 上看到 400 `malformed ... replaces`，
说明漂移分支又把旧证书的 ARI certID 带上了 —— 后果不是"这一轮失败"，
而是这张证书**永久无法换域名**，再也不会恢复。

---

### A5 — 中断续跑：复用同一订单，不重下

**目的**：进程半途失败后重启，**绝不能**下第二张订单。
identifier 集合一模一样的新订单会直接撞上 5/7 天限制，而且没有申诉渠道。

**操作**：紧接 A4 的中断态（在恢复之前）观察即可：

```bash
# 中断态（A4 中断之后、恢复之前）：
q "SELECT order_url, status, identifiers FROM orders;"

# 恢复之后：
q "SELECT count(*) FROM orders;"      # 期望 0（成功后被丢弃）
grep 'resuming the existing order' /tmp/a4-resume.log
```

**判据**

| 检查 | 期望 |
|---|---|
| 中断态 `orders` | 1 行，`identifiers` 与配置的域名集合一致 |
| 恢复日志 | 出现 `resuming the existing order`，其 `order` 与中断态的 `order_url` **相同** |
| 恢复日志 | **没有**新的 `ACME order created` 行（即没有下第二单） |

**失败说明**：如果恢复时出现 `the configured domains changed; discarding the old order`，
说明配置的规范化形式（`config.DomainKey`）与订单里存的不一致 ——
常见原因是域名大小写/顺序/通配写法被改动过。

**已知的真实竞态，别误判成缺陷**：恢复轮有可能在 LE 那边失败，报

```
validation failed for identifier ...: DNS problem: NXDOMAIN looking up TXT for
_acme-challenge.<名字> - check that a DNS record exists for this domain
```

而同一时刻我们的权威探测**明明看到记录在**。原因是 DNSPod 的 NS 最终一致：
就绪检查按设计容忍**从本机不可达**的 NS（否则永远无法就绪），而 LE 能到达它们 ——
它们可能还没同步，于是对 LE 回 NXDOMAIN。实测 10 个 NS 地址里有 4 个从本机不可达。

处理方式就是重试：这一轮记一次失败并退避 1 分钟；重试时 LE 已把那次授权判为
`invalid`，wecert 会丢弃订单（日志 `order became invalid`）并清掉 TXT，下一轮用新订单重来。
**没有 wecert 侧缺陷**，但这一步的判据要等到"最终签发成功"，不要在第一轮失败时就下结论。

---

### A6 — 并发双证书：同名 TXT 不互相删

**目的**：**回归本次修复的缺陷类**。两张证书可以共享一个挑战名
（配置去重的是证书名，不是域名）。lego 的 provider `CleanUp` 会删掉**该名字下的所有**
TXT，所以 A 的清理绝不能把 B 还活着的记录一起删掉。

`RunAll`（`-once` 和定时巡检）是**顺序**执行的，碰不到这个窗口；
要真正并发，只能用 webhook 触发（`StartCert` 给每张证书一个 goroutine）。
而守护进程启动时会立刻跑一轮 —— 所以顺序是"先让初始那轮无事可做，
再用 SQL 把两张证书同时推进续期窗口，最后触发"。

**操作**

```bash
# 1) 配置里加第二张证书，故意让两张共享 $APEX。
#    lifecycle 在 A4 之后是 [$APEX, *.$APEX]，注意 *.$APEX 的挑战也落在
#    同一个 _acme-challenge.$APEX 上 —— 于是这一个名字会被三行授权共享
#    （lifecycle 两行 + lifecycle-b 一行），正是最容易踩到的形状：
#      - name: lifecycle     domains: [$APEX, "*.$APEX"]      # 已在配置里
#      - name: lifecycle-b   domains: [$APEX, other.$APEX]    # 新增

# 2) 先把第二张签出来（此时只有它需要签发）
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a6-setup.log
sans lifecycle-b

# 3) 起守护进程，间隔设长，避免定时巡检插进来
./bin/wecert -config "$A_CFG" -state "$DB" -interval 24h -log-level debug > /tmp/a6.log 2>&1 &
WPID=$!
# 等启动那一轮跑完（此时两张都不在窗口内，应当是空转）
for i in $(seq 1 60); do grep -q 'reconcile pass finished' /tmp/a6.log && break; sleep 2; done
grep -c 'ACME order created' /tmp/a6.log     # 期望 0

# 4) 把两张同时推进续期窗口（清 ARI，按时间回退生效）
q "UPDATE certificates SET ari_cert_id='', ari_window_start=0, ari_window_end=0,
       ari_checked_at=0, ari_retry_after_ns=0,
       not_after = strftime('%s','now') + 20*86400
   WHERE name IN ('lifecycle','lifecycle-b');"

# 5) 记录触发前的 not_after，作为"真的跑完了"的判据
BEFORE_MAX="$(q "SELECT coalesce(max(not_after),0) FROM certificates WHERE name IN ('lifecycle','lifecycle-b');")"

# 6) 触发并发收敛
TOKEN=0123456789abcdef0123456789abcdef
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"certs":["lifecycle","lifecycle-b"]}' http://127.0.0.1:9801/hook/reconcile
echo

# 7) 等两张的 not_after 都推进（只看 consecutiveFailures 会在续期还没做之前就满足）
# 必须逐张判断：把两行拼成一个字符串再比 !=，第一张跑完就会跳出，
# 把第二张在半途杀掉（实测踩过这个坑）。
for i in $(seq 1 90); do
  DONE="$(q "SELECT count(*) FROM certificates
             WHERE name IN ('lifecycle','lifecycle-b') AND not_after > $BEFORE_MAX;")"
  [ "$DONE" = "2" ] && break
  sleep 5
done
# 状态接口是给人看的，顺手留一份记录（缩进 JSON，冒号后面有空格）
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9801/hook/status | tee /tmp/a6-status.json

kill "$WPID"; wait "$WPID" 2>/dev/null

q "SELECT name, datetime(not_after,'unixepoch'), consecutive_failures, last_error FROM certificates ORDER BY name;"
sans lifecycle; sans lifecycle-b
txt "_acme-challenge.$APEX"
grep 'another challenge is still live at the TXT name' /tmp/a6.log || true
```

**判据**

| 检查 | 期望 |
|---|---|
| 触发响应 | `accepted` 里**两张都在**，`skipped` 为空（证明真的并发起来了） |
| 等待条件 | 两张的 `not_after` 都相对触发前推进了 |
| `certificates` | 两行的 `not_after` 都推进了、`consecutive_failures` 都是 0、`last_error` 为空 |
| SAN | 两张各自符合配置，且都含 `$APEX` |
| `txt _acme-challenge.$APEX` | **空**（最后一张离开时 delete-all 生效） |
| 日志 | `another challenge is still live at the TXT name; leaving its cleanup to the last leaver` 至少出现一次 |

日志那条是"租约登记表起作用"的直接证据。若两者恰好完全串行（先完成的那个
已经清理干净才开始第二个），它不会出现 —— 此时只要**两张都签发成功**仍算通过。

**判据的核心**：两张证书**都**成功。若租约那条路径坏了，症状是其中一张的授权变成
`invalid`（LE 校验时找不到自己的 TXT），`consecutive_failures` 变 1，
并且烧掉一次每个 identifier 每小时的授权失败配额。

**失败说明**：只有一张成功 + 日志里出现 `the authorization for identifier ... is invalid`
→ 检查 `challengeLeases` 的租约登记（`internal/acme/dns.go`）与
`registerRecoveredLeases`（`internal/acme/manager_flow.go`）。

---

### A7 — 续期：ARI 路径

**目的**：ARI（RFC 9773）是本系统最重要的东西：**带 `replaces` 的续期豁免所有
Let's Encrypt 限流**。这条路径必须单独验证，因为它和"按时间续期"是两条不同的代码路径。

**方法**：不改时钟，直接改状态库，把 ARI 窗口拨到过去，
同时把 `ari_checked_at` 设成"刚刚检查过"，这样本轮不会重新拉取并覆盖我们的窗口。

**操作**

```bash
q "UPDATE certificates SET
     ari_checked_at     = strftime('%s','now'),
     ari_retry_after_ns = 0,
     ari_window_start   = strftime('%s','now') - 7200,
     ari_window_end     = strftime('%s','now') - 3600
   WHERE name='lifecycle';"

OLD_ARI="$(q "SELECT ari_cert_id FROM certificates WHERE name='lifecycle';")"
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a7.log
```

**期望**

- `starting renewal`，该行 `ariReplaces=true`
- `ACME order created` 一行里 `replaces=true`
- 新叶证书的 SAN 与配置一致，`not_after` 前移
- 成功后 `ari_window_start` / `ari_window_end` 被**归零**（下一轮重新拉取），
  且 `ari_cert_id` 变成**新证书**的
- `orders`=0，`authorizations`=0，挑战记录清空

**判据**

```bash
grep -E 'starting renewal|ACME order created' /tmp/a7.log
q "SELECT ari_window_start, ari_window_end, ari_checked_at, ari_cert_id FROM certificates WHERE name='lifecycle';"
```

| 检查 | 期望 |
|---|---|
| `starting renewal` 行 | 存在，且 `ariReplaces=true` |
| `ACME order created` 行 | 存在，且 `replaces=true` |
| `replaces` 是否真被 CA 接受 | 签发成功即证明（staging 会校验 `replaces` 指向的证书） |
| `ari_cert_id` | 与 `OLD_ARI` **不同**（新证书的 AKI/serial） |
| `ari_window_start` / `_end` | 0 / 0 |

**失败说明**

- `replaces=false` → 走的是回退分支：说明 `ari_window_start` 是零值，
  或窗口不满足 `end > start`。检查上面的 UPDATE 是否真的写进去了。
- CA 返回 `unauthorized` / ARI 相关错误 → staging 的 ARI 不可用，
  把这一条记为"环境限制"，改用 A8 验证回退路径，并在报告里注明。

---

### A8 — 续期：时间回退路径

**目的**：ARI 拉不到时系统必须仍然会续期，只是失去豁免。这条路径不能因为 A7 通过就被跳过。

**方法**：清掉 ARI 状态 + 把 `not_after` 拨进续期窗口。

**操作**

```bash
q "UPDATE certificates SET
     ari_cert_id = '', ari_window_start = 0, ari_window_end = 0,
     ari_checked_at = 0, ari_retry_after_ns = 0,
     not_after = strftime('%s','now') + 20*86400
   WHERE name='lifecycle';"

./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a8.log
```

**为什么是 20 天**：classic 档 `renewBefore` 默认 30 天，而回退分支还会加一个
`renewBefore/8`（= 3.75 天）的确定性抖动。要确保 `notAfter - 30d + 3.75d` 已经过去，
`not_after` 必须小于"现在 + 26.25 天"。20 天留了 6 天余量。

**判据**

| 检查 | 期望 |
|---|---|
| `starting renewal` | 存在，`ariReplaces=false` |
| `ACME order created` | 存在，`replaces=false` |
| 结果 | 签发成功，`not_after` 变成 +90 天左右 |
| 日志 | **没有** `ARI lookup failed`（`ari_cert_id` 已清空，压根不会去查） |

**失败说明**：没有续期且日志是 `not yet due for renewal` → 检查 `renewBefore` 的档位默认值
（classic 30d / tlsserver 15d / shortlived 48h）与 `renewBefore/8` 抖动。

---

### A9 — 孤儿回收：找回未持久化的记录

**目的**：覆盖最难、也最容易被漏掉的一条恢复路径 ——
`presented=0` 但带着 token 的授权行。它的指纹是"DNS 写成功了，但状态没来得及落库"。
这行里的 token 是**唯一**能重新定位那条 TXT 的线索，所以回收之前绝不能删它。

**操作**

```bash
# 1) 配置里加一张新证书（首签最容易制造中断，不需要退避之外的额外准备）
#      - name: orphan
#        domains: [orphan.$APEX]
#        deploy: { enabled: false }

# 2) 用 A4 的 kill 手法制造一次中断（后台跑，看到 orphan 的 TXT presented 就 kill -9）
rm -f /tmp/a9-interrupt.log
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug > /tmp/a9-interrupt.log 2>&1 &
PID=$!
for i in $(seq 1 1200); do
  grep -q 'TXT presented.*cert=orphan' /tmp/a9-interrupt.log 2>/dev/null && break
  kill -0 $PID 2>/dev/null || break
  sleep 0.1
done
kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null

# 3) 确认这次确实写了 TXT 但没做完
q "SELECT identifier, txt_name, presented, challenge_token != '' AS has_token
   FROM authorizations WHERE cert_name='orphan';"
txt "_acme-challenge.orphan.$APEX"

# 4) 构造"订单已经没了、授权行还在、而且没持久化"的状态
q "DELETE FROM orders WHERE cert_name='orphan';"
q "UPDATE authorizations SET presented=0 WHERE cert_name='orphan';"
# kill 不留退避；若上一轮是自己失败的，清掉它免得恢复轮被跳过
clear_backoff orphan

# 5) 恢复正常解析器，跑一轮
./bin/wecert -config "$A_CFG" -state "$DB" -once -log-level debug 2>&1 | tee /tmp/a9-recover.log
```

**期望**

- 第 5 步日志出现 `found the TXT of an interrupted pass; reclaiming it before deleting the row`
- 那一轮之后：`orphan` 的授权行**全部消失**（回收成功才会删）
- `txt _acme-challenge.orphan.$APEX` 为空
- 没有 `some TXT records could not be reclaimed automatically; their rows are kept and
  retried next round`

```bash
q "SELECT count(*) FROM authorizations WHERE cert_name='orphan';"
txt "_acme-challenge.orphan.$APEX"
grep -c 'reclaiming it before deleting the row' /tmp/a9-recover.log
```

**判据**

| 检查 | 期望 |
|---|---|
| `authorizations`（orphan） | 0 |
| TXT | 空 |
| 日志 | ≥1 次 `reclaiming it before deleting the row` |

**反例（必须判失败，不是通过）**：如果日志里出现
`could not probe for the TXT of an interrupted pass; keeping the row`，说明探测无法给出**权威**结论。
**保持行不删是正确行为**（宁可留着行，也不能凭递归缓存的"没有"就删掉唯一的线索），
但本阶段的判据因此不成立 —— 需要人工查 DNS 后介入。

**顺带记录**：第 5 步在回收之后会继续走首次签发，所以 `orphan` 最终也会有一张证书。
这不是副作用，而是"回收 → 正常签发"的完整路径。

---

## 4. Part B — 声明层生命周期

Part B 用**自己的** state 库和文档，避免与 Part A 的证书名混淆。

```bash
B_CFG=/tmp/wecert-lifecycle/b.yaml
BDB=/tmp/wecert-lifecycle/b.db
DOC=/tmp/wecert-lifecycle/desired-state.yaml

# 注意：Part B 用的是自己的库，别拿 Part A 的 q / sans（它们绑在 $DB 上）
q2() { sqlite3 "$BDB" "$1"; }
sansb() {
  q2 "SELECT writefile('/tmp/wecert-leaf-b.pem', cert_pem) FROM certificates WHERE name='$1';" >/dev/null
  openssl x509 -in /tmp/wecert-leaf-b.pem -noout -ext subjectAltName | tail -n +2
}
```

前提：本环境**没有 CLB**，所以必须 `-require-clb=false`。
guard 1 要求"有 CLB 规则服务这个名字"，在这个环境里永远不成立，
不加这个开关期望文档会是空的（这也是为什么它必须是一个显式开关，而不是默认放宽）。

先写声明（在 `$APEX` 所在区域里）。每条声明一个 TXT 记录，
值里必须带版本标记，用空格或逗号分隔字段：

```
_wecert.alpha    TXT   "v=wecert1 deploy=false"
_wecert.beta     TXT   "v=wecert1 deploy=false"
```

`deploy=false` 是必须的：`wecert-onboard` 的 `-deploy` 默认是 true，
而本环境没有云资源。控制台或 `tccli` 都可以写；`tccli` 的参数名以
`tccli dnspod DescribeRecordList --help` 为准。

`$B_CFG` 从 `$A_CFG` 复制而来：`statePath` 改成 `b.db`，加上下面的 `onboarding` 段，
`certificates` 先保留（observe 模式需要它，enforce 模式再清空）。要点：

```yaml
onboarding:
  zones:
    - REPLACE_ME_APEX
  requireCLBRule: false
  allowlist:
    - REPLACE_ME_APEX
  deploy: false
```

---

### B0 — 声明 → 期望状态

**操作**

```bash
./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX" -dry-run -json | head -60
echo "dry-run 之后 \$DOC 存在吗: $(test -f "$DOC" && echo 是 || echo 否)（期望：否）"

./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX"
cat "$DOC"
```

**期望**

- 文档里出现**一张**证书，名字是注册域派生的 `example-com`（`group.CertName`），
  而不是任何一个具体域名 —— 这是"证书名不随域名集合变化"这条设计的落点
- SAN **恰好**是声明集合 `{alpha.$APEX, beta.$APEX}`。
  注意：apex 不会被自动加进来，`Cover` 只会包含**被声明过**的名字
  （所以想覆盖 apex 就得显式声明 `_wecert` 那条记录）
- `-dry-run` 不写任何文件

**判据**

```bash
grep -E '^\s+name:' "$DOC"
grep -A6 'domains:' "$DOC"
grep -E 'revision|apiVersion|kind' "$DOC"
```

| 检查 | 期望 |
|---|---|
| 证书名 | `example-com` |
| SAN | 恰好 `{alpha.$APEX, beta.$APEX}`，没有多余名字 |
| `apiVersion` / `kind` | `wecert/v1` / `DesiredState` |
| `revision` | 非空，形如 `sha256:<16 hex>` |
| dry-run 后 `$DOC` | 不存在 |

---

### B1 — observe：影子对比不改变行为

**目的**：切到"文档说了算"之前先只读对比一次。价值是**零风险验证推断结果** ——
差异会在指标里露出来，而不是先改了再说。

**操作**：把 `wecert` 配置改成：

```yaml
desiredState:
  mode: observe
  path: /tmp/wecert-lifecycle/desired-state.yaml
```

仍然保留 `certificates:`（observe 模式下**配置说了算**），然后跑一轮：

```bash
./bin/wecert -config "$B_CFG" -state "$BDB" -once -log-level debug 2>&1 | tee /tmp/b1.log
grep 'observe mode' /tmp/b1.log
curl -sS http://127.0.0.1:9800/metrics | grep -E 'desired_state_(shadow_diff|frozen|certificates)'
```

**判据**

| 检查 | 期望 |
|---|---|
| 日志 | `observe mode: converging on the configuration file while reporting the diff against the document` |
| 收敛依据 | **配置里的**证书（不是文档） |
| `wecert_desired_state_shadow_diff` | 0（配置与文档一致时） |
| `wecert_desired_state_frozen` | 0 |
| 状态库 | 没有任何证书被删或重建 |

**失败说明**：`shadow_diff` 不为 0 → 说明配置与文档确实不一致，
**这正是这个模式存在的意义**，先把差异查清楚再切 enforce。

---

### B2 — enforce：文档说了算

**操作**：配置改成

```yaml
desiredState:
  mode: enforce
  path: /tmp/wecert-lifecycle/desired-state.yaml
# enforce 模式下 certificates 必须为空，否则配置加载直接报错
certificates: []
```

```bash
./bin/wecert -config "$B_CFG" -state "$BDB" -once -log-level debug 2>&1 | tee /tmp/b2.log
grep -m1 'enforce mode' /tmp/b2.log
q2 "SELECT name, datetime(not_after,'unixepoch') FROM certificates;"
grep -c 'first issuance' /tmp/b2.log
```

**判据**

| 检查 | 期望 |
|---|---|
| 日志 | `enforce mode: the desired-state document is the single source of truth` |
| `certificates` 行 | 1 行，名字是 `example-com` |
| SAN | `{alpha.$APEX, beta.$APEX}` |
| 第二轮 | 不再 `first issuance`，也不下新订单 |

**失败说明**：如果配置加载就报 "certificates must be empty"，
说明 enforce 模式仍然保留了 `certificates:` 列表 —— 那是设计上的拒绝，
因为"谁说了算"必须唯一。

---

### B3 — 新增声明

**操作**：再加一条 `_wecert.gamma` TXT（`v=wecert1 deploy=false`），然后：

```bash
./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX"
grep -E 'name:|domains:|^      -' "$DOC"
./bin/wecert -config "$B_CFG" -state "$BDB" -once -log-level debug 2>&1 | tee /tmp/b3.log
grep 'SANs no longer match' /tmp/b3.log
```

**判据**

| 检查 | 期望 |
|---|---|
| 新文档 SAN | 出现 `gamma.$APEX`，共三个名字 |
| 证书名 | **仍然是** `example-com` |
| `wecert` | 报 SAN 漂移并重签，新 SAN 含三个名字 |
| 挑战记录 | 过程结束后全部清空 |

**失败说明**：如果证书名从 `example-com` 变成了别的，说明名字是从域名集合派生的 ——
那会让每次域名变更都变成"旧证书退役 + 新证书首签"，直接踩配额。
文档边界上有 `checkNameStability` 会先拦住这种文档。

---

### B4 — 域名下线：移除一条声明

**目的**：删除路径必须比新增保守一个数量级。这里验证"确认缺失 → 宽限期 → 引用检查"
这三道闸依次生效。**注意这是域名级下线（该证书的 SAN 收缩），不是证书级下线** ——
`alpha` 还在，所以 `example-com` 这张证书仍然存在。

> ⚠️ **声明条数会影响这一阶段能否跑通。** 熔断的阈值是"单轮跌幅 > 30%"，
> 所以只有 3 条声明时删掉 1 条就是 **33% > 30% → 那一轮直接冻结**（实测就是这样：
> `the declared name set dropped from 3 to 2 (33%, threshold 30%)`，文档不动）。
> 两种做法：**声明 4 条以上**（删 1 条 = 25%，默认阈值下就能过，最忠实），
> 或者像下面这样**显式放宽** `-drop-threshold 0.5` —— 那等于人工声明"这次是故意的"。
> 顺带：那个 33% 的冻结本身就是一个**应当确认**的行为（熔断按设计工作），值得单独跑一次留证。

**操作**

```bash
# 1) 删掉 _wecert.beta 这条 TXT 记录

# 2) 第一次 onboard：标记缺失，但还在宽限期内，应当被保留（carry）
./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX" \
  -grace 30s -drop-threshold 0.5 -json | grep -E 'beta|carried'
grep -c "beta.$APEX" "$DOC"        # 期望仍然在文档里

# 3) 等过宽限期，再跑一次
sleep 35
./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX" \
  -grace 30s -drop-threshold 0.5 -json | grep -E 'beta|removed'
grep -c "beta.$APEX" "$DOC"        # 期望 0

# 4) wecert 侧：确认它真的把 SAN 收缩了
./bin/wecert -config "$B_CFG" -state "$BDB" -once -log-level debug 2>&1 | tee /tmp/b4.log
grep 'SANs no longer match' /tmp/b4.log
sansb example-com
```

**判据**

| 步骤 | 检查 | 期望 |
|---|---|---|
| 2 | 决策 | `beta.$APEX` 被 **carry**，理由里带 `grace period` |
| 2 | 报告 | `mode` 不是 `frozen`（是宽限期在保护，不是熔断） |
| 2 | 文档 | 仍然包含 `beta.$APEX` |
| 3 | 决策 | `beta.$APEX` 被 **removed**，理由为 `removed: confirmed absent for …, past the … grace period, and no CLB rule references it` |
| 3 | 文档 | 不再包含 `beta.$APEX` |
| 4 | `wecert` | SAN 漂移，重签后为 `{alpha.$APEX, gamma.$APEX}` |
| 4 | 证书名 | 仍然是 `example-com` |

**为什么第 2 步"必须不删"**：声明可能只是抖动（改错、手滑删掉又加回来）。
宽限期就是为这个存在的；一次抖动值两张证书的配额。

**如果宽限期过了但名字还在文档里**：说明引用检查没通过。
检查日志/报告里的 `guardUnavailable` —— CLB API 不可达时系统**故意**什么都不删，
这是设计，不是 bug。本环境里没有 CLB 规则，正常情况下 `referenced()` 为 false。

---

### B5a — 声明全删光：必须冻结

**目的**：验证"空期望状态永不落盘"这条保护。一个"合法的空文件"和"生成失败导致的空文件"
长得一模一样，接受后者的后果是把每张证书的域名全部抹掉。所以这条路径必须冻死，
而不是照写。

**操作**：把 `_wecert.alpha`、`_wecert.gamma`（以及 `beta`）**全部**删掉，然后：

```bash
REV_BEFORE="$(grep -m1 '^revision:' "$DOC")"

./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX" \
  > /tmp/b5a.out 2>&1
echo "退出码: $?  （期望 2 = deliberately frozen）"
tail -5 /tmp/b5a.out

echo "文档是否被清空: $(grep -c 'certificates:' "$DOC")（期望 ≥1，即仍是旧文档）"
echo "$REV_BEFORE"; grep -m1 '^revision:' "$DOC"

# wecert 侧确认指标
./bin/wecert -config "$B_CFG" -state "$BDB" -once -log-level debug 2>&1 | tee /tmp/b5a-wecert.log
curl -sS http://127.0.0.1:9800/metrics \
  | grep -E 'wecert_desired_state_(frozen|age_seconds|certificates)'
```

**判据**

| 检查 | 期望 |
|---|---|
| `wecert-onboard` 退出码 | **2** |
| 输出 | `FROZEN: the previous desired state is untouched`（注意：`-json` 模式不会打印这一行，只有 JSON） |
| `$DOC` | 内容与操作前**完全相同**（行数与 `revision` 都没变） |
| `$DOC.report.json` | 存在，`"mode": "frozen"`，`freezeReasons` 说明**为什么**冻结。实测先被熔断拦下：`the declared name set dropped from 2 to 0 (100%, threshold 30%)`；"空期望状态永不落盘"那道网就在它后面一层，两者都指向"不接受空文档"这个结论 |
| `wecert` 行为 | 仍然按旧文档续期（不是停止工作） |
| `wecert_desired_state_frozen` | **0** —— wecert 只看到"文档仍然有效"，它**无从知道** onboard 那一轮冻结了。别把这一项当成 onboard 的冻结信号（实测确认） |
| `wecert_desired_state_age_seconds` | 持续增长 —— 这才是"onboarding 停了/冻了"的运维信号，应当据此告警 |

**失败说明**：如果文档真被清空了 → 这是最严重的等级：下一次巡检会把所有证书
重建为"无域名"。**立即停止测试**，先修 `assemble` 之前的那道空值判断。

---

### B5b — 证书级孤儿（可选，需要第二个注册域）

**目的**：证书从期望状态里**整体消失**之后，wecert 必须停止为它续期并报警，
而不是继续拿着一份没人管的证书续下去。

**前提**：`$APEX2`（第二个注册域，自己在 DNSPod 上有区域）。

**操作**

```bash
# 1) 声明 $APEX2 的 apex（记录名就是 _wecert，值 v=wecert1 deploy=false）
# 2) 把 _wecert.alpha / gamma 恢复回来，让 $APEX 那张证书也在
# 3) 生成文档并让 wecert 签出两张证书
./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX,$APEX2"
./bin/wecert -config "$B_CFG" -state "$BDB" -once -log-level debug
q2 "SELECT name FROM certificates ORDER BY name;"     # 期望两张

# 4) 只删掉 $APEX2 的那条声明。
#    注意：这会缩小声明集合，可能撞上熔断（见下方说明），所以显式放宽阈值。
./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX,$APEX2" \
  -grace 30s -drop-threshold 0.9
sleep 35
./bin/wecert-onboard -config "$B_CFG" -out "$DOC" -require-clb=false -allow "$APEX,$APEX2" \
  -grace 30s -drop-threshold 0.9

# 5) wecert 侧
./bin/wecert -config "$B_CFG" -state "$BDB" -once -log-level debug 2>&1 | tee /tmp/b5b.log
grep 'no longer in the desired state' /tmp/b5b.log
curl -sS http://127.0.0.1:9800/metrics | grep 'wecert_orphaned_certificates'
q2 "SELECT name FROM certificates ORDER BY name;"     # 期望两张都还在（行不删）
```

**为什么需要 `-drop-threshold 0.9`**：删掉一个注册域的声明会让声明集合从 3 个名字降到 2 个，
跌幅 33% 已经超过默认阈值 30%，熔断会直接冻结这一轮。**这正是设计**：
单轮掉三分之一就该怀疑上游故障。做这个测试时显式放宽阈值，等于人工声明"这次是故意的"。

**判据**

| 检查 | 期望 |
|---|---|
| 文档 | 只剩 `$APEX` 那张证书（`$APEX2` 的消失） |
| `wecert` 日志 | `this certificate is no longer in the desired state, so it will not be renewed and will expire; if that was not intended, restore its declaration and re-run wecert-onboard` |
| `wecert_orphaned_certificates` | **1** |
| 订单 | **不**为那张证书创建任何订单（不再续期） |
| `certificates` 表 | 两行都还在（系统不替人删数据，只报警） |

**失败说明**：如果它还在续期，说明期望状态的"移除"没有传导到收敛侧 ——
这是最危险的一种失败：证书表面正常，实际上已经没人管了。

---

## 5. 观测手册

### 状态库（SQLite）

```bash
q "SELECT name, datetime(not_after,'unixepoch') AS not_after, ari_cert_id,
          deployed_cert_id, deploy_confirmed, consecutive_failures, last_error,
          datetime(issued_at,'unixepoch') AS issued_at
   FROM certificates;"

q "SELECT cert_name, order_url, status, identifiers, datetime(expires_at,'unixepoch') FROM orders;"

q "SELECT cert_name, identifier, status, txt_name, substr(txt_value,1,10)||'…', presented, challenge_sent
   FROM authorizations;"

q "SELECT * FROM identifier_failures;"      # 每个 identifier 的失败账本（联动 fallback）
q "SELECT * FROM cert_fallback;"            # 正在生效的降级（掉了哪些名字）
q "SELECT * FROM retired_certificates;"     # 待回收的云证书（本用例应为空）

sans lifecycle                              # 叶证书的 SAN
```

### DNS

```bash
dig +short TXT "_acme-challenge.$APEX"                                  # 走本机递归
dig +short TXT "_acme-challenge.$APEX" @"$(dig +short NS "$APEX" | head -n1)"   # 直接问权威
```

递归解析器有负缓存（DNSPod 免费版 TTL 下限 600s，负缓存同样吃这个值）。
**判断"记录在不在"一律问权威 NS**，否则会看到过期答案。

也可以直接用仓库里的工具查残留：

```bash
./bin/wecert-preflight -domain "$APEX"     # [3/4] 就是 _acme-challenge 残留检查
```

### 指标

```bash
curl -sS http://127.0.0.1:9800/metrics | grep -E '^wecert_'
```

本用例会用到的那几个：

| 指标 | 看什么 |
|---|---|
| `wecert_certificate_not_after_timestamp_seconds{cert}` | 续期有没有真的推进 |
| `wecert_certificate_consecutive_failures{cert}` | 必须回到 0 |
| `wecert_certificate_ari_window_start_timestamp_seconds{cert}` | ARI 窗口有没有拉到手 |
| `wecert_desired_state_frozen` | 期望状态是否被熔断冻结（1 = 冻结，什么都没改） |
| `wecert_desired_state_shadow_diff` | observe 模式下的差异数，切 enforce 前应为 0 |
| `wecert_orphaned_certificates` | 已不在期望状态里、但还在状态库里的证书数 |
| `wecert_reconcile_panics_total{cert}` | **任何非 0 都是 bug**，直接告警 |

### 日志

```bash
# 一次完整签发的顺序
grep -E 'first issuance|TXT presented|TXT propagated|ACME order created|issued and recorded locally' /tmp/a7.log

# 中断与恢复
grep -E 'TXT from the interrupted pass|resuming the existing order|reclaiming it before deleting the row' /tmp/*.log

# 必须为空（出现即失败）
grep -E 'recovered from a panic|could not be reclaimed' /tmp/*.log
```

---

## 6. 清理与复位

```bash
pkill -f 'bin/wecert' 2>/dev/null    # 守护模式起的那个

# 状态、文档、onboarding 账本与报告
rm -rf /tmp/wecert-lifecycle
#   注意 onboarding 的 state/report 默认落在文档旁边：
#   $DOC.state.json 和 $DOC.report.json

# DNS：删掉本用例留下的所有挑战记录与声明
#   _acme-challenge.$APEX / _acme-challenge.sub.$APEX / _acme-challenge.other.$APEX
#   _acme-challenge.orphan.$APEX
#   _wecert.alpha / _wecert.beta / _wecert.gamma / _wecert（$APEX2 那条）
for n in "" "sub." "other." "orphan."; do
  dig +short TXT "_acme-challenge.${n}$APEX"
done
```

staging 签发的证书**不需要**吊销，也不占生产配额。若 `deploy.enabled` 被打开过，
记得清理腾讯云 SSL 里 alias 以 `wecert/` 开头的测试证书
（`./bin/wecert-preflight -list-certs` / `-prune-certs`）。

---

## 7. 已知边界

| 事项 | 说明 |
|---|---|
| 中断的制造方式 | A4/A9 用 `kill -9`（窗口实测约 29 秒，见 A4）。**不要**改用"黑洞递归解析器"：它会连带打断 lego provider 自己的 zone 查找，TXT 根本写不下去 |
| 退避窗口 | 中断阶段会留下 `consecutive_failures=1` 与约 1 分钟的 `next_attempt_at`（`recordFailure` 的 `1<<0` 退避）。用例里显式用 SQL 清掉它，是为了让恢复步骤立刻能跑，而不是绕过这条设计。**顺带**：`inside the backoff window; skipping` 本身就是个值得确认的日志 |
| 部署 / CLB 绑定 | 不在本用例内。见 `testenv/README.md` Stage B / B2 / B3 |
| `presented=1` 的孤儿行 | A9 用 SQL 构造 `presented=0` 的形态。反过来（行说 presented=1 但 DNS 已被手工删掉）表现为 delete-all 被推迟，最终由 `cleanupOrphanTXT` 收敛；这条由单元测试覆盖（`internal/acme/cleanup_test.go`） |
| 故障降级（failureFallback） | 需要"某些 identifier 持续失败 + 临近过期"才能触发，本用例不构造。默认关闭，且属于会改变证书覆盖范围的安全决策 |
| 时钟 | 续期用改状态库的方式触发，不改系统时钟。改时钟会同时影响 TLS、日志与 ARI 的 `Retry-After` |

---

## 附：最小 PASS 判据（回归用）

日常回归不必跑全部阶段。**这 7 条**覆盖了历史上真正出过问题的缺陷类：

1. A0：`orders`=0、`authorizations`=0、`ari_cert_id` 非空
2. A1：第二轮 `ACME order created` 出现 0 次
3. A4：中断态下同一个 `txt_name` 有 2 行授权、`dig` 返回 2 条 TXT
4. A5：恢复时 `resuming the existing order`，且没有第二张订单
5. A6：并发两张共享挑战名的证书都签发成功
6. A7：`ACME order created` 里 `replaces=true`
7. A9：`reclaiming it before deleting the row` 出现，且授权行清空
8. A4b：换到零重叠的域名集合仍能签发（不带 `replaces`）

Part B 单独跑的话，最少确认 B4（宽限期先 carry 后 remove）和 B5a（空期望状态冻结）。

任何一条不过，都对应一类"绿灯下的慢性病"：配额被悄悄烧掉、DNS 里留下垃圾、
或者某个域名在某天突然失去覆盖。
