# 期望状态：声明、生成与切换

这份文档是操作手册。设计动机与取舍见 [`desired-state-providers.md`](desired-state-providers.md)，
那份文档回答"为什么这么切"，这份回答"怎么用、怎么切换、出事怎么看"。

---

## 1. 一句话架构

```
DNS 里的 _wecert 声明  ──►  wecert-onboard  ──►  期望状态文档  ──►  wecert
   （意图，人写）              （推断 + 熔断）      （契约，机器写）    （只读收敛）
```

**wecert 永远不推断。** 它只读一份已经写下来的、可 diff 的期望状态，然后做收敛。
推断全部在 `wecert-onboard` 里，而那个组件可以随时重写、替换、甚至整个丢掉，
签发侧一行都不用改。

这么切的理由是失败模式：来源故障只会让期望状态**不更新**（安全，保持现状），
而如果 wecert 自己去枚举来源，一次接口抖动就可能被读成"这些域名都没了"。

---

## 2. 三种模式

`desiredState.mode` 决定**谁有最终解释权**：

| 模式 | 收敛依据 | 用途 |
|---|---|---|
| `static`（默认） | 配置里的 `certificates` | 历史行为，零风险 |
| `observe` | 仍然按 `certificates`，但**额外**读文档并报告差异 | 迁移前的观察期 |
| `enforce` | 文档 | 动态签发 |

**不要从 `static` 直接跳到 `enforce`。**

`observe` 不签发任何东西，它只回答"如果真的按文档来，会加什么、会删什么"。
先让它跑够时间（建议两周），你会知道：一天漂移几次、有没有批量导入、
有没有奇怪的记录。这些数据直接决定去抖窗口、分组上限和熔断阈值 ——
没有它们，参数只能靠猜，而猜错的代价是账号级的限速。

迁移路径：

```yaml
# 第一步：加上这一节，certificates 保持不变。
desiredState:
  mode: observe
  path: /var/lib/wecert/desired-state.yaml
```

```bash
wecert-onboard -config /etc/wecert/config.yaml -dry-run   # 先看，不写
wecert-onboard -config /etc/wecert/config.yaml            # 落盘
systemctl restart wecert                                   # 进入 observe
curl -s -H "X-Wecert-Token: $TOKEN" localhost:9801/hook/desired | jq .shadow
```

差异长期为零之后：

```yaml
# 第二步：删掉整个 certificates 区块，切到 enforce。
desiredState:
  mode: enforce
  path: /var/lib/wecert/desired-state.yaml
```

> `enforce` 模式下 `certificates` **必须为空**，否则配置加载直接报错。
> 留着它只会造成"我改了配置却没生效"这种最难查的困惑。

---

## 3. 声明语法

一条声明就是一条 TXT 记录，记录名以 `_wecert.` 开头：

```
_wecert.example.com.      TXT  "wildcard=1"
_wecert.api.example.com.  TXT  "profile=tlsserver"
_wecert.www.example.com.  TXT  ""            ; 裸记录，等价于没有附加参数
```

记录名去掉 `_wecert.` 前缀就是**要证书的那个名字**。
TXT 内容是可选参数，用空格、逗号或分号分隔：

| 键 | 取值 | 说明 |
|---|---|---|
| `v` | `wecert1` | 格式版本。写错会报错而不是被忽略 |
| `wildcard` | `1`/`0`、`true`/`false`、`yes`/`no`、`on`/`off` | 同时声明 `*.<名字>` |
| `profile` | `classic` / `tlsserver` / `shortlived` | 覆盖默认 profile |
| `keytype` | `ecdsa-p256` / `ecdsa-p384` / `rsa2048` / `rsa4096` | 覆盖默认密钥类型 |
| `deploy` | 同 `wildcard` | 覆盖默认的部署开关 |

**未知的键一律报错。** `wildard=1` 被静默忽略的结果是"声明了通配符但没生效"，
而人会一直以为它生效了 —— 这类沉默的偏差比一条清晰的报错昂贵得多。

### 为什么声明放在 DNS zone 里

DNS zone 本来就是这个系统的信任根：谁能写这个 zone，谁本来就能为其中任何名字
做 DNS-01 验证、从任何 CA 拿到证书。把声明也放在这里，**没有引入新的信任边界**，
只是把已经存在的能力显式化。

反过来，"DNS 里有记录就签"是明确不做的：zone 里 MX/TXT/SPF/各种验证记录
全在里面，DNS 记录 ≠ 想要证书。授权必须是一个明确的动作。

---

## 4. 守卫：CLB 规则

默认要求**声明必须同时有 CLB 规则兜底**（`onboarding.requireCLBRule`，默认 `true`）。

它挡住两类真问题：

- 声明写了但规则还没配好 —— 会造成一次无用的签发，白烧配额
- 域名拼错了 —— 规则里根本不存在

守卫是**前置条件，不是来源**。这个区别决定了它的失败模式：最坏情况是
"该签的没签"，而不是"不该删的删了"。

**守卫读不到时一律不做任何删除决策**，并且把它当成"通过"处理（保守方向是保留）。
不会降级成"那就只听声明的" —— 降级会让安全性随故障一起消失，而你恰好在那时最需要它。

**守卫答得不全时也一样，而且会单独标记出来。** CLB 的应答自带总数，只要返回的对象
比它声称的少（分页被截断、代理截断响应、某个 region 少给了一条），这一轮就当作
"读不到"处理：不删任何名字，并在报告里写 `guardIncomplete: true`。它和
`guardUnavailable` 的区别是给人看的 —— 后者是天气，重试即可；前者说明规则列表本身在被
截断，而它没提到的每个名字都**没有和任何东西比对过**。

**守卫拒绝 ≠ 摘掉覆盖。** 一个名字只要**声明还在**，即使规则暂时没了（或不在
`allowlist` 里），它也**保持**当前证书里的覆盖：文档不变 → revision 不变 → 不触发签发，
规则恢复时也不会再签一次。守卫只挡住**新增**覆盖。实测一次规则抖动 = 改两次文档、签两次、
两轮没有覆盖；现在的行为是零次。要把覆盖真正摘掉，请删声明 —— 那之后走的是正常的
宽限期 + 引用检查路径（见 §6 闸门 3）。

> 通配符声明不受守卫约束：七层规则的域名里不会出现 `*.example.com`，
> 拿它去要求一条规则等于永远不通过。

---

## 5. 通配符优先：这是省配额的根本手段

`*.example.com` 覆盖它下面**一层**标签的子域。所以声明了它之后：

| 场景 | 没有通配符 | 有 `*.example.com` |
|---|---|---|
| 加 `foo.example.com` | 1 次重签 | **0 次** |
| 批量导入 50 个子域 | 50 次 = 撞满配额 | **0 次** |
| 加 `a.b.example.com` | 1 次重签 | 1 次（需要 `*.b.example.com`） |

注意 `*.example.com` **不覆盖** `example.com` 本身 —— 这是最常见的误解，
所以两个都要显式声明。

**通配符不会被凭空造出来。** 加一张 `*.example.com` 意味着证书能对任意子域
完成握手，那是权限扩张，必须是显式声明的动作。

分组按**注册域（eTLD+1，用 Public Suffix List）**，一张证书一个注册域。
证书名由注册域派生：`example.com` → `example-com`，而且**只由注册域派生**。

映射是**单射**的：点号变成连字符，而注册域里本来就有的连字符会**双写**。
不这样做的话 `a.co.uk` 和 `a-co.uk` 会派生出同一个名字 `a-co-uk`，
文档里出现两张同名证书，契约校验直接拒绝 —— 此后**每一轮都写不进去**，
所有证书一起停止更新，`-force` 也救不回来。

| 注册域 | 证书名 |
|---|---|
| `example.com` | `example-com`（不含连字符的名字**完全不变**） |
| `a.co.uk` | `a-co-uk` |
| `a-co.uk` | `a--co-uk` |
| `my-site.com` | `my--site-com` |

> ⚠️ 升级提醒：含连字符的注册域**会一次性改名**（`my-site.com`：`my-site-com` → `my--site-com`）。
> 名字变了就是一张新证书：会重新签发一次，旧的状态记录变成孤儿。
> `wecert` 与 `wecert-onboard` 必须**一起升级**，否则新二进制读到旧文档会拒绝加载。

> ### ⚠️ 为什么证书名不能跟着域名集合跑
>
> 如果名字随域名集合变化，加一个域名就会在状态库里凭空多出一条新记录，
> 而旧那条的 order URL、ARI certID、deployed CertID **全部成为孤儿**。
> "每张证书最多一个进行中的订单"这条不变量随之失效 —— 两边的订单会同时飞，
> 直接撞上 *5 certificates per exact set of identifiers / 7 days*（这条没有 override）。
>
> 契约层会主动校验这一点：文档里证书名与其域名集合的注册域不匹配，
> `wecert` 会在加载时直接拒绝。

---

## 6. 五条熔断与它们的出口

| # | 不变量 | 表现 | 怎么解 |
|---|---|---|---|
| 1 | 来源失败 ≠ 名字消失 | 整轮冻结，文档一个字不改 | 修好 DNS 权限 / API，下一轮自动恢复 |
| 2 | 期望状态骤变 | 集合掉超过 30%（`dropThreshold`）→ 冻结 | 确认这次下线是有意的，然后 `-force` |
| 3 | 删除比增加保守 | 必须**确认缺失 + 超过 24h 宽限 + 没人引用**三条件同时满足；声明还在的名字根本不进这条路径（覆盖跟着声明走） | 等，或 `-force`；想立刻摘掉覆盖就删声明 |
| 4 | 配额预算 | 7 天内超过 25 次集合变更（`budget`）→ 冻结 | 等窗口滑过，或申请 LE 的 rate limit override |
| 5 | 显式授权 | 没有声明就不签；`allowlist` 限定可签发的注册域 | 加声明 |

**冻结是安全的方向，不是故障。** 冻结期间：文档不动、`wecert` 继续按上一版
正常续期、没有任何证书会断。唯一的代价是新声明的域名要等到解冻之后才会进来。

`-force` 会跳过闸门 2（骤变保险丝）、闸门 3（删除宽限期）和闸门 4（配额预算），
直接按这一轮算出来的结果写。它**跳过不了闸门 1**：来源读不出来时仍然冻结 ——
那正是「读不到」和「确实没有了」必须区分开的场合，`-force` 也变不出没读到的数据。

它必须是由人敲出来的显式动作 —— 自动化流程里绝不能带上它，否则这几道闸门就等于不存在。

> 空期望状态**永远**被拒绝，`-force` 也不行。"合法的空"和"生成失败导致的空"
> 在文件里长得一模一样，而后者一旦被写出去，后果是每张证书的每个域名都被摘掉。
> 真要全部拆掉，请手工操作并停掉续期。

---

## 7. 配置

```yaml
desiredState:
  mode: observe                 # static | observe | enforce
  path: /var/lib/wecert/desired-state.yaml
  maxStaleness: 48h             # 文档多久没刷新就告警

onboarding:                     # wecert 自己不读这一节
  zones: [example.com]          # 留空 = 枚举账号下所有 zone
  requireCLBRule: true
  allowlist: [example.com]      # 留空 = 不限制
  maxNames: 25                  # 与 tlsserver 对齐，将来切 profile 不用改架构
  profile: classic
  keyType: ecdsa-p256
  deploy: true
  gracePeriod: 24h
  budget: 25
  budgetWindow: 168h
  dropThreshold: 0.30
  statePath: /var/lib/wecert/onboard-state.json
  reportPath: /var/lib/wecert/desired-state.report.json
```

任何命令行参数都可以覆盖对应的配置项。

### 关于 `maxStaleness`

这是这套架构**新引入**的失败模式：`wecert-onboard` 挂掉之后，`wecert` 会一直
按旧文档正常续期，一切看起来都正常，只是新域名再也不会进来。

两个信号专门盯这件事：

- `wecert_desired_state_age_seconds` —— 文档年龄，持续增长就是它没在跑
- `wecert_orphaned_certificates` —— 状态库里有、期望状态里已经没有的证书

---

## 8. 部署

`wecert-onboard` 是个一次性进程，跑完就退出，交给定时器驱动：

```ini
# /etc/systemd/system/wecert-onboard.service
[Unit]
Description=wecert desired-state generation
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wecert-onboard -config /etc/wecert/config.yaml
User=wecert
```

```ini
# /etc/systemd/system/wecert-onboard.timer
[Unit]
Description=Refresh the wecert desired state

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

先跑 observe 的话，可以再加一个单元，让它在期望状态真的变了之后再触发 wecert：

```ini
# /etc/systemd/system/wecert-reload.service
[Service]
Type=oneshot
ExecStart=/usr/bin/curl -sf -X POST \
  -H "X-Wecert-Token: ${WEBHOOK_TOKEN}" \
  http://127.0.0.1:9801/hook/reconcile
```

> 只在 `enforce` 模式下这么做。`observe` 模式下文档变化不改变收敛依据，
> 触发一次只是白跑。

`wecert-onboard` 的退出码是可以直接接进监控的：

| 码 | 含义 |
|---|---|
| 0 | 正常写出（或算出来与上一版相同） |
| 1 | 程序本身出错，需要修 |
| 2 | **有意冻结**，需要人看一眼报告 |

---

## 9. 排障

### "我加了域名，怎么没签出来？"

按顺序查，每一步都能直接给答案：

```bash
# 1. 声明读到了吗？
wecert-onboard -config /etc/wecert/config.yaml -dry-run | head -40

# 2. 这个名字为什么没进去？
curl -s -H "X-Wecert-Token: $TOKEN" localhost:9801/hook/desired \
  | jq '.decisions[] | select(.hostname=="api.example.com")'
```

`decisions[].reason` 是给人看的一句话，常见的几种：

| Reason | 含义 | 怎么办 |
|---|---|---|
| `no CLB rule serves this name; the declaration is still there, so the name keeps its coverage` | 守卫 1 没通过，但声明还在，所以覆盖保留（不会触发签发） | 去 CLB 加规则；想把覆盖摘掉就删声明 |
| `covered by the declared wildcard *.example.com` | 它已经在证书覆盖范围内了，**不需要签发** | 什么都不用做（这正是省钱的地方） |
| `unparseable declaration: unknown key "wildard"` | 声明里有拼写错误 | 改 TXT |
| `registered domain "x.com" is not in the allowlist` | 不在允许清单里 | 加进 `allowlist` |
| `kept at the previous revision: ...` | 分组超过 SAN 上限，保留了上一版 | 加一条通配符声明，或拆分名字 |
| `no longer declared, but only absent for 2h0m0s` | 删除宽限期内 | 等，或确认后 `-force` |

### 冻结了

报告文件里有完整的 `freezeReasons`：

```bash
jq '.mode, .freezeReasons' /var/lib/wecert/desired-state.report.json
```

冻结期间**没有任何东西在坏**，只是期望状态停在上一版。先判断这次变化是不是
你干的；是你干的就 `-force` 确认一次，不是你干的就去查来源为什么变了。

### 期望状态文档长什么样

```yaml
# This file is generated by wecert-onboard; do not edit it by hand.
# It is a contract: wecert only reads it and never infers anything.
# To change the desired state, change the upstream declaration (the _wecert DNS
# record / onboarding config) and re-run wecert-onboard; hand edits are overwritten.
apiVersion: wecert/v1
kind: DesiredState
generatedAt: 2026-08-20T12:00:00Z
generator: wecert-onboard/v0.5.0
revision: sha256:761ab0521ef046c2
certificates:
  - name: example-com
    domains: [example.com, "*.example.com", api.example.com]
    profile: classic
    keyType: ecdsa-p256
    deploy: {enabled: true}
```

它是**派生产物**。手工改会在下一次 `wecert-onboard` 时被覆盖，
而且 `revision` 校验会让 `wecert` 拒绝一份被改过的文档。

---

## 10. 已知限制

- **一张证书只能落在一个注册域内。** 契约层会拒绝跨注册域的证书：
  同证书的域名生死与共，而 Let's Encrypt 的配额本来就是按注册域算的。
  真有跨注册域的需求，只能留在 `static` 模式。
- **空期望状态无法表达。** 见第 6 节末尾。
- **不枚举子 zone 的声明归属。** 记录名决定 hostname，与它落在哪个 zone 无关；
  但如果同一个 hostname 在两个 zone 里都写了声明且参数不一致，两条都会被排除。
- **`observe` 模式不下发任何东西。** 它的产物只有报告和指标。
