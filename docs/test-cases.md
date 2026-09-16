# wecert 测试用例设计

> 基线：`c6d6a51`（v0.4.2）。用例里的**预期值都是从实现读出来的**，不是推测的。
>
> 三份文档的分工：
>
> | 文档 | 回答什么 |
> |---|---|
> | [`docs/test-plan.md`](test-plan.md) | 谁在什么层级跑、缺口优先级、发布门禁 |
> | [`docs/lifecycle-acceptance.md`](lifecycle-acceptance.md) | 端到端怎么跑（TC-LIFECYCLE-01，需要真实 staging + DNSPod） |
> | **本文** | **具体用例：编号、前置、输入、步骤、预期** |
>
> 本文只设计 **test-plan 里 P0/P1 指出的缺口**，不重复已有的 384 个用例。

---

## 1. 缺口 → 用例族

| 用例族 | 目标 | 对应缺口 | 能否进 CI | 条数 |
|---|---|---|---|---|
| **TC-PROBE** | `cmd/wecert-probe` 的命令行契约（退出码、`-wait`、`-json`） | P0-1 | ✅ 需一处可测性改造 | 18 |
| **TC-TATRUN** | `cmd/tatrun` 的远端退出码传播与取证可信度 | P0-2 | ✅ 需一处可测性改造 | 15 |
| **TC-NOOP** | `deploy.enabled=false` 时的部署语义 | P1-2 | ✅ 无需改造 | 5 |
| **TC-ONBOARD** | 声明发现层：记录名拼接、zone/TXT/CLB 枚举 | P1-1 | ✅ 需 httptest | 18 |
| **TC-DNSWAIT** | `WaitAll` / `waitZone` 的传播等待编排 | P1-3 | ✅ 接缝已存在 | 7 |
| | | | | **63** |

### 先说清楚为什么不测 `internal/probe`

`internal/probe` 已有 **16 个**库层用例，且覆盖了要害：读取实际服务的证书、区分"链可信"与"证书正确"、错误证书、陈旧证书、缺失/多余域名、大小写顺序重复不敏感、过期、**拒绝通配符**、空 host、context 取消、无人监听、握手停滞超时、**多地址中任一台不匹配**、并发拨号、部分不可达。

所以 **TC-PROBE 只设计 `cmd/` 层**：退出码映射、多 host 聚合、`-wait` 重试、`-json` 形态。库层不必重测。

---

## 2. TC-PROBE · `cmd/wecert-probe` 命令行契约

### 2.1 被测契约（从实现读出）

```
退出码     0 = 每个 host 都服务了期望证书
           1 = 探测无法完成（解析/拨号/握手失败）
           2 = 探测完成，但证书不是期望的那张
          64 = 用法错误（EX_USAGE）
```

`run()` 的多 host 聚合（`cmd/wecert-probe/main.go`）：

```go
worst := exitOK
for _, host := range hosts {
    code := checkOne(...)
    if code == exitMismatch { worst = exitMismatch }          // 2 压过一切
    else if code == exitUnreachable && worst == exitOK { worst = exitUnreachable }  // 1 只在没更差时
}
```

→ 优先级 **2 > 1 > 0**。源码注释给了理由：*"a mismatch deserves to stop a script more than an unreachable host does"*。

`attemptOnce` 的 `retry` 判定：

```go
if err != nil { return exitUnreachable, true }   // 网络抖动 / VIP 未起 / DNS 未生效 —— 都值得重试
...
if v.OK { return exitOK, false }
return exitMismatch, true                        // 重绑定后 ~15s 内看到旧证书是正常的
```

→ **不可达与不匹配都会重试**，只有 OK 才停。

### 2.2 用例

#### A. 单 host 退出码

| 编号 | 前置 | 输入 | 预期 |
|---|---|---|---|
| TC-PROBE-01 | TLS 桩，证书 SAN = `{a.example.com}` | `-host a.example.com -port <桩端口> -expect-san a.example.com` | 退出码 **0** |
| TC-PROBE-02 | 同上桩 | 同上但 `-expect-san b.example.com` | 退出码 **2**，输出含缺失/多余域名 |
| TC-PROBE-03 | 桩**未启动**（端口无人监听） | `-host a.example.com -port <空端口>` | 退出码 **1**（**不能是 2** —— 这正是分开两个码的意义） |
| TC-PROBE-04 | 桩证书剩余 1h | `-min-valid 168h` | 退出码 **2** |
| TC-PROBE-05 | 桩证书 `notAfter = T` | `-expect-not-after <T 的 RFC3339>` | 退出码 **0** |
| TC-PROBE-06 | 桩换了一版证书，`notAfter = T+1d` | `-expect-not-after <T>` | 退出码 **2**（钉住"重绑定到底生效没有"） |

#### B. 多 host 聚合（TC-PROBE-07~10 是本节的核心）

| 编号 | 输入（3 个桩，各自状态） | 预期 |
|---|---|---|
| TC-PROBE-07 | a 匹配(0)、b 匹配(0) | **0** |
| TC-PROBE-08 | a 匹配(0)、b 不匹配(2) | **2** |
| TC-PROBE-09 | a 匹配(0)、b 不可达(1) | **1** |
| TC-PROBE-10 | a 不匹配(2)、b 不可达(1) | **2**（2 优先，见 2.1） |

#### C. `-wait` 重试

| 编号 | 前置 | 输入 | 预期 |
|---|---|---|---|
| TC-PROBE-11 | 桩一直匹配 | `-wait 30s` | 退出码 0，且**只探一次**（不轮询） |
| TC-PROBE-12 | 桩先返回不匹配，5s 后切换为匹配 | `-wait 30s` | 退出码 **0**，总耗时 < 30s，日志有 ≥2 次尝试 |
| TC-PROBE-13 | 桩一直不匹配 | `-wait 10s` | 退出码 **2**，总耗时 ≈ 10s（不超过 wait + 单次超时） |
| TC-PROBE-14 | 桩一直不可达 | `-wait 10s` | 退出码 **1**，总耗时 ≈ 10s，**且确实重试了**（见 2.4 的注释矛盾） |
| TC-PROBE-15 | 桩一直匹配 | 不传 `-wait`（默认 0） | 退出码 0，**恰好一次**尝试，无任何重试 |

#### D. 参数与输出形态

| 编号 | 输入 | 预期 |
|---|---|---|
| TC-PROBE-16 | 不传 `-host` | 退出码 **64**，且打印 usage 到 stderr |
| TC-PROBE-17 | `-nope`（未知 flag） | 退出码 **64** |
| TC-PROBE-18 | `-expect-not-after "不是时间"` | 退出码 **64**，stderr 提示必须 RFC3339 |
| TC-PROBE-19 | `-version` | 退出码 **0**，stdout 一行版本号 |
| TC-PROBE-20 | `-json`，桩匹配 | stdout 是**一个**合法 JSON 对象，含 `host` / `result` / `verdict` / `attempt`；`result` 含 `sans`、`notAfter`、`trusted`、`resolvedIPs` |
| TC-PROBE-21 | `-json -wait 10s`，桩一直不匹配 | stdout 是 **NDJSON**：每个尝试一行一个 JSON 对象，不是末尾一个聚合对象 |
| TC-PROBE-22 | `-json`，桩不可达 | 输出对象含 `error` 字段且**不含** `result` |
| TC-PROBE-23 | 非 `-json`，桩不匹配 | 人类可读输出到 **stdout**，重试提示到 **stderr**（保证 stdout 可进日志/管道） |

### 2.3 需要的前置改造（可测性）

`run()` 目前自带 `flag.NewFlagSet` 并直接读 `os.Args[1:]`、直接 `fmt.Fprintf(os.Stderr, ...)`。三个改造都很小：

1. `run(args []string, stdout, stderr io.Writer) int` —— 把参数与输出流注入（现在只能靠改 `os.Args` + 重定向来测）
2. TLS 桩需要能**在运行中切换证书**（TC-PROBE-12），即用一个原子指针持有 `tls.Config.Certificates`
3. 端口改为可传（已有 `-port`，无需改）

### 2.4 设计用例时发现的一处代码/注释矛盾

`checkOne` 里写着：

```go
// Only "not in effect yet" is worth waiting for: unreachable and wrong-cert won't fix themselves.
if !retry || deadline.IsZero() || time.Now().After(deadline) {
```

但 `attemptOnce` 对**不可达**也返回 `retry=true`，且它自己的注释说明了理由（"网络抖动 / VIP 未起 / DNS 未传播 —— 都值得重试"）。所以实际行为是**两者都重试**，`checkOne` 那句注释与代码不符。

TC-PROBE-14 的用途就是把真实契约钉死。**建议顺带修掉那句注释**，否则下一个人会按注释去"优化"掉重试。

---

## 3. TC-TATRUN · `cmd/tatrun` 远端取证

### 3.1 被测契约

`main()` 只有两种结果：`run()` 返回 nil → 退出 0；返回 error → stderr 打印 + **退出 1**。

关键行为（已核实，代码是**对的**）：

```go
case "SUCCESS":
    exitCode := derefI64(task.TaskResult.ExitCode)   // TaskResult 为 nil 时保持 0
    fmt.Print(out)
    if exitCode != 0 {
        return fmt.Errorf("command exited with code %d", exitCode)   // → 本进程退出 1
    }
    return nil
```

→ **远端非 0 会冒泡**。但**远端的具体退出码被折叠成 1**，不是原样透传 —— 这条要作为契约钉住。

### 3.2 用例

| 编号 | 前置 | 输入 / 桩返回 | 预期 |
|---|---|---|---|
| TC-TAT-01 | 桩：`TaskStatus=SUCCESS`、`ExitCode=0`、`Output="hello\n"` | 正常三参数 | 退出码 **0**，stdout 恰为 `hello\n` |
| TC-TAT-02 | 桩：`SUCCESS`、`ExitCode=3`、`Output="partial\n"` | 同上 | 退出码 **1**，stderr 含 **"exited with code 3"**，stdout 仍含 `partial` |
| TC-TAT-03 | 桩：`SUCCESS`、`TaskResult=nil` | 同上 | 当前行为：退出码 **0** + 空输出。**用例价值在于把这个含糊行为定下来** —— 建议改为报错（"任务成功但没有结果"），因为取证工具不该在拿不到证据时判成功 |
| TC-TAT-04 | 桩：`FAILED`、`Output="boom\n"`、`ErrorInfo="..."` | 同上 | 退出码 **1**，stdout 含 `boom`，stderr 含错误信息 |
| TC-TAT-05 | 桩：`TIMEOUT` | 同上 | 退出码 **1** |
| TC-TAT-06 | 桩：先返回空 `InvocationTaskSet`，第 3 次返回 SUCCESS | `-interval 100ms` | 不 panic，继续轮询，最终退出 **0** |
| TC-TAT-07 | 桩：`RunCommand` 返回 `Response=nil` | 同上 | 退出码 **1**，报 "empty response"，**不 panic** |
| TC-TAT-08 | 桩：`RunCommand` 返回 `InvocationId=""` | 同上 | 退出码 **1**，报 "no InvocationId" |
| TC-TAT-09 | 桩：一直无任务记录 | `-timeout 1s -interval 100ms` | 退出码 **1**，报超时且含 invocation id |
| TC-TAT-10 | 不设桩 | 缺 `-region` | 退出码 **1**，stderr 指明 `-region` 必需 |
| TC-TAT-11 | 不设桩 | 缺 `-instance` | 退出码 **1**，指明 `-instance` |
| TC-TAT-12 | 不设桩 | 缺 `-cmd` | 退出码 **1**，指明 `-cmd` |
| TC-TAT-13 | 清空 `TENCENTCLOUD_SECRET_ID/KEY` | 三参数齐全 | 退出码 **1**，提示设置这两个环境变量 |
| TC-TAT-14 | 断言**请求体** | `-cmd "echo hi"` | `RunCommand` 请求里 `Content` = **base64("echo hi")**，且 `SaveCommand=false`。历史坑：传明文会报 `InvalidParameterValue ... parameter Content is not valid` |
| TC-TAT-15 | 桩返回 SUCCESS | `-quiet` | stdout **只有**命令输出；"TAT command submitted..." 与 "--- command output ---" 一律走 stderr |

### 3.3 需要的前置改造

`tatrun` 目前把 endpoint 硬编码：

```go
cpf.HttpProfile.Endpoint = "tat.tencentcloudapi.com"
```

且用全局 `flag.Parse()` 直接读 `os.Args`。最小改造：

1. endpoint 允许被覆盖（flag 或 `TAT_ENDPOINT` 环境变量），指向 `httptest.Server` —— 这样 TC-TAT-01~09、14、15 全部可测，**不需要云账号、不产生费用**
2. `run(args []string, stdout, stderr io.Writer) error`，与 TC-PROBE 一致

> 改造 1 有个副作用值得留意：`-endpoint` 出现在生产二进制的 `--help` 里，等于给了一个"把取证流量导向任意主机"的开关。若不希望如此，就用**仅测试可见**的方式（构建 tag，或只读环境变量且文档不宣传）。

---

## 4. TC-NOOP · 部署关闭时的语义

### 4.1 为什么这个最该先补

`deploy.enabled: false` 时用的是 `Noop`。而 **TC-LIFECYCLE-01 全程都是这个模式** —— 也就是说这条路径只有人工验收在跑，单元层完全空白（`deploy/*_test.go` 里没有一处引用 `Noop`）。

其中一条是**刻意的设计**，源码注释写明了理由：

> *Delete 不谎报成功：部署关闭时云上那张证书收不回来。返回 nil 会让回收器以为删掉了、从而忘掉队列项，而云证书其实还在，于是永久泄漏。*

### 4.2 用例

| 编号 | 输入 | 预期 |
|---|---|---|
| TC-NOOP-01 | `Noop{}.Deploy(ctx, "cert", "old-id", pem, key)` | 返回 `("old-id", nil)` —— **原样返回**，不伪造新 ID |
| TC-NOOP-02 | `Noop{}.Deploy(ctx, "cert", "", pem, key)` | 返回 `("", nil)`（首次签发场景，oldID 为空也不报错） |
| TC-NOOP-03 | `Noop{}.Delete(ctx, "")` | 返回 **nil**（空 ID 无事可做） |
| TC-NOOP-04 | `Noop{}.Delete(ctx, "cert-abc")` | 返回错误，且 **`errors.Is(err, ErrDeploymentDisabled)` 为真**。**这条是回归护栏**：改成返回 nil 就会让回收器永久漏掉云证书 |
| TC-NOOP-05 | `Noop{}.Bindings(ctx, "cert")` | 返回 `(0, nil)` |
| TC-NOOP-06 | 编译期 | `var _ Deployer = Noop{}` —— 接口实现断言，防止有人改签名后静默失配 |

`TC-NOOP-06` 成本几乎为零，但能挡住一类"改了接口、`Noop` 没跟上、编译却过了"的情形（如果接口是通过嵌入满足的话）。

---

## 5. TC-ONBOARD · 声明发现层

这一层决定**哪些域名应该有证书**。它错了不报错，只推出一份错误的域名集合 → 整批域名静默失去覆盖。

### 5.1 `joinRecordName` —— 纯函数，零 mock，先测这个

实现（`internal/onboarding/tencent.go`）：

```go
func joinRecordName(name, zone string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || name == "@" {
		return zone
	}
	return name + "." + zone
}
```

注意：**只规范化 `name`，`zone` 原样透传**；且返回**不带尾点**。

| 编号 | 输入 `(name, zone)` | 预期 | 说明 |
|---|---|---|---|
| TC-ONB-01 | `("_acme-challenge", "example.com")` | `"_acme-challenge.example.com"` | 无尾点 |
| TC-ONB-02 | `("sub", "example.com")` | `"sub.example.com"` | |
| TC-ONB-03 | `("_wecert.alpha", "example.com")` | `"_wecert.alpha.example.com"` | 多点相对名 |
| TC-ONB-04 | `("@", "example.com")` | `"example.com"` | DNSPod 的 apex 写法 |
| TC-ONB-05 | `("", "example.com")` | `"example.com"` | 空名等同 apex |
| TC-ONB-06 | `("  _ACME-Challenge  ", "example.com")` | `"_acme-challenge.example.com"` | 去空白 + 转小写 |
| TC-ONB-07 | `("sub.", "example.com")` | `"sub.example.com"` | name 的尾点被去掉，不出现 `..` |
| TC-ONB-08 | `("x", "Example.COM.")` | `"x.Example.COM."` | **不对称**：zone 未被规范化。当前行为如此；用例把它固定下来，并**建议在调用点统一 zone 的来源**，否则同一份数据两种写法会产出两个不同的记录名 |
| TC-ONB-09 | `("alpha.example.com", "example.com")` | `"alpha.example.com.example.com"` | **裸拼接**。DNSPod 返回的是相对名，所以正常不可达；用例的价值是**标注为不可达并锁住**，避免有人以为它会去重 |

TC-ONB-08/09 是"用用例把当前行为写清楚，同时标出值得改的地方"，而不是"断言它是对的"。

### 5.2 枚举层（需要 `httptest`）

腾讯云 SDK 的 endpoint 可覆盖，指向 `httptest.Server` 即可，**不需要云账号**。断言重点是"我们处理响应时的边界"，不是腾讯云怎么响应。

| 编号 | 桩响应 | 预期 |
|---|---|---|
| TC-ONB-10 | zone 列表**分页**（第一页 TotalCount 大于本页条数） | 取全所有页；漏页会导致某些注册域下的声明**完全看不见** |
| TC-ONB-11 | zone 列表为空 | 返回空集合且**不报错**（不是"没有声明"=错误） |
| TC-ONB-12 | TXT 记录分页，且混入非 `_wecert` 前缀的记录 | 只取 `_wecert*`；非声明记录被忽略且不报错 |
| TC-ONB-13 | TXT 值格式非法：缺 `v=`、字段顺序颠倒、多余空格 | **跳过该条并留下可诊断的日志**，不能让整个 onboard 崩掉 |
| TC-ONB-14 | TXT 值大小写不同（`V=wecert1`） | 按契约处理（当前实现若要求小写，用例明确写入预期） |
| TC-ONB-15 | 同一 zone 出现同名两条 `_wecert` 记录 | 行为明确：取其一或报错，**不能静默随机** |
| TC-ONB-16 | CLB 规则域名跨多个 region | 聚合且去重；漏 region 会少一批域名 |
| TC-ONB-17 | `listLoadBalancers` 分页 | 取全所有页 |
| TC-ONB-18 | CLB 上**没有**某个已声明的域名 | **不得**据此删除声明 —— `CLBRules` 的注释明确说它是 guard 而非 infer：最坏只能是"该签的没签"，绝不能是"不该删的删了" |

TC-ONB-18 是这一族里最重要的一条：它锁的是**故障方向**。

---

## 6. TC-DNSWAIT · 传播等待编排

`probeRecords` 等内层已 100% 覆盖，缺的是 `WaitAll` / `waitZone` 的编排。接缝已存在（注入 exchange 函数）。

| 编号 | 场景 | 预期 |
|---|---|---|
| TC-DNSW-01 | 两个 zone，第一个 zone 用掉大部分预算 | 第二个 zone **共享同一个 deadline**，不会各自重新计时 |
| TC-DNSW-02 | 同一 zone 的多条记录 | 权威 NS 列表**只解析一次**（断言 NS 查询次数） |
| TC-DNSW-03 | 一直不就绪，超时 | 报错含**真实已等待时长**（不是"在 5m 内未确认"这种与实际不符的措辞） |
| TC-DNSW-04 | 3 条记录，2 条就绪 1 条不就绪 | 超时信息**只列未就绪的那 1 条**，不把已就绪的混进来 |
| TC-DNSW-05 | 20 条记录 | 并发上限生效（在飞探测数不超过 `maxProbeConcurrency`） |
| TC-DNSW-06 | 首轮就全部就绪 | 立即返回，不进入 `interval` 等待 |
| TC-DNSW-07 | 探测中途 ctx 取消 | 立即返回 `ctx.Err()`，不等满 interval |

---

## 7. 汇总与执行

### 7.1 分层归属

| 用例族 | 层次 | 执行位置 | 频率 |
|---|---|---|---|
| TC-PROBE | L2 集成（本地 TLS 桩） | CI | 每次 push |
| TC-TATRUN | L2 集成（httptest 假 TAT） | CI | 每次 push |
| TC-NOOP | L1 单元 | CI | 每次 push |
| TC-ONBOARD | L1（`joinRecordName`）+ L2（httptest） | CI | 每次 push |
| TC-DNSWAIT | L2（注入 exchange） | CI | 每次 push |

**63 条全部可进 CI，全部不需要云账号、不需要真实 DNS、不消耗任何配额。**

### 7.2 建议的落地顺序

1. **TC-NOOP（6 条）** —— 零改造，`deploy.enabled: false` 是验收用例常态，先把它焊住
2. **TC-ONBOARD 的 9 条纯函数用例** —— 零 mock，`joinRecordName` 是这一族里唯一无需桩的部分
3. **TC-PROBE（18 条）** —— 先做 `run(args, stdout, stderr)` 注入，再补桩的可换证书能力
4. **TC-TATRUN（15 条）** —— 先让 endpoint 可覆盖
5. **TC-ONBOARD 枚举层（9 条）+ TC-DNSWAIT（7 条）** —— 都需要搭 httptest / 注入 exchange

### 7.3 与发布门禁的关系

这 63 条落地后，`docs/test-plan.md` 里这几条就可以勾掉：

- P0-1（`wecert-probe` 零测试）→ TC-PROBE 覆盖
- P0-2（`tatrun` 零测试）→ TC-TATRUN 覆盖
- P1-1（发现层 11 个函数 0%）→ TC-ONBOARD 覆盖
- P1-2（`Noop` 零覆盖）→ TC-NOOP 覆盖
- P1-3（`WaitAll` 编排未覆盖）→ TC-DNSWAIT 覆盖

P0-3（CI 覆盖率下限）与 P0-4（`make check` ≠ CI）是门禁改造，不是用例，仍需单独做。

---

## 附：设计用例过程中发现的三处问题

| # | 位置 | 问题 | 建议 |
|---|---|---|---|
| 1 | `cmd/wecert-probe/main.go` `checkOne` | 注释写 *"unreachable and wrong-cert won't fix themselves"*，但 `attemptOnce` 对**两者都返回 `retry=true`` —— 注释与代码不符 | 改注释（行为是对的：网络抖动与重绑定窗口都值得重试）。否则下一个人会按注释"优化"掉重试 |
| 2 | `internal/onboarding/tencent.go` `joinRecordName` | 规范化 `name` 但**不规范化 `zone`**，且裸拼接（name 已含 zone 会双拼） | 在调用点统一 zone 来源；或用例 TC-ONB-08/09 把行为固定下来并标注 |
| 3 | `cmd/tatrun/main.go` | `SUCCESS` 且 `TaskResult == nil` 时判成功（退出 0、空输出） | 取证工具在拿不到证据时不该判成功，建议改为报错。TC-TAT-03 就是为这个决策设计的 |

第 3 条属于**产品判断**，需要你定：如果认可以"任务成功但无结果"为成功，那就保持现状并把 TC-TAT-03 的预期写成 0；如果认可我的建议，就改成报错。

---

## 变更记录

| 日期 | 变更 |
|---|---|
| 2026-09-16 | 首版，基线 `c6d6a51` / v0.4.2。5 个用例族、63 条用例 |
