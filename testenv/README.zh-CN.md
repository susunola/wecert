# wecert 测试环境

<a href="README.md">English</a> · <b>简体中文</b>

用 Terraform 管理测试资源。**所有资源都在这个模块里，`terraform destroy` 一击清空，不留孤儿计费项。**

分三个阶段，成本递增。**先跑通 A 再决定要不要往下走。**

---

## 阶段 A：wildcard 签发 —— 不需要任何云资源

这是反直觉但很重要的一点：**测通配符证书不需要 CLB，也不需要 CVM。**

通配符只能走 DNS-01，也就是：
- 写一条 `_acme-challenge.<domain>` 的 TXT
- 等它传播到全部权威 NS
- 告诉 LE 来验证

全程只有 DNS API 调用。证书签出来之后上传到腾讯云 SSL 证书服务，同样只是 API 调用 —— **不需要绑定到任何东西**。

```bash
# 用专门的 wildcard 配置（domain 要同时包含 apex 和通配符）
./scripts/e2e-test.sh example.com e2e-config-wildcard.yaml
```

这个阶段验证的东西其实是最多的：

| 验证点 | 为什么重要 |
|---|---|
| **wildcard + apex 共用同一个 TXT 名字** | `example.com` 和 `*.example.com` 的 challenge 值都写在 `_acme-challenge.example.com` 上，必须同时存在。这是 DNS-01 实现里最容易写错的地方 |
| **权威 NS 传播等待** | LE 从多个 vantage point 校验并要求全部一致 |
| **ARI certID 构造** | 构造不出来就拿不到"豁免全部速率限制"的待遇 |
| **幂等性** | 再跑一轮不能产生新订单 |
| **CNAME 委派**（如已配置） | `EffectiveFQDN` 跟随 CNAME 到集中 zone |

本模块 **不需要 apply**。

---

## 阶段 B：验证 `UpdateCertificateInstance` 重绑定 CLB

```bash
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
export TF_PLUGIN_CACHE_DIR=/Users/atom/Documents/dsh/.terraform-plugin-cache

cd testenv
terraform init
terraform plan      # 先看要建什么
terraform apply
```

创建的资源：

| 资源 | 规格 | 说明 |
|---|---|---|
| `tencentcloud_vpc` | 10.99.0.0/16 | 免费 |
| `tencentcloud_subnet` | 10.99.1.0/24 | 免费 |
| `tencentcloud_clb_instance` | **内网型** | 不开公网带宽，省掉 EIP 费用 |
| `tencentcloud_clb_listener` | HTTPS:443，开 SNI | 绑占位证书 |
| `tencentcloud_ssl_certificate` | 自签名占位证书 | apply 时生成，私钥不落盘 |

### 怎么测

Terraform 建的占位证书绑在监听器上，模拟"**wecert 管的证书当前正在线上服务**"。然后把它的 CertId 预置进 wecert 状态库：

```bash
PLACEHOLDER_ID=$(terraform output -raw placeholder_cert_id)

# 预置：让 wecert 以为这张证书已经绑上去了
sqlite3 /tmp/wecert-e2e/state.db \
  "UPDATE certificates SET deployed_cert_id='${PLACEHOLDER_ID}' WHERE name='e2e-test';"

# 跑一轮，wecert 会签发新证书并调 UpdateCertificateInstance(OldCertificateId=占位证书)
./bin/wecert -config e2e-config.yaml -state /tmp/wecert-e2e/state.db -once
```

### 断言

```bash
# 监听器的 certificate_id 应该变成新证书，而不是占位证书
tccli clb DescribeListeners --LoadBalancerId "$(terraform output -raw clb_id)" \
  --region "$(terraform output -raw region)"
```

**这一步验证的是整个项目最关键的设计假设**：腾讯云自己去找"哪些资源绑了旧证书"并逐个更新，所以我们不需要维护监听器清单，也就不会误伤同一监听器上的其它 SNI 证书。

---

## 阶段 C：验证 systemd + CVM 角色

```bash
terraform apply -var create_cvm=true -var enable_cvm_role=true
```

| 资源 | 规格 | 说明 |
|---|---|---|
| `tencentcloud_instance` | S5.MEDIUM2（2C2G） | 按量计费 |
| `tencentcloud_security_group` | 无入站规则 | TAT 是 agent 主动出网，不需要开端口 |
| 公网 IP | 1 Mbps，按流量 | 仅够 TAT 通信 |

验证点：
- systemd unit 能正常拉起、`StateDirectory` 权限正确
- **CVM 角色凭证路径**：wecert 从 `metadata.tencentyun.com` 现取临时凭证，密钥不落盘
- 长驻守护模式下没有凭证过期问题（这是 `dns.provider=tencentcloud` 每次重建 provider 的原因）

不需要 SSH 密钥 —— 用 TAT（自动化助手）远程执行命令。

---

## 成本

| 资源 | 计费 | 量级 |
|---|---|---|
| VPC / 子网 / 安全组 | 免费 | ¥0 |
| 内网型 CLB | 按小时实例费 | 每天几毛量级 |
| CVM（阶段 C） | 按小时 | 每天几元量级 |
| 公网 IP（阶段 C） | 按流量 | 仅 TAT 通信，几乎为 0 |
| SSL 证书服务 | 上传证书免费 | ¥0 |
| Let's Encrypt | 免费 | ¥0 |

> ⚠️ 具体单价随地域和活动变化，**请以控制台结算页为准**。上表只是量级参考。
> 建议在控制台设一个费用告警再开始。

## 清理

```bash
terraform destroy
```

**每次测试结束后务必执行。** 所有资源都带统一 tag（`project=wecert`, `purpose=acme-e2e-test`），可以在控制台按 tag 核对是否还有残留。

另外记得清理 wecert 上传到 SSL 证书服务的测试证书 —— 它们不受 Terraform 管理（wecert 自己创建的），数量多了会撞账号配额：

```bash
tccli ssl DescribeCertificates --region ap-guangzhou   # 找出 Alias 以 wecert/ 开头的
```

## 需要的最小 CAM 权限

阶段 A（wildcard）需要：

```
ssl:UploadCertificate / DescribeCertificate / DeleteCertificate
dnspod:DescribeDomainList / DescribeRecordList / CreateRecord / ModifyRecord / DeleteRecord
```

阶段 B 额外需要：

```
ssl:UpdateCertificateInstance
clb:CreateLoadBalancer / DescribeLoadBalancers / DeleteLoadBalancer
clb:CreateListener / DescribeListeners / ModifyListener / DeleteListener
vpc:CreateVpc / CreateSubnet / DescribeVpcs / DescribeSubnets / DeleteVpc / DeleteSubnet
```

阶段 C 额外需要：

```
cvm:RunInstances / DescribeInstances / TerminateInstances
tat:RunCommand / DescribeCommands / DescribeInvocationTasks
cam:PassRole                       # 把角色关联给 CVM
```

`deploy/cam-policy-test.json` 只覆盖了阶段 A。要跑 B/C 需要额外加权限。

---

## 阶段 B2：2-SAN wildcard + SNI + CVM 后端（实测记录）

比阶段 B 更严格的一组场景：**一张证书带 2 个 wildcard SAN**，
绑在**开了 SNI 的监听器**上，后面挂**真实 CVM 后端**，
从公网做端到端 TLS 验证。

```bash
terraform apply -var create_cvm=true
```

搭出来的东西：

```
CLB（公网型）
└── 监听器 HTTPS:443（SniSwitch=1）
    ├── 规则 test.alpha.<域名>  → 证书 + CVM
    └── 规则 test.beta.<域名>   → 证书 + CVM（同一个）
```

### 结论（全部通过）

- 一张证书覆盖 `*.alpha` + `*.beta`，SAN 完全正确
- 从公网做 TLS 握手，两个 SNI 域名都读到新证书
- 两个域名都能通过 CLB 走到同一个 CVM 后端（HTTP 200）
- **`UpdateCertificateInstance` 确实重绑定了两条规则**

### 一个重要的产品级发现：重绑定不是原子的

实测时间线：

| 时刻 | test.alpha | test.beta |
|---|---|---|
| 调用返回后 30s | 新证书 ✅ | **旧占位证书** ❌ |
| 60s 后 | 新证书 ✅ | 新证书 ✅ |
| 90s / 120s | 稳定 | 稳定 |

一次调用会重绑定所有资源，但**各资源生效时间不同**，存在
30~60 秒的窗口，期间不同端点服务的证书版本不一致。

续期场景下无害（新旧证书都有效），但如果依赖"重绑定瞬间完成"
就会出错 —— 比如首次签发一个全新域名时，那个窗口内该域名
可能还拿不到证书。

**做外部黑盒探测时必须带轮询，不能只测一次。**

### 踩过的 8 个坑（全部是真跑才暴露的）

| # | 现象 | 原因 / 修法 |
|---|---|---|
| 1 | `InvalidZone.MismatchRegion` | 可用区硬编码错了。`ap-guangzhou-3` 该账号下 CVM 不可售，实际是 `-5/-6/-7`。**子网能建出来不代表 CVM 能在那里开机**。用 `data.tencentcloud_availability_zones_by_product` 查 |
| 2 | `InvalidUserDataFormat` | `user_data` 要求 base64，明文要用 `user_data_raw` |
| 3 | `do not support to create v1 target group` | 该账号不支持目标组，改用经典的 `tencentcloud_clb_attachment` |
| 4 | `Lack of parameter Certificate or MultiCertInfo` | 建**规则**时也要带证书 —— CLB 的 SNI 多证书是在规则层配置的 |
| 5 | `HttpCheckDomain:*.alpha... can't be wildcards` | 规则域名不能是通配符（会被当作健康检查 Host）。用具体主机名，它仍被证书的 wildcard 覆盖 |
| 6 | `health_check_http_code cannot be higher than 31` | 这个字段是**位掩码**不是 HTTP 状态码，别填 200 |
| 7 | `uin don't support set L7 custom port for health check` | 该账号不允许给七层规则设自定义健康检查端口 |
| 8 | `You can't specify SubnetId when create open loadbalancer` | 公网型 CLB 不能指定子网；内网型必须指定 |

### 还有一个：公网 CLB 的健康检查源不在 VPC 网段

只放通 VPC 网段和 `100.64.0.0/10` 时，健康检查一直失败，
CLB 对所有请求返回 **504**。

迷惑点：**TLS 握手是正常的**（`curl` 报 504 而不是连接错误，
`ssl_verify_result=20` 说明有证书送出），所以很容易误判成"后端挂了"。
实际后端好好的 —— 直连 CVM 公网 IP 返回 200。

排查方式：临时放开 `0.0.0.0/0 → 80`，504 立刻消失，从而定位到是安全组。

### 最重要的一个：不要让 Terraform 和 wecert 抢同一个字段

调试安全组时我跑了几次 `terraform apply`，结果**两条规则的证书被悄悄改回了占位证书**，
而 wecert 状态库还以为部署的是新证书 —— 两边认知完全不一致。

原因：Terraform 的 `certificate_id` 是**期望状态**，每次 apply 都会强制刷成配置里的值；
而 wecert 是通过 `UpdateCertificateInstance` 在**带外**改这个字段的。
两者管理同一个字段，必然打架。

修法是让 Terraform 不要碰这个字段：

```hcl
resource "tencentcloud_clb_listener" "https" {
  # ...
  lifecycle {
    ignore_changes = [multi_cert_info, certificate_id, certificate_ssl_mode]
  }
}

resource "tencentcloud_clb_listener_rule" "wildcard" {
  # ...
  lifecycle {
    ignore_changes = [certificate_id, certificate_ssl_mode, certificate_ca_id]
  }
}
```

代价：Terraform state 里这个字段会**长期停留在旧值**（本项目里就一直是占位证书的 ID），
`terraform plan` 也不会再报漂移。这是有意为之 —— 这个字段的真相在 wecert 的状态库里，
不在 Terraform 里。

**推广开来：任何"Terraform 管基础设施 + 另一个系统管证书/密钥轮转"的组合都有这个问题。**
要么让 Terraform 管绑定（那 wecert 就不该调 `UpdateCertificateInstance`），
要么让 wecert 管绑定（那就必须 `ignore_changes`）。不能两个都管。

---

## 阶段 B3：按域名分流 + 本机可测

在 B2 基础上加了：后端按 Host 返回不同页面、CLB 安全组、以及 DNS 记录。

### 后端按 Host 分流

CVM 上的 python 后端读 `Host` 头返回不同页面：

| 访问 | 页面 |
|---|---|
| `https://test.alpha.<域>/` | 大写的 **ALPHA** |
| `https://test.beta.<域>/` | 大写的 **BETA** |
| 其它 Host | **UNKNOWN**（红色） |

这样"CLB 的域名路由到底生效没有"一眼就能看出来 —— 两个域名显示同一个页面就是没生效。

页面映射在 `var.backend_pages` 里改，不用动脚本。

### 为什么要建 DNS 记录

之前只能用 `curl --resolve` 或 `openssl -connect` 加 IP 来测，
因为 `test.alpha` / `test.beta` 根本没有解析记录。
建了 A 记录之后浏览器直接就能打开。

注意 `alpha` / `beta` **不是独立 zone**，只是 `atomwangnus.com` 下的子域，
所以记录建在 `atomwangnus.com` 里，`sub_domain` 写成 `test.alpha`。

### CLB 安全组：默认放开，是有意的

```hcl
clb_allowed_cidrs = ["0.0.0.0/0"]   # 默认
```

试过按 IP 白名单收紧，但**出口 IP 不稳定**：会话期间本机出口从
`121.35.103.225` 变成了 `14.153.66.173`，而且不同探测服务还报出第三个地址。
再加上浏览器所在网络的出口无从得知，白名单一旦写错就会把自己关在门外。

而"被安全组挡住"的表现是 **TLS 握手直接被重置**（`SSL_ERROR_SYSCALL`），
不直观，排查成本高。所以在测试环境默认放开，等你确认固定出口 IP 后
改成 `["x.x.x.x/32"]` 重新 apply 即可收紧。

### 新增：cloud-init 本地校验

```bash
make validate-cloudinit
```

从 `.tf` 源码里抽出 `write_files`，对嵌入的 Python / shell 做语法检查。

**这是被一次真实事故逼出来的**：user_data 里的 Python 有个字符串引号不匹配
（`'...\n"`），CVM 建出来了、cloud-init 也"成功"了，但后端一直不监听 80，
现象是 CLB 返回 502 —— 很容易误判成网络或安全组问题，白排查很久。

`user_data` 里的脚本只有机器启动后才执行，语法错误在那之前完全不可见，
所以在 apply 之前先查一遍。加 `--from-state` 可以校验已 apply 的版本。
