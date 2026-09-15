# wecert 测试环境

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
