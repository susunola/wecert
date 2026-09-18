# Stage C：在真实 CVM 上以 systemd + CVM 角色跑通一次续期

> ## 已跑（2026-09-17 / 09-18）
>
> **本文的步骤已经在真机上执行过两轮**，不再是"从未跑过"：
>
> | 轮次 | 报告 | 覆盖到本文的哪一段 |
> |---|---|---|
> | 2026-09-17 | [`e2e-run-2026-09-17-credentialed.md`](e2e-run-2026-09-17-credentialed.md) §4.5、§4.9 | §3 构建 + `install.sh` 安装（sha256 与本机产物一致、路径与权限、三个 unit）；§5 systemd 启动、日志与指标；§6 的凭证取证（配置/unit/磁盘上的零密钥匹配）。§4.9 另外跑通了第 1 节第 5 条：首签 → 手工绑定（用 API 完成，对应控制台那一次）→ 守护进程自动续期并换绑 |
> | 2026-09-18 | [`e2e-run-2026-09-18-credentialed.md`](e2e-run-2026-09-18-credentialed.md) §4.7 | 同一套路径重跑：`install.sh` → systemd → `cvm-role` 下的真实签发与上传，配置里 `SecretId`/`SecretKey`/`loginToken`/`password` 零匹配，元数据服务读回角色名 |
>
> 这两轮**没有**覆盖的：§6.5 的"故意指向不存在的角色名"反证、第 1 节最后两条（跨过一次真实续期
> 窗口的临时凭证过期、多 region / 多 resourceTypes 覆盖）。
>
> 本文其余部分仍然是 runbook：每条"预期"都标注了来源 —— 能追到源码的写明文件与行内字符串；
> 追不到的写 **expect** 或 **跑之前确认**，不做断言。
>
> **要跑起来至少需要**：
>
> | 需要什么 | 为什么 |
> |---|---|
> | 腾讯云测试账号（**不要用生产账号**） | 要建 VPC / CLB / CVM，要调用 `ssl`、`clb`、`cam`、`tat` 接口 |
> | 一个已存在的 CAM 角色 + 策略 | `testenv/` 只用 `cam_role_name` **挂载**角色，**不创建**角色（见第 2 节）|
> | 一个你能改 DNS 的测试域名（DNSPod 托管） | DNS-01 要真写 `_acme-challenge` 记录 |
> | 一个 EIP / 公网出口 | CVM 要能出网（ACME、腾讯云 API）；`testenv` 默认给 CVM 分配公网 IP |
> | 一台能跑 terraform 的机器 + 腾讯云 API 密钥（仅 terraform 用） | 建资源；这份密钥**不进 CVM**，CVM 上靠角色 |
>
> 与配套文档的分工：
>
> | 文档 | 管什么 |
> |---|---|
> | 本文 | Stage C：真机 + systemd + CVM 角色，从安装到一次真续期 |
> | [`testenv/README.md`](../testenv/README.md) | Terraform 环境总览（Stage A / B / B2 / B3 / C、成本、权限） |
> | [`docs/sni-multicert.md`](sni-multicert.md) | L4 的另一半：同一 listener 上两张证书，续期一张不能动另一张 |
> | [`docs/staging-checklist.md`](staging-checklist.md) | 需要真云账号的人工清单（本文是其中"systemd + 角色"那部分的展开） |
> | [`docs/test-plan.md`](test-plan.md) | 分层策略与 L4 在整张图里的位置 |

---

## 1. Stage C 比 Stage A/B 多验证了什么

`scripts/run-stage-ab.sh` 已经能跑通"签发 → 上传 → `UpdateCertificateInstance` 重绑 → 独立取证"，
但它是**人在仓库目录里手敲二进制**。Stage C 换掉的是这件事：**按产品真实运行的方式跑**。

| | Stage A/B（`run-stage-ab.sh`） | Stage C |
|---|---|---|
| 谁在跑 | 当前登录用户在仓库目录敲 `bin/wecert` | systemd 以 `User=wecert` 跑 `/usr/local/bin/wecert` |
| 配置 | 脚本 `sed` 生成的 `/tmp/wecert-e2e/config.yaml` | `/etc/wecert/config.yaml`（`install.sh` 装成 `0640 root:wecert`）|
| 状态库 | `/tmp/wecert-e2e/state.db` | `/var/lib/wecert/state.db`（`StateDirectory=wecert`，`0700`）|
| 凭据 | `~/.wecert/tencent.env` 里的静态密钥，被脚本 `export` 成环境变量 | **CVM 角色**：`credentialMode: cvm-role`，运行时向 `metadata.tencentyun.com` 取临时凭证 |
| 触发 | `-once`，一轮就退 | 常驻进程（每小时一轮 + 启动后抖动的一轮），或 `wecert-once.timer` |
| 指标 | 有，但 `-once` 跑完就退出，只在那一轮期间可读 | 常驻，`/metrics` 持续可读（这才是告警链路） |
| 锁 | 不涉及 | 跨进程 `flock` 真正生效（daemon 与 timer 二选一）|

**所以 Stage C 能证明的**：

1. `install.sh` 装出来的那套路径约定（二进制、`/etc/wecert`、`/var/lib/wecert`、三个 unit）**真的能跑**，
   而不是"看起来对"。
2. systemd 的加固项（`ProtectSystem=strict`、`CapabilityBoundingSet=`、`StateDirectoryMode=0700` 等）
   **不挡路**：一个 Go 程序在空 capability、只读 `/etc` 的沙箱里仍能出网、写状态库。
3. **角色凭证路径可用**：没有任何静态密钥落盘、落 unit、落环境变量，而 `ssl:UploadCertificate` /
   `UpdateCertificateInstance` 仍然成功。
4. 常驻收敛：`wecert_last_reconcile_timestamp_seconds` 会持续推进，而不是"起来了但一轮都没跑完"。
5. 在有 CLB 的前提下，**首签 → 人工绑定一次 → 之后自动重绑**这条完整链路（这是本项目的核心断言）。

**Stage C 不能证明的**（别把它当总验收）：

- **`-dry-run` 绿 ≠ 角色路径可用。** 第 11 轮之后 `-dry-run` 会真的构建 DNS provider 与 deployer
  （`cmd/wecert/main.go` 的 `buildCredentialBearingComponents`，所以静态 `secretId`/`secretKey` 会被
  校验），但 **CVM 角色的凭证获取仍然推迟到首次使用**（`internal/deploy` 的 `LazyTencentCLB` 构造时不
  解析凭证），而 `acme.EnsureAccount()` 只跟 ACME 服务端说话。也就是说一个指向不存在角色的
  `-dry-run` 照样退出 0 —— 实测（2026-09-18）：
  `credentialMode=cvm-role` + `roleName: wecert-role-that-does-not-exist` 在没有任何元数据服务的机器上
  仍然是 `dry run finished …` / 退出 0。详见第 4 节。
- **重绑定的时序与原子性**：那是 Stage B 的战场，`UpdateCertificateInstance` 是异步且非原子的
  （实测 30s–2min 内逐条切换，README《The rebind is asynchronous **and not atomic**》）。
- **SNI 多证书互不干扰**：见 [`docs/sni-multicert.md`](sni-multicert.md) 与 `scripts/e2e-sni.sh`。
- **临时凭证过期行为**：`fetchCVMRoleCredential` **刻意不缓存**、每次调用重取。实测（2026-09-18，真实 CVM 角色）：元数据返回的 `ExpiredTime` 是**每次取到时刻 + 12.0 小时**，不是本文原先写的「一般 2 小时」；一次守护进程重启后的新一轮续期（19:47）也重新取了一次（tcpdump 抓到 38 次 metadata GET），说明「不缓存」这一半是对的，而「2 小时」这个数字是错的。
  一次 Stage C 只跨几分钟，证明不了"跨过续期窗口仍正常"。真要证，得让它跑过一个真实续期窗口。
- **多 region / 多 resourceTypes / 规模**：`tencent.regions` 少写一个 region 就静默不更新，这条只有把
  那个 region 的 CLB 也纳入才谈得上验证。

---

## 2. 用 Terraform 建一台带角色的 CVM

### 2.1 先建角色，再 apply

**`testenv/` 不创建 CAM 角色，只挂载一个已存在的角色。** `testenv/cvm.tf` 里唯一的角色相关行是：

```hcl
cam_role_name = var.enable_cvm_role ? var.cam_role_name : null
```

`variables.tf` 里 `cam_role_name` 的描述就是"Name of the CAM role **to attach** to the CVM"。
整个 `testenv/` 没有任何 `tencentcloud_cam_role` / `cam_role` 资源。

所以顺序是：

```bash
# 1) 先在 CAM 控制台（或 tccli）建角色 wecert-test-role，并挂上策略。
#    策略内容用仓库里现成的：deploy/cam-policy-runtime.json
#    （README《Tencent Cloud permissions》列出了运行时真正会调的 ssl / dnspod 动作）
#    注意 testenv/README.md 的提醒：deploy/cam-policy-test.json 只覆盖 Stage A，跑 B/C 要额外权限。

# 2) 挂载角色还额外需要 cam:PassRole —— 这是 testenv/README.md 明确列出的 Stage C 权限。
```

### 2.2 变量

`testenv/variables.tf` 里与 Stage C 有关的变量（**名字就是下面这些，不要另造**）：

| 变量 | 默认值 | Stage C 怎么设 |
|---|---|---|
| `create_cvm` | `false` | **必须 `true`** —— 否则不建 CVM |
| `enable_cvm_role` | `false` | **必须 `true`** —— 否则 `cam_role_name` 传 `null`，CVM 没有角色 |
| `cam_role_name` | `wecert-test-role` | 改成你实际建好的角色名 |
| `create_clb` | `true` | 保持 `true`：没有 listener 就没有"绑定 → 重绑"这条链路可验 |
| `availability_zone` | `ap-guangzhou-6` | **先查再定**。`variables.tf` 自己写明 `ap-guangzhou-3` 在本账号下报 `InvalidZone.MismatchRegion`；而 `testenv/terraform.tfvars.example` 里那份**过期的示例**恰恰写着 `ap-guangzhou-3`，别照抄 |
| `cvm_instance_type` | `S5.MEDIUM2` | 2C2G，最小规格 |
| `cvm_image_id` | `img-487zeit5` | Ubuntu 22.04（ap-guangzhou）。镜像 ID 分 region，换 region 要覆盖 |
| `cvm_charge_type` | `POSTPAID_BY_HOUR` | 按量计费，随时 destroy |
| `region` | `ap-guangzhou` | 与 CLB、CVM 同一个 region |

### 2.3 命令

```bash
cd testenv

# 凭据只给 terraform 用，走环境变量，不写进文件：
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
export TF_IN_AUTOMATION=1
[[ -n "${TF_PLUGIN_CACHE_DIR:-}" ]] && export TF_PLUGIN_CACHE_DIR

terraform init -input=false

# 先看可用区，再决定 -var availability_zone：
terraform plan -input=false -out=tfplan \
  -var create_cvm=true \
  -var enable_cvm_role=true \
  -var cam_role_name=wecert-test-role
terraform output available_zones      # 来自 zones.tf 的 data source

terraform apply -input=false tfplan
```

`run-stage-ab.sh` 用的就是 `plan -out=tfplan` → `apply tfplan` 这一套，好处是 apply 的就是你看过的
那份 plan（`-var` 已经烘进 plan 文件，apply 时不必重复）。

建完读输出：

```bash
terraform output cvm_instance_id    # ins-xxxx
terraform output cvm_public_ip
terraform output cvm_cam_role       # 期望是 wecert-test-role；空字符串说明角色没挂上
terraform output clb_id
terraform output listener_id
terraform output clb_vip
terraform output teardown_command
```

`cvm_cam_role` 空字符串**不是报错**，它是 `outputs.tf` 里"没有角色"的表达方式：

```hcl
value = var.create_cvm ? var.enable_cvm_role ? var.cam_role_name : "" : null
```

看到空字符串就说明 `enable_cvm_role` 没生效 —— 这时候继续往下走，第 6 节那套取证会直接失败。

### 2.4 成本

`testenv/README.md` 给的量级（**不是报价，以控制台账单页为准**）：

| 资源 | 计费 | 量级 |
|---|---|---|
| CVM（Stage C 才有） | 按小时 | 几元/天 |
| 公网 IP（Stage C 才有） | 按流量 | 只有 TAT 的流量，基本为 0 |
| CLB | 实例费按小时 | 几毛/天 |
| SSL 证书服务 | 上传免费 | ¥0 |
| Let's Encrypt | 免费 | ¥0 |

> ⚠️ 开跑前在控制台设一个**费用告警**。跑完 `terraform destroy` —— 但 wecert 上传到 SSL 证书服务的
> **测试证书不归 terraform 管**，要自己清（`wecert-preflight -list-certs` 找 Alias 以 `wecert/` 开头的）。

---

## 3. 构建 linux/amd64 二进制并用 install.sh 安装

### 3.1 构建

```bash
make release
# 产物：dist/wecert_{linux_amd64,linux_arm64,darwin_arm64}
#      dist/wecert-onboard_{linux_amd64,linux_arm64,darwin_arm64}
#      dist/SHA256SUMS
# 这一节要的是 dist/wecert_linux_amd64 与 dist/SHA256SUMS。
```

`make release` 用 `CGO_ENABLED=0 GOOS=... GOARCH=...` 交叉编译（SQLite 走纯 Go 实现），所以产物不依赖
glibc，直接扔到 Ubuntu 上能跑。它**先 `rm -rf dist`**，所以别把别的东西放在 dist 里指望留下。

### 3.2 怎么把东西送到 CVM 上

`install.sh` 不是单文件安装器 —— 它从**自己所在目录**读别的文件：

| 它要读的 | 代码位置 | 缺了会怎样 |
|---|---|---|
| `config.example.yaml`（→ `/etc/wecert/config.yaml`） | `install.sh:118` | 只打印 warning，配置要你手写 |
| `deploy/systemd/wecert*.service` / `.timer` | `install.sh:129` | 打印 Error：二进制和配置装好了，但**没有服务可启动** |

所以要送过去的是这一组：`dist/wecert_linux_amd64`、`dist/SHA256SUMS`、`install.sh`、
`config.example.yaml`、`deploy/systemd/`。

三种送法，按可行性排：

**(a) 从 CVM 拉（推荐，不依赖 SSH）** —— CVM 有公网出口。把 `dist/` 放到 CVM 能访问的 HTTPS 地址
（COS 预签名 URL、你自己的静态站、对象存储都行），然后在 CVM 上拉：

```bash
# 用仓库自带的 tatrun 在 CVM 上执行命令，不需要 SSH、不需要开入站端口：
./bin/wecert-tatrun -region ap-guangzhou -instance ins-xxxx -cmd '
  set -e
  mkdir -p /root/wecert-install && cd /root/wecert-install
  curl -fsSLO https://YOUR-HOST/wecert_linux_amd64
  curl -fsSLO https://YOUR-HOST/SHA256SUMS
  curl -fsSLO https://YOUR-HOST/install.sh
  curl -fsSLO https://YOUR-HOST/config.example.yaml
  mkdir -p deploy/systemd
  for u in wecert.service wecert-once.service wecert-once.timer; do
    curl -fsSL -o deploy/systemd/$u https://YOUR-HOST/deploy/systemd/$u
  done
  sha256sum -c SHA256SUMS --ignore-missing   # expect: wecert_linux_amd64: OK
  ls -la
'
```

> **跑之前确认**：`internet_max_bandwidth_out = 1` 限制的是 CVM 的**出方向**带宽，而这里做的是
> **下载**（入方向），所以 **expect** 不受这 1 Mbps 约束；但腾讯云对入方向的实际策略以控制台/计费
> 文档为准 —— 第一次拉的时候看一眼耗时和账单，不要照抄这句话。

**(b) SSH / scp** —— `testenv/cvm.tf` **没有**设置 `key_name` 或 `password`，所以默认根本没有可登录的
凭据；要用这条路得先改 terraform（加 `key_name`、并在 `cvm.tf` 的安全组里加 22 端口入站规则）。
provider 1.83.x 的资源 schema 里能查到 `key_name` 字段，但**跑之前用下面这条确认**，不要照抄：

```bash
terraform providers schema -json | python3 -c 'import json,sys; s=json.load(sys.stdin); print("key_name" in json.dumps(s["provider_schemas"]))'
```

**(c) 在 CVM 上编译** —— 装 Go 再 `make release`，零传输但最重，只在你既没有 SSH 也没有可发布地址时考虑。

> **TAT 不适合传二进制**：`tatrun` 把命令 base64 后放进 `RunCommand.Content`，而一个 Go 二进制十几 MB，
> 远超一条命令的合理大小。TAT 用来**执行**命令（下一步的安装、取证），不用来搬文件。

### 3.3 安装

```bash
cd /root/wecert-install
sudo ./install.sh ./wecert_linux_amd64
```

**逐条对照 `install.sh` 实际做的事**（下面每一条都能在 `install.sh` 里找到对应行）：

| 步骤 | 结果 |
|---|---|
| 检查非 root | 不是 root 直接退出 |
| 检查文件存在 | 不存在直接退出 |
| `file -- "${BINARY}"` 且要求包含 `ELF 64-bit` | 不是 Linux ELF 就拒绝 |
| `SHA256SUMS` 在二进制旁边 | **在** → 校验，不匹配**拒绝安装**；**不在** → 只 warning（"会被 root 安装并以 CAM 凭据+私钥库运行"）|
| 建系统用户 | `useradd --system --no-create-home --shell /usr/sbin/nologin wecert`（已存在则跳过）|
| 装二进制 | `/usr/local/bin/wecert`，`0755 root:root` |
| 建配置目录 | `/etc/wecert`，`root:wecert`，`0750` |
| 建状态目录 | `${WECERT_STATE_DIR:-/var/lib/wecert}`，`wecert:wecert`，`0700`（`install -d`）|
| 放配置 | **仅当 `/etc/wecert/config.yaml` 不存在**时，把 `config.example.yaml` 装成 `0640 root:wecert` |
| 装 unit | `deploy/systemd/` 下的三个文件 → `/etc/systemd/system/`，`0644` |
| `systemctl daemon-reload` | 执行 |
| 启动服务 | **不启动** —— 脚本最后明确写"还有三步" |

两个容易踩的点：

1. **`file` 命令必须先装上。** `install.sh:40` 是裸的 `file -- "${BINARY}"`，脚本开着 `set -euo pipefail`，
   所以 `file: command not found` 会让整个安装**在架构检查这一步中止**（此时二进制还没装）。
   Ubuntu 云镜像通常自带 `file`；跑之前 `command -v file` 确认一次，没有就 `apt-get install -y file`。
2. **不要用 root 跑第 4 节的 `-dry-run`。** `install.sh` 自己用一整段注释解释了原因：root 跑一次会在
   `/var/lib/wecert/` 里留下 `root:root 0600` 的 `state.db`，而 `StateDirectory=` 只修**目录**的归属，
   修不了**已经在里面的文件** —— 之后服务就 crash-loop 在 `pre-create state file ... permission denied`，
   而且报错完全不指向真正的原因。第 7 节有这两个签名的完整说明。

---

## 4. CVM 角色配置 + `sudo -u wecert` 的 `-dry-run`

### 4.1 配置

`/etc/wecert/config.yaml` 的关键部分（`install.sh` 放进去的就是 `config.example.yaml`，
它默认已经是 `dns.provider: tencentcloud` + `credentialMode: cvm-role`，所以改动很小）：

```yaml
statePath: /var/lib/wecert/state.db

acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com

dns:
  provider: tencentcloud     # 与部署共用同一套 CAM 凭据（含角色），所以文件里没有 DNSPod token
  ttl: 600
  propagationTimeout: 5m
  pollingInterval: 5s

tencent:
  credentialMode: cvm-role
  roleName: wecert-test-role # 必须与 terraform 挂到 CVM 上的角色名逐字一致
  resourceTypes:
    - clb
  regions:
    - ap-guangzhou           # CLB 是地域资源：少写一个 region，那里的证书就静默不更新

metrics:
  listen: 127.0.0.1:9800

certificates:
  - name: stage-c-test
    profile: classic
    keyType: ecdsa-p256
    domains:
      - test1.example.com    # 换成你的测试域名
    deploy:
      enabled: true
```

**为什么没有 `secretId` / `secretKey`** —— 直接读 `internal/deploy/credentials.go`：

```go
switch cfg.CredentialMode {
case config.CredentialStatic:
    id, key := cfg.SecretID, cfg.SecretKey      // 配置优先
    if id == ""  { id  = os.Getenv(EnvSecretID) }   // 再退到环境变量
    if key == "" { key = os.Getenv(EnvSecretKey) }
    ...
case config.CredentialCVMRole:
    return func(ctx context.Context) (common.CredentialIface, error) {
        return fetchCVMRoleCredential(ctx, cfg.RoleName)   // 只看 roleName
    }, nil
```

`cvm-role` 这一支**从头到尾没有读过 `cfg.SecretID` / `cfg.SecretKey`，也没有读过环境变量** ——
它唯一的输入是 `cfg.RoleName`，唯一的动作是 GET
`http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/<roleName>`。
所以配置里放密钥不是"会被覆盖"，而是**根本不会被看**。

两个前提条件（都在 `internal/config/config.go` 的校验里）：

- `credentialMode` 只接受 `static` / `cvm-role`，空值默认 `cvm-role`；
- `cvm-role` 且 `roleName` 为空 → 配置加载直接失败：`tencent.credentialMode=cvm-role requires roleName`。

另外：**这里说"没有静态密钥"，指的是 CAM 凭据。** 如果你把 `dns.provider` 写成 `dnspod`，那
`dns.loginToken` 仍然是一个长期有效的 DNSPod token，躺在 `0640 root:wecert` 的文件里。
要做到"文件里一个长期密钥都没有"，就得保持 `dns.provider: tencentcloud`（默认值）。

改完权限要对（`install.sh` 已经设好，手改过就重设一次）：

```bash
sudo chown root:wecert /etc/wecert/config.yaml
sudo chmod 0640 /etc/wecert/config.yaml
sudo -u wecert test -r /etc/wecert/config.yaml && echo "wecert can read the config"
```

### 4.2 `-dry-run`

```bash
sudo -u wecert /usr/local/bin/wecert -config /etc/wecert/config.yaml -dry-run
```

（`sudo -u wecert <命令>` 直接 exec 目标命令，不经过 wecert 用户的登录 shell，所以
`--shell /usr/sbin/nologin` 不影响；反过来，想 `sudo -u wecert -s` 进交互 shell 是进不去的。）

**绿色的一轮预期长这样**（字符串取自源码；`key=value` 的排版是 slog 的 TextHandler，
`newLogger` 明确不带时间戳，因为在 journald 下由 journal 加）：

| 来源 | 期望出现 |
|---|---|
| `cmd/wecert/main.go` `logStartup` | `wecert starting version=... directory=https://acme-staging-v02... production=false statePath=/var/lib/wecert/state.db certificates=1` |
| 同上，首次运行 | `level=WARN msg="no account in the state store; registering a new ACME account"` |
| 同上，每张证书 | `loaded certificate cert=stage-c-test profile=classic domains=1 maxNames=100 renewBefore=720h0m0s deploy=true` |
| `newProvider` | `desired state comes from the configuration file mode=static certificates=1` |
| `-dry-run` 分支 | `dry run finished: the config, the ACME account, the desired-state source, the DNS provider and the deployer are all fine; nothing was issued or deployed mode=static provider=static certificates=1 probing=on (port 443, timeout 10s, max 3 hosts/cert)` |
| 退出码 | `0` |

`provider=static` 来自 `internal/spec/static.go` 的 `Kind()`（返回 `config.ModeStatic`）；
`probing=on (...)` 里的三个数字是 `probe` 段的默认值（`internal/config/config.go`：`port` 默认 443、
`timeout` 默认 10s、`maxHostsPerCert` 默认 3，`enabled` 默认 true）。

**这一轮到底证明了什么、没证明什么**（这是本节的重点）：

| 证明了 | 依据 |
|---|---|
| 配置能被解析、校验通过 | `config.Load` 在最前面，失败就没有后面的日志 |
| 状态目录可写、schema 能建/能验 | `state.OpenUnlocked`（`-dry-run` 走的是**不加锁**的开库路径）|
| ACME 服务端可达、账户可注册/可加载 | `acme.EnsureAccount` 会向 `acme.directory` 发请求；首次运行还会**真的注册账号** |
| 期望状态来源可构造 | `newProvider` 通过 |

| **没**证明 | 依据 |
|---|---|
| **CVM 角色凭证可用** | `buildCredentialBearingComponents`（`cmd/wecert/main.go`）会构造 DNS provider 与 deployer，但两者都不在构造时取凭证：`LazyTencentCLB` 把角色凭证的获取推迟到首次 `Deploy`/`Delete`/`Bindings`，`acme.NewDNSSolver` 对 `cvm-role` 也是每次使用时才取。于是角色名写错、或元数据服务不可达，`-dry-run` 仍然退出 0（2026-09-18 实测：不存在的角色名 + 无元数据服务的机器 → `dry run finished` / 退出 0） |
| 指标端口能绑 | `startMetricsServer` 在 `-dry-run` 返回点**之后** |
| 快照目录可写 | `dirIsWritable` / `startStateBackups` 同样在后面 |
| 任何 DNS 或部署行为 | 一行都没执行 |

> 顺带一提：`-dry-run` **不是只读的**。首次运行它会写 `state.db`（建库 + 注册 ACME 账号），
> 这就是 `OpenUnlocked` 注释里那句"`-dry-run` registers the ACME account on a first run"。
> 账号是有限资源（**10 个 / IP / 3 小时**），别反复删库重跑。

---

## 5. `systemctl enable --now wecert`：成功判据与指标

### 5.1 启动

```bash
# 二选一，不要同时开 —— 它们共用一个状态库，而 flock 只保证"单个进程内至多一个在途订单"
sudo systemctl enable --now wecert            # 常驻
# 或者：
# sudo systemctl enable --now wecert-once.timer   # 每小时跑一轮就走

systemctl is-enabled wecert    # expect: enabled
systemctl is-active  wecert    # expect: active
systemctl status wecert --no-pager
journalctl -u wecert -f
```

### 5.2 日志里的成功判据（按时间顺序）

| # | 期望看到 | 含义 |
|---|---|---|
| 1 | `wecert starting version=... directory=... production=false ...` | 进程起了，读的是你那份配置 |
| 2 | `desired state comes from the configuration file mode=static certificates=1` | 期望状态来源 OK |
| 3 | `network-side certificate probing is on port=443 timeout=10s maxHostsPerCert=3` | 黑盒探测开着（这是唯一不信控制面的证据）|
| 4 | `entering daemon mode interval=1h0m0s` | 进入常驻循环（`-once` / timer 模式**没有**这一行，它是 `RunOnce` 后直接退出）|
| 5 | 首签：`certificate uploaded; waiting for a one-time manual bind in the CLB console cert=stage-c-test notAfter=... uploadedCertId=<新 CertId> hint=...` | **上传成功但还没绑定** —— 此时 `wecert_certificate_deployed` 仍然是 **0**，这是对的，不是故障 |
| 6 | 绑定后下一轮：`confirmed the certificate is bound to cloud resources cert=stage-c-test certId=<CertId> resources=N` | 只读的绑定检查确认了，`deploy_confirmed` 变 true |
| 7 | 强制续期后：`the live certificate's SANs no longer match the config; reissuing now cert=... detail=...` | 域名集合变了，立刻重签（这条会提示它消耗 "Certificates per Registered Domain, 50 / 7 天，账号间共享"）|
| 8 | 续期落地：`certificate renewed and live cert=stage-c-test notAfter=... daysLeft=... deployedCertId=<新 CertId> ariCertId=true` | **Stage C 的终点**：新证书已经通过 `UpdateCertificateInstance` 换到 listener 上 |

> 第 7 步是这次测试里**唯一能主动触发续期**的可靠手段。原因看 `internal/acme/manager_renew.go`：
> ARI 窗口可用时（`ARIWindowStart/End` 非零）走 ARI 给的时间；只有 ARI 不可用时才退到
> `NotAfter - renewBefore`。所以"把 `renewBefore` 改小"在生产/预发上**不会**让续期提前 ——
> 要在这个 session 里看到一次真续期，就给证书的 `domains` 加一个测试子域，然后
> `sudo systemctl restart wecert`。
>
> **配置只在启动时读一次**（`config.Load` 在 `runDaemon` 之前，代码里没有 SIGHUP 重载），
> 所以改完配置必须 `systemctl restart wecert`。

### 5.3 指标

```bash
curl -s localhost:9800/healthz; echo                      # expect: ok
curl -s localhost:9800/metrics | grep -E '^wecert_(certificate_(deployed|not_after_timestamp_seconds|consecutive_failures|ari_window_start_timestamp_seconds)|last_reconcile_timestamp_seconds|reconcile_total|reconcile_panics_total)'
```

指标名与语义都取自 `internal/metrics/metrics.go`：

| 指标 | 期望 | 说明 |
|---|---|---|
| `wecert_certificate_deployed{cert="stage-c-test"}` | 首签后 `0`，绑定确认后 `1` | 它反映的是 `deploy_confirmed`，**不是**"上传过"。help 原文：*"0 otherwise (including the period after the first upload while waiting for a manual bind)"* |
| `wecert_certificate_not_after_timestamp_seconds{cert="..."}` | 签发前**整条 series 不存在**；签发后是 unix 秒 | 这是**主过期信号**，告警建在它上面 |
| `wecert_certificate_ari_window_start_timestamp_seconds{cert="..."}` | 非 0 = 已拿到 ARI 窗口；`0` = 还没拿到 | 拿到 ARI 才有续期限额豁免 |
| `wecert_certificate_consecutive_failures{cert="..."}` | 期望 0 | 持续 > 0 就是要人介入 |
| `wecert_last_reconcile_timestamp_seconds` | 持续增长 | **0 表示启动以来一轮都没跑完** —— "进程活着但什么都没收敛"就靠它暴露 |
| `wecert_reconcile_total{cert="...",result="ok"}` | 每完成一轮 +1 | `result` 还有 `error` / `skipped`（`skipped` = 在退避窗口内故意不跑）|
| `wecert_reconcile_panics_total{cert="..."}` | 必须是 0 | 非 0 就是 bug，直接告警 |

再补一条**不来自控制面**的证据：如果 wecert 跑在能访问 CLB VIP 的机器上，`probe` 会自己拨 443：

```bash
curl -s localhost:9800/metrics | grep -E 'wecert_certificate_probe_(match|errors_total|not_after)'
```

- `wecert_certificate_probe_match{host="test1.example.com"}` 期望 `1`；
- `wecert_certificate_probe_not_after_timestamp_seconds{host="..."}` 应该和
  `wecert_certificate_not_after_timestamp_seconds{cert="..."}` 对得上 —— 对不上就是"控制面说换了、实际没换"。
- `wecert_certificate_probe_errors_total` 增长说明**根本没拨通**（环境问题，不是证书问题）。

> 通配符不会被探测（`*.example.com` 没有可拨的地址）；如果这张证书全是通配符，probe 系列就会是空的，
> 这是设计如此，不代表探测坏了。

---

## 6. 怎么证明凭证真的走的是角色，而不是某个遗留的静态密钥

按"证据强度"从弱到强排。前三条是**排除法**，第 4、5 条才是**直接证据**。

### 6.1 排除：配置里没有静态密钥

```bash
sudo grep -nE 'credentialMode|roleName|secretId|secretKey' /etc/wecert/config.yaml
# expect: credentialMode: cvm-role
#         roleName: wecert-test-role
#         没有 secretId / secretKey（被注释掉的不算，没被注释的才算）
```

### 6.2 排除：unit 里没有环境变量

```bash
grep -RniE '^\s*Environment(File)?=' /etc/systemd/system/wecert*.service
# expect: 无输出
```

`install.sh` 把 `deploy/systemd/` 下的 unit **原样**装成 `0644 root:root`，而仓库里那三个 unit
一条 `Environment=` 都没有。`credentials.go` 的注释解释了为什么不要往里加：
unit 是 `0644`，一条内联的 `Environment=` 会让长期 CAM 密钥变成**任何本地用户可读**；
要放就放 `0600 root:wecert` 的 `EnvironmentFile`。

### 6.3 排除：进程环境里没有密钥

```bash
pid="$(systemctl show -p MainPID --value wecert)"
sudo cat "/proc/${pid}/environ" | tr '\0' '\n' | grep -c TENCENTCLOUD || true
# expect: 0
# 注意不能用 `sudo tr ... < /proc/${pid}/environ`：重定向由当前 shell（普通用户）执行，
# 而 /proc/<pid>/environ 只有进程属主和 root 能读，会直接 Permission denied。
```

**对照实验（关键）**：`cvm-role` 模式下，环境变量**根本不会被读**。想亲眼看到这一点：

```bash
sudo systemctl set-environment TENCENTCLOUD_SECRET_ID=AKIDdeliberately-wrong
sudo systemctl set-environment TENCENTCLOUD_SECRET_KEY=deliberately-wrong
sudo systemctl restart wecert
# 然后强制一次续期（第 5 节第 7 步），预期：续期照常成功，日志里不出现任何 AuthFailure。
# 反过来，把配置改成 credentialMode: static 再重启，同样的错密钥会立刻换来
# AuthFailure / UnauthorizedOperation。
sudo systemctl unset-environment TENCENTCLOUD_SECRET_ID TENCENTCLOUD_SECRET_KEY
```

这条对照的说服力在于：**同一组错密钥，在 `cvm-role` 下无事发生、在 `static` 下必然失败** ——
说明生效的确实是模式选择，而不是"环境里恰好有一份能用的密钥"。

### 6.4 直接证据：在 CVM 上手工读一次元数据

```bash
# 用 terraform output cvm_cam_role 的值替换角色名
curl -s -o /tmp/cam.json -w 'http=%{http_code}\n' \
  "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/wecert-test-role"
python3 -c 'import json;d=json.load(open("/tmp/cam.json"));print({k:(v if k=="ExpiredTime" else "<redacted>") for k,v in d.items()})'
```

预期是 `http=200`，body 是 `TmpSecretId` / `TmpSecretKey` / `Token` / `ExpiredTime` / `Code` 的 JSON
（字段名就是 `internal/deploy/credentials.go` 里 `cvmRoleCredential` 的那些）。
其中 `TmpSecretId` 与 `TmpSecretKey` 任一为空，代码就报
`the metadata service returned no usable credentials (Code=%q)`。

> ⚠️ 这条命令会把一份**可用的临时凭证**打印到你的终端。它有时效（`ExpiredTime`），但仍然不要
> 粘进工单、聊天记录或 CI 日志。上面的 `python3 -c` 就是为了只在屏幕上留 `ExpiredTime`。

### 6.5 直接证据（反证）：指向一个不存在的角色名

这是最强的一条 —— 把角色名改错，看它是不是**恰好**以元数据错误失败：

```bash
sudo sed -i 's/^\(\s*roleName:\).*/\1 wecert-role-that-does-not-exist/' /etc/wecert/config.yaml
sudo systemctl restart wecert
journalctl -u wecert -n 50 --no-pager | grep -i 'metadata service'
# expect（消息骨架出自 fetchCVMRoleCredential，角色名以 %q 引用）：
#   the metadata service returned <状态码>; check that this CVM has role "wecert-role-that-does-not-exist" attached (response: ...)
#   <状态码> 预期是 404，但这是服务端行为，跑之前确认；代码只负责把它原样打出来。

# 再改回来
sudo sed -i 's/^\(\s*roleName:\).*/\1 wecert-test-role/' /etc/wecert/config.yaml
sudo systemctl restart wecert
```

如果改错角色名之后**依然一切正常**，那说明生效的不是角色路径 —— 这比任何"我看过配置了"都更有力。

---

## 7. 四个值得认识的失败签名

### 7.1 状态目录权限陷阱（两个方向，长得完全不一样）

**方向一：目录不存在 / 建不动** —— `internal/state/state.go` 的
`create state dir %s: %w`：

```
create state dir /var/lib/wecert: permission denied
```

意思是：进程（`wecert` 用户）发现 `/var/lib/wecert` 不存在，试图按 `0700` 建，没有权限。
正常安装不会走到这里（`install.sh` 已经 `install -d -o wecert -g wecert -m 0700`）；
出现它基本等于"你换了 `statePath` 但没建目录"。
修：

```bash
sudo install -d -o wecert -g wecert -m 0700 /var/lib/wecert
```

> **把 `statePath` 指到别处要额外小心**：unit 里是 `StateDirectory=wecert` + `ProtectSystem=strict`，
> 只有 `/var/lib/wecert`（以及 systemd 放行的少数路径）可写。换成别的前缀时，`mkdir` 更可能报
> `read-only file system` 而不是 `permission denied` —— **跑之前确认**这类错误到底长什么样，
> 别只按 `permission denied` 去搜。

**方向二：目录对，但里面的文件是 root 的** —— `pre-create state file %s: %w`：

```
pre-create state file /var/lib/wecert/state.db: permission denied
```

这是**最坑的一个**，`install.sh` 用一整段注释记录过它：你用 `sudo`（而不是 `sudo -u wecert`）
跑了一次 `-dry-run`，就在 `/var/lib/wecert/` 里留下 `root:root 0600` 的 `state.db`。
`StateDirectory=wecert` 只保证**目录**的属主，**不会**去改已经存在的文件；于是服务每次都死在
pre-create，systemd 按 `Restart=on-failure` / `RestartSec=30s` 每 30 秒重试一次，
`systemctl status` 只看到反复重启，报错完全不提"权限"以外的线索。修：

```bash
sudo systemctl stop wecert
sudo ls -la /var/lib/wecert/            # 先确认里面没有你还需要的东西
sudo rm -f /var/lib/wecert/state.db /var/lib/wecert/state.db-wal /var/lib/wecert/state.db-shm
sudo -u wecert /usr/local/bin/wecert -config /etc/wecert/config.yaml -dry-run
sudo systemctl start wecert
```

> ⚠️ 删 `state.db` 的代价见 [`docs/recovery.md`](recovery.md)：ACME 账号私钥和在途订单 URL 都在里面，
> 丢了就会重新注册账号 + 重新下单，撞的正是那条"不可恢复、只能等"的限额。确认是刚装的空库再删。

> **跑之前确认**：上面两条字符串来自 `internal/state/state.go` 的 `fmt.Errorf` 原文，但错误链上还套着
> `*os.PathError`，实际输出会是 `... : open /var/lib/wecert/state.db: permission denied` 这种拼接形式。
> 以 "pre-create state file" / "create state dir" 这两个前缀做定位，不要逐字比对整行。

### 7.2 第二个进程启动时被 flock 拒绝

```
the state database is already held by another wecert process (lock file: /var/lib/wecert/state.db.lock)
```

- 字符串：`internal/state/state.go` 的 `ErrLocked` + `internal/state/lock_unix.go` 的 `(lock file: %s)`。
- 触发：daemon 与 timer 同时启用；或 daemon 在跑时手工 `-once`；或（更常见）**上一次没停干净**。
- systemd 下的表现：`wecert.service` 每 30 秒重启一次；`wecert-once.service` 单次失败后停在那里。
- 诊断：

```bash
systemctl is-enabled wecert wecert-once.timer    # 两个都 enabled 就是配置错了
systemctl list-units 'wecert*' --all
pgrep -a wecert
```

- **别被 `-dry-run` 骗了**：`-dry-run` 刻意豁免锁（`state.OpenUnlocked`），它能在 daemon 正在跑的时候
  成功。所以"dry-run 通过了"**不能**用来证明"没有第二个实例"。
- 锁是内核 `flock`，`kill -9` 立即释放，没有残留 PID 文件要清。

### 7.3 `wecert_certificate_deployed` 一直是 0：没人绑定证书

含义很明确：`deploy_confirmed` 为 false —— 证书**上传了，但没有任何云资源绑着它**。
对应日志是第 5 节第 5 步那条 `certificate uploaded; waiting for a one-time manual bind in the CLB console`。

修：把 `uploadedCertId` 那张证书**绑到 CLB listener 上**。两个必须知道的点：

1. **SNI listener 必须走 `multi_cert_info`。** `README.reference.md` 与 `testenv/clb.tf` 都记录了：
   `sni_switch = true` 时服务端**静默忽略**主 `certificate_id`，只认 `multi_cert_info`。
   `internal/deploy/tencent.go` 的 `noResourceBoundError` 把这个判断写进了错误文本：
   *"an SNI listener must use multi_cert_info; the primary certificate_id is silently ignored"*。
2. 绑定后**不用重启**：每个 pass 都会做一次**只读**的绑定检查
   （`CreateCertificateBindResourceSyncTask`，带缓存），确认后打
   `confirmed the certificate is bound to cloud resources ... resources=N`，指标变 1。
   没有这一步，手工绑的证书要等到下一次续期（classic 最长 90 天）才会变绿 —— 那期间的 0 是假警报。

**和"部署真的失败"怎么区分**：

| | 只是没绑 | 部署真失败 |
|---|---|---|
| 日志 | `certificate uploaded; waiting for a one-time manual bind` | `UpdateCertificateInstance: ...` 之类的错误 |
| `wecert_certificate_deployed` | 0 | 0 |
| `wecert_certificate_consecutive_failures` | **0** | **> 0** |
| 账号侧 | 账号里有一张多出来的 `wecert/...` 证书 | 可能一张都没有（上传就失败了）|

### 7.4 指标端口被占用

`startMetricsServer` 是**同步绑定、失败即退出**（这是故意的：`/metrics` 是唯一的过期告警路径，
静默死掉的端点意味着证书过期没人知道）。原文：

```
failed to listen on the metrics port 127.0.0.1:9800: listen tcp 127.0.0.1:9800: bind: address already in use (already in use? only one wecert instance should run per machine; do not enable both the daemon and the timer)
```

- 触发：另一个 wecert（daemon + `-once` 也算了，因为 `-once` 同样会绑端口）或任何占了 9800 的进程。
- 诊断：`sudo ss -ltnp | grep 9800`；再对照 7.2（如果第二个进程也是 wecert 且共用 `statePath`，
  **`flock` 通常先报**，因为 `state.Open` 在 `startMetricsServer` 之前）。
- systemd 下的表现：unit `failed`，daemon 每 30 秒重试一次。

---

## 8. 什么情况下 Stage C 其实没成功

服务 `active (running)` 是**最弱的**证据。下面任何一条成立，就说明这次没真的验证成功，别记 PASS：

| 观察 | 为什么这不算成功 |
|---|---|
| `systemctl is-active wecert` = active，但 `wecert_last_reconcile_timestamp_seconds` 一直是 0 | 进程活着，但一轮都没跑完。"起来了"和"在收敛"是两件事 |
| 日志里只有 `certificate uploaded; waiting for a one-time manual bind`，没有 `confirmed the certificate is bound` | 只证明了上传，没证明绑定。Stage C 的核心断言（自动重绑）根本没被触达 |
| `deployed_cert_id`（状态库）与实际 listener 上的 CertId 不一致 | 用仓库自带的 `bin/wecert-clbverify`（`make tools`）`-region ... -clb ... -listener ... -raw` 独立读一次；"程序以为自己成功了"正是本项目最想抓的那类失效 |
| `wecert_certificate_deployed{cert}` = 1，但从 CLB VIP 拨 443 拿到的还是旧证书/占位证书 | 控制面说绑好了、边缘没换。`wecert_certificate_probe_match{host}` 应该是 0 —— 这正是 probe 存在的理由 |
| journal 里出现 `AuthFailure` / `UnauthorizedOperation` / `the metadata service returned ...` | 角色路径没走通；此时即使证书签发成功，也只是"DNS 侧恰好用的是别处的凭据" |
| `wecert_certificate_consecutive_failures{cert}` > 0 | 有东西在持续失败，只是还没到告警阈值 |
| `wecert_reconcile_panics_total{cert}` > 0 | 有一轮是靠 recover 才活下来的，属于 bug |
| 这次只跑了 `-dry-run`，没有任何 `notAfter` | `-dry-run` 不签发、不部署、不取角色凭证（第 4 节）。它绿了等于"配置没写错" |
| 证书是在 staging 目录签的，却当成生产能力记录 | staging 证书不受信任。这一条不影响"链路跑通"的结论，但发布记录里必须写清楚 |

**反过来，一次可信的 Stage C 记录至少要能同时给出**：

1. `terraform output cvm_cam_role` = 角色名（非空）；
2. `journalctl` 里第 5 节第 5→6→8 步三条日志**都在**，时间顺序正确；
3. `curl -s localhost:9800/metrics` 里 `wecert_certificate_deployed{cert}` = 1，且
   `wecert_last_reconcile_timestamp_seconds` 在推进；
4. `bin/wecert-clbverify` 独立读出的 CertId 与日志里的 `deployedCertId` 一致；
5. 第 6.5 节那条反证做过一次（改错角色名 → 报元数据错误 → 改回来）。

---

## 附：命令速查

```bash
# 2. 建 CVM（先建好 CAM 角色再 apply）
cd testenv
terraform plan  -input=false -out=tfplan -var create_cvm=true -var enable_cvm_role=true -var cam_role_name=wecert-test-role
terraform output available_zones
terraform apply -input=false tfplan
terraform output cvm_instance_id cvm_public_ip cvm_cam_role clb_id listener_id clb_vip

# 3. 构建 + 安装（在 CVM 上）
make release
sudo ./install.sh ./wecert_linux_amd64

# 4. 校验（必须是 wecert 用户，不是 root）
sudo -u wecert /usr/local/bin/wecert -config /etc/wecert/config.yaml -dry-run

# 5. 启动 + 观察
sudo systemctl enable --now wecert
journalctl -u wecert -f
curl -s localhost:9800/metrics | grep wecert_certificate_deployed
curl -s localhost:9800/metrics | grep wecert_last_reconcile_timestamp_seconds

# 6. 凭证取证
sudo grep -nE 'credentialMode|roleName' /etc/wecert/config.yaml
grep -RniE '^\s*Environment(File)?=' /etc/systemd/system/wecert*.service
curl -s -o /dev/null -w '%{http_code}\n' http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/wecert-test-role

# 收尾（下面两条都在仓库根目录执行）
(cd testenv && terraform destroy)
./bin/wecert-preflight -list-certs        # 需要 CAM 凭据；手工删 Alias 以 wecert/ 开头的测试证书
```

---

## 变更记录

| 日期 | 变更 |
|---|---|
| 2026-09-17 | 首版。**未跑**：本机无腾讯云凭据，无法执行；每条"预期"都标注了源码出处 |
| 2026-09-18 | 顶部横幅按实跑更正：Stage C 已在 2026-09-17（[§4.5、§4.9](e2e-run-2026-09-17-credentialed.md)）与 2026-09-18（[§4.7](e2e-run-2026-09-18-credentialed.md)）两轮真机运行中执行，不再是"未跑"，仍未覆盖的是 §6.5 的反证与跨续期窗口的临时凭证。第 1 节与 §4.2 的 `-dry-run` 说明按第 11 轮修复后的 `cmd/wecert/main.go` 更正（dry-run 现在会构建 DNS provider 与 deployer，但角色凭证仍推迟到首次使用，所以"绿 ≠ 角色可用"的结论不变） |
