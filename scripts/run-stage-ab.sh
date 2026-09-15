#!/usr/bin/env bash
#
# 阶段 A + B 端到端编排
#
#   ./scripts/run-stage-ab.sh <域名> <邮箱> [--skip-apply]
#
# 例：
#   ./scripts/run-stage-ab.sh example.com ops@example.com
#
# 做四件事：
#   1. terraform apply —— 建 VPC + CLB + HTTPS 监听器 + 占位证书
#   2. 生成 staging 配置，注册 ACME 账号
#   3. 把占位证书的 CertId 预置进 wecert 状态库（模拟"证书已绑在监听器上"）
#   4. 跑 wecert —— 签发 wildcard 证书，并触发 UpdateCertificateInstance 重绑定
#
# 最后用 wecert-clbverify 从腾讯云侧独立取证，确认监听器的 CertId 真的变了。
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"
shift 2 2>/dev/null || true

# 默认只做 plan。创建真实云资源必须显式加 --yes —— 这类脚本
# 不应该存在"不小心跑一下就产生费用"的可能。
CONFIRM=""
SKIP_APPLY=""
for arg in "$@"; do
	case "${arg}" in
	--yes) CONFIRM="--yes" ;;
	--skip-apply) SKIP_APPLY="--skip-apply" ;;
	*)
		echo "未知参数: ${arg}" >&2
		exit 1
		;;
	esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTENV="${ROOT}/testenv"
STATE_DIR="/tmp/wecert-e2e"
STATE_DB="${STATE_DIR}/state.db"
CONFIG="${STATE_DIR}/config.yaml"
CREDS="${WECERT_CREDS:-/Users/atom/Documents/dsh/.secrets/tencent.env}"

if [[ -z "${DOMAIN}" || -z "${EMAIL}" ]]; then
	echo "用法: $0 <域名> <邮箱> [--yes] [--skip-apply]" >&2
	echo "例:   $0 example.com ops@example.com --yes" >&2
	echo >&2
	echo "不带 --yes 时只生成 terraform plan 并停下，不会创建任何资源。" >&2
	exit 1
fi

# ── 前置检查 ────────────────────────────────────────────────────────────────

if [[ ! -f "${CREDS}" ]]; then
	echo "错误: 找不到凭证文件 ${CREDS}" >&2
	echo "      格式应为：export TENCENTCLOUD_SECRET_ID=... / export TENCENTCLOUD_SECRET_KEY=..." >&2
	exit 1
fi

# 只提取需要的两个变量，不整个 source 进来。
#
# 凭证文件里往往还躺着别的密钥（GitHub token、PyPI token 之类），
# source 会把它们一并塞进当前 shell 并被子进程继承 ——
# terraform 和 wecert 完全不需要这些，没有理由让它们拿到。
eval "$(grep -E '^[[:space:]]*(export[[:space:]]+)?(TENCENTCLOUD_SECRET_ID|TENCENTCLOUD_SECRET_KEY)=' "${CREDS}")"
export TENCENTCLOUD_SECRET_ID TENCENTCLOUD_SECRET_KEY

if [[ -z "${TENCENTCLOUD_SECRET_ID:-}" || -z "${TENCENTCLOUD_SECRET_KEY:-}" ]]; then
	echo "错误: ${CREDS} 里没有设置 TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY" >&2
	exit 1
fi
echo "凭证: 已加载（${TENCENTCLOUD_SECRET_ID:0:8}...）"

for bin in terraform sqlite3; do
	command -v "${bin}" >/dev/null 2>&1 || { echo "错误: 缺少 ${bin}" >&2; exit 1; }
done

[[ -x "${ROOT}/bin/wecert" ]] || { echo "错误: 先 make build" >&2; exit 1; }
[[ -x "${ROOT}/bin/wecert-clbverify" ]] || { echo "错误: 先构建辅助工具: make tools" >&2; exit 1; }

export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-/Users/atom/Documents/dsh/.terraform-plugin-cache}"
export TF_IN_AUTOMATION=1

echo "域名: ${DOMAIN} + *.${DOMAIN}"
echo "邮箱: ${EMAIL}"
echo

# ── 1. 建云资源 ─────────────────────────────────────────────────────────────

if [[ "${SKIP_APPLY}" != "--skip-apply" ]]; then
	echo "=== [1/4] terraform plan ==="
	(
		cd "${TESTENV}"
		terraform init -input=false >/dev/null
		terraform plan -input=false -out=tfplan
	)

	if [[ "${CONFIRM}" != "--yes" ]]; then
		cat <<'EOF'

⚠️  以上计划尚未执行。这一步会创建真实的腾讯云资源并产生费用
    （VPC / 内网 CLB / HTTPS 监听器 / 占位证书，共 7 个资源）。

    确认无误后加 --yes 重新运行即可执行：

        ./scripts/run-stage-ab.sh <域名> <邮箱> --yes

EOF
		exit 0
	fi

	echo
	echo "=== terraform apply ==="
	(cd "${TESTENV}" && terraform apply -input=false tfplan)
	rm -f "${TESTENV}/tfplan"
	echo
else
	echo "=== [1/4] 跳过 terraform apply ==="
fi

cd "${TESTENV}"
REGION="$(terraform output -raw region)"
CLB_ID="$(terraform output -raw clb_id)"
LISTENER_ID="$(terraform output -raw listener_id)"
PLACEHOLDER_ID="$(terraform output -raw placeholder_cert_id)"

echo "CLB       : ${CLB_ID}"
echo "监听器     : ${LISTENER_ID}"
echo "占位证书   : ${PLACEHOLDER_ID}"
echo

echo "--- 重绑定前的状态 ---"
"${ROOT}/bin/wecert-clbverify" -region "${REGION}" -clb "${CLB_ID}" -listener "${LISTENER_ID}" \
	-expect "${PLACEHOLDER_ID}"
echo

# ── 2. 生成配置并初始化 ─────────────────────────────────────────────────────

echo "=== [2/4] 生成配置并注册 ACME 账号 ==="
mkdir -p "${STATE_DIR}"
rm -f "${STATE_DB}" "${STATE_DB}-wal" "${STATE_DB}-shm"

sed -e "s|REPLACE_ME|${DOMAIN}|g" \
	-e "s|^  email: .*|  email: ${EMAIL}|" \
	"${ROOT}/e2e-config-wildcard.yaml" > "${CONFIG}"

# 强制 staging：打错一个字符就会消耗真实生产配额。
grep -q 'acme-staging' "${CONFIG}" || { echo "错误: 配置不是 staging" >&2; exit 1; }

"${ROOT}/bin/wecert" -config "${CONFIG}" -state "${STATE_DB}" -dry-run
echo

# ── 3. 预置"证书已绑定"状态 ─────────────────────────────────────────────────

echo "=== [3/4] 预置 deployed_cert_id = 占位证书 ==="
# 模拟"wecert 管的证书当前正绑在监听器上"。
# 这样首次签发走到部署阶段时，oldID 不为空，
# 就会真正触发 UpdateCertificateInstance 这条路。
sqlite3 "${STATE_DB}" \
	"INSERT INTO certificates (name, deployed_cert_id) VALUES ('wildcard-test', '${PLACEHOLDER_ID}')
	 ON CONFLICT(name) DO UPDATE SET deployed_cert_id='${PLACEHOLDER_ID}';"
sqlite3 "${STATE_DB}" "SELECT name, deployed_cert_id FROM certificates;"
echo

# ── 4. 签发 + 重绑定 ────────────────────────────────────────────────────────

echo "=== [4/4] 签发 wildcard 证书并触发重绑定 ==="
"${ROOT}/bin/wecert" -config "${CONFIG}" -state "${STATE_DB}" -once

NEW_CERT_ID="$(sqlite3 "${STATE_DB}" "SELECT deployed_cert_id FROM certificates WHERE name='wildcard-test';")"
echo
echo "新证书 CertId: ${NEW_CERT_ID}"

if [[ "${NEW_CERT_ID}" == "${PLACEHOLDER_ID}" || -z "${NEW_CERT_ID}" ]]; then
	echo "错误: 证书没有被上传（deployed_cert_id 未变化）" >&2
	exit 1
fi

# ── 独立取证 ────────────────────────────────────────────────────────────────

echo
echo "=== 从腾讯云侧独立验证重绑定 ==="
"${ROOT}/bin/wecert-clbverify" -region "${REGION}" -clb "${CLB_ID}" -listener "${LISTENER_ID}" \
	-expect "${NEW_CERT_ID}" \
	-not-expect "${PLACEHOLDER_ID}"

echo
echo "=== 校验 ARI（决定能否豁免速率限制）==="
ARI="$(sqlite3 "${STATE_DB}" "SELECT ari_cert_id FROM certificates WHERE name='wildcard-test';")"
if [[ -z "${ARI}" ]]; then
	echo "⚠️  ARI certID 为空 —— 续期将无法享受速率豁免" >&2
else
	echo "ARI certID: ${ARI}"
fi

echo
echo "=== 幂等性：再跑一轮不应产生新订单 ==="
"${ROOT}/bin/wecert" -config "${CONFIG}" -state "${STATE_DB}" -once
ORDERS="$(sqlite3 "${STATE_DB}" "SELECT count(*) FROM orders;")"
echo "残留订单数: ${ORDERS}（应为 0）"
[[ "${ORDERS}" == "0" ]] || { echo "错误: 幂等性被破坏" >&2; exit 1; }

cat <<EOF

==============================================
 ✅ 阶段 A + B 全部通过

 验证结论：
   - wildcard + apex 共用同一 TXT 名字的路径正常
   - 权威 NS 传播等待正常
   - 证书成功上传到腾讯云 SSL 证书服务
   - UpdateCertificateInstance 成功重绑定了 CLB 监听器
   - 幂等性正常（未到窗口不产生新订单）

 ⚠️  记得清理：
     cd ${TESTENV} && terraform destroy
     以及 wecert 上传的测试证书（Alias 以 wecert/ 开头的那张）
==============================================
EOF
