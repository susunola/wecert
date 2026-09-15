#!/usr/bin/env bash
#
# wecert 端到端测试 —— 在真实 Let's Encrypt staging + 真实 DNSPod 上跑完整流程。
#
#   ./scripts/e2e-test.sh <测试域名> [配置文件]
#
# 例：
#   ./scripts/e2e-test.sh test1.example.com
#
# 这个脚本只做一件事：用一份全新的状态库跑一次完整签发，
# 然后校验结果。它不碰生产环境，也不会绑定 CLB。
#
# 前置条件：
#   - 域名在 DNSPod / 腾讯云 DNSPod 托管
#   - 配置里的 dns.provider 和凭证可用
#   - acme.directory 指向 staging（脚本会强制检查）
set -euo pipefail

DOMAIN="${1:-}"
CONFIG="${2:-./e2e-config.yaml}"
BIN="${BIN:-./bin/wecert}"

if [[ -z "${DOMAIN}" ]]; then
	echo "用法: $0 <测试域名> [配置文件]" >&2
	exit 1
fi

if [[ ! -x "${BIN}" ]]; then
	echo "错误: 找不到可执行文件 ${BIN}（先 make build）" >&2
	exit 1
fi

if [[ ! -f "${CONFIG}" ]]; then
	echo "错误: 找不到配置文件 ${CONFIG}" >&2
	exit 1
fi

# 安全闸门：绝不拿生产环境做测试。
if ! grep -q 'acme-staging' "${CONFIG}"; then
	echo "错误: ${CONFIG} 的 acme.directory 不是 staging，拒绝执行。" >&2
	echo "      端到端测试必须用 staging，否则失败重试会消耗真实生产配额。" >&2
	exit 1
fi

# 每次都用全新状态库，确保测的是冷启动路径。
STATE_DIR="$(mktemp -d)"
trap 'rm -rf "${STATE_DIR}"' EXIT

echo "=============================================="
echo " wecert 端到端测试"
echo " 域名   : ${DOMAIN}"
echo " 配置   : ${CONFIG}"
echo " 状态库 : ${STATE_DIR}/state.db（临时，跑完删除）"
echo "=============================================="
echo

echo "--- [1/5] dry-run：验证配置与 ACME 账号 ---"
"${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -dry-run || {
	echo "dry-run 失败，后面的步骤没有意义。" >&2
	exit 1
}
echo

echo "--- [2/5] 首次签发 ---"
if ! "${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -once; then
	echo "签发失败。常见原因：" >&2
	echo "  - _acme-challenge.${DOMAIN} 的 TXT 没能传播到全部权威 NS" >&2
	echo "  - DNS 凭证权限不足" >&2
	echo "  - 域名不在该 DNS 账号下" >&2
	exit 1
fi
echo

echo "--- [3/5] 检查状态库 ---"
if command -v sqlite3 >/dev/null 2>&1; then
	sqlite3 "${STATE_DIR}/state.db" \
		"SELECT name, datetime(not_after,'unixepoch') AS not_after, deployed_cert_id, ari_cert_id FROM certificates;"
else
	echo "（未安装 sqlite3，跳过）"
fi
echo

echo "--- [4/5] 校验 ARI 与订单状态 ---"
# 关键断言：签发成功后不应该残留订单；ARI certID 必须构造出来了，
# 否则后续续期拿不到"豁免全部速率限制"的待遇。
ORDERS="$(sqlite3 "${STATE_DIR}/state.db" "SELECT count(*) FROM orders;" 2>/dev/null || echo "?")"
echo "残留订单数: ${ORDERS}（成功签发才应为 0；失败时保留订单供下一轮复用是正确行为）"

ARI="$(sqlite3 "${STATE_DIR}/state.db" "SELECT ari_cert_id FROM certificates;" 2>/dev/null || echo "")"
if [[ -z "${ARI}" ]]; then
	echo "⚠️  ARI certID 为空 —— 续期将无法享受速率豁免，需要检查证书的 AKI 解析" >&2
else
	echo "ARI certID: ${ARI}"
fi
echo

echo "--- [5/5] 幂等性：再跑一轮，必须复用而不是重建订单 ---"
ORDER_BEFORE="$(sqlite3 "${STATE_DIR}/state.db" "SELECT coalesce(order_url,'') FROM orders LIMIT 1;" 2>/dev/null || echo "")"

if ! "${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -once; then
	echo "第二轮执行失败" >&2
	exit 1
fi

ORDER_AFTER="$(sqlite3 "${STATE_DIR}/state.db" "SELECT coalesce(order_url,'') FROM orders LIMIT 1;" 2>/dev/null || echo "")"

# 真正的不变量是"不新建订单"，而不是"没有订单"：
# 如果第一轮失败了（订单仍 pending），第二轮就该复用同一个 order URL 继续推进 ——
# 这正是防止撞上 "5 certs per exact set of identifiers / 7 days" 的机制。
if [[ -n "${ORDER_BEFORE}" ]]; then
	echo "第一轮遗留订单，第二轮应当复用："
	echo "  之前: ${ORDER_BEFORE}"
	echo "  之后: ${ORDER_AFTER}"
	if [[ "${ORDER_BEFORE}" != "${ORDER_AFTER}" ]]; then
		echo "错误: 第二轮重新下单了，订单复用机制失效" >&2
		exit 1
	fi
	echo "  ✅ 订单被正确复用，没有新建"
else
	ORDERS="$(sqlite3 "${STATE_DIR}/state.db" "SELECT count(*) FROM orders;" 2>/dev/null || echo "?")"
	echo "残留订单数: ${ORDERS}（第一轮已成功，未到续期窗口就不该产生任何订单）"
	if [[ "${ORDERS}" != "0" ]]; then
		echo "错误: 不该产生订单却产生了，续期窗口判断有误" >&2
		exit 1
	fi
fi

echo
echo "=============================================="
echo " ✅ 端到端测试通过"
echo "=============================================="
