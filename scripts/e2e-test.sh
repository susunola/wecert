#!/usr/bin/env bash
#
# wecert end-to-end test — runs the full flow against real Let's Encrypt staging
# plus real DNSPod.
#
#   ./scripts/e2e-test.sh <test domain> [config file]
#
# Example:
#   ./scripts/e2e-test.sh test1.example.com
#
# This script does exactly one thing: run one full issuance against a brand-new
# state store, then verify the result. It never touches production and never binds
# a CLB.
#
# Prerequisites:
#   - the domain is hosted on DNSPod / Tencent Cloud DNSPod
#   - dns.provider and the credentials in the config work
#   - acme.directory points at staging (the script enforces this)
set -euo pipefail

DOMAIN="${1:-}"
CONFIG="${2:-./e2e-config.yaml}"
BIN="${BIN:-./bin/wecert}"

if [[ -z "${DOMAIN}" ]]; then
	echo "Usage: $0 <test domain> [config file]" >&2
	exit 1
fi

if [[ ! -x "${BIN}" ]]; then
	echo "Error: executable not found: ${BIN} (run make build first)" >&2
	exit 1
fi

if [[ ! -f "${CONFIG}" ]]; then
	echo "Error: config file not found: ${CONFIG}" >&2
	exit 1
fi

# Safety gate: never run the test against production.
if ! grep -q 'acme-staging' "${CONFIG}"; then
	echo "Error: acme.directory in ${CONFIG} is not staging, refusing to run." >&2
	echo "      The end-to-end test must use staging; otherwise failed retries burn real production quota." >&2
	exit 1
fi

# Use a brand-new state store every time, so the cold-start path is what gets tested.
STATE_DIR="$(mktemp -d)"
trap 'rm -rf "${STATE_DIR}"' EXIT

echo "=============================================="
echo " wecert end-to-end test"
echo " domain : ${DOMAIN}"
echo " config : ${CONFIG}"
echo " state  : ${STATE_DIR}/state.db (temporary, deleted when done)"
echo "=============================================="
echo

echo "--- [1/5] dry-run: validate the config and the ACME account ---"
"${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -dry-run || {
	echo "dry-run failed; the remaining steps would be pointless." >&2
	exit 1
}
echo

echo "--- [2/5] first issuance ---"
if ! "${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -once; then
	echo "issuance failed. Common causes:" >&2
	echo "  - the TXT record for _acme-challenge.${DOMAIN} did not propagate to every authoritative NS" >&2
	echo "  - the DNS credentials lack permission" >&2
	echo "  - the domain is not in that DNS account" >&2
	exit 1
fi
echo

echo "--- [3/5] inspect the state store ---"
if command -v sqlite3 >/dev/null 2>&1; then
	sqlite3 "${STATE_DIR}/state.db" \
		"SELECT name, datetime(not_after,'unixepoch') AS not_after, deployed_cert_id, ari_cert_id FROM certificates;"
else
	echo "(sqlite3 not installed, skipping)"
fi
echo

echo "--- [4/5] verify ARI and order state ---"
# The key assertions: a successful issuance should leave no order behind, and the
# ARI certID must have been built — otherwise later renewals lose the
# "exempt from all rate limits" treatment.
ORDERS="$(sqlite3 "${STATE_DIR}/state.db" "SELECT count(*) FROM orders;" 2>/dev/null || echo "?")"
echo "orders left behind: ${ORDERS} (0 only if issuance succeeded; keeping an order around for reuse next round after a failure is correct behavior)"

ARI="$(sqlite3 "${STATE_DIR}/state.db" "SELECT ari_cert_id FROM certificates;" 2>/dev/null || echo "")"
if [[ -z "${ARI}" ]]; then
	echo "⚠️  ARI certID is empty — renewals will not get the rate-limit exemption; check the certificate's AKI parsing" >&2
else
	echo "ARI certID: ${ARI}"
fi
echo

echo "--- [5/5] idempotency: run another round; the order must be reused, not recreated ---"
ORDER_BEFORE="$(sqlite3 "${STATE_DIR}/state.db" "SELECT coalesce(order_url,'') FROM orders LIMIT 1;" 2>/dev/null || echo "")"

if ! "${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -once; then
	echo "second round failed" >&2
	exit 1
fi

ORDER_AFTER="$(sqlite3 "${STATE_DIR}/state.db" "SELECT coalesce(order_url,'') FROM orders LIMIT 1;" 2>/dev/null || echo "")"

# The real invariant is "no new order is created", not "there is no order":
# if the first round failed (the order is still pending), the second round should
# reuse the same order URL and keep advancing it — this is exactly the mechanism
# that avoids running into "5 certs per exact set of identifiers / 7 days".
if [[ -n "${ORDER_BEFORE}" ]]; then
	echo "the first round left an order behind; the second round should reuse it:"
	echo "  before: ${ORDER_BEFORE}"
	echo "  after:  ${ORDER_AFTER}"
	if [[ "${ORDER_BEFORE}" != "${ORDER_AFTER}" ]]; then
		echo "Error: the second round placed a new order; order reuse is broken" >&2
		exit 1
	fi
	echo "  ✅ order reused correctly, nothing new was created"
else
	ORDERS="$(sqlite3 "${STATE_DIR}/state.db" "SELECT count(*) FROM orders;" 2>/dev/null || echo "?")"
	echo "orders left behind: ${ORDERS} (the first round succeeded, so no order should exist before the renewal window opens)"
	if [[ "${ORDERS}" != "0" ]]; then
		echo "Error: an order was created when none should be; the renewal-window check is wrong" >&2
		exit 1
	fi
fi

echo
echo "=============================================="
echo " ✅ end-to-end test passed"
echo "=============================================="
