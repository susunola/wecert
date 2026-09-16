#!/usr/bin/env bash
#
# wecert end-to-end test — the wildcard + apex interaction against real DNS and real
# Let's Encrypt staging.
#
#   ./scripts/e2e-wildcard.sh <apex domain> [config file]
#
# Example:
#   ./scripts/e2e-wildcard.sh test1.example.com e2e-config-wildcard.yaml
#
# Why this exists separately from e2e-test.sh: the single-domain run cannot test the one
# thing that makes DNS-01 hard. A wildcard authorization carries the BARE identifier
# (RFC 8555 §7.1.3), so `<apex>` and `*.<apex>` are two authorizations that resolve to the
# SAME challenge name while carrying DIFFERENT tokens -- hence two different TXT values
# that must be present at the same time. An implementation that writes, validates and
# deletes one authorization at a time cannot pass: the second write lands on the name the
# first one just cleared.
#
# The unit suite covers the ordering with an injected resolver. This script is the only
# thing that observes the real thing: two TXT values coexisting on a real authoritative
# nameserver, and none left behind afterwards.
#
# Prerequisites:
#   - the apex is hosted on DNSPod / Tencent Cloud DNSPod, in the account the config uses
#   - dns.provider and the credentials in the config work
#   - acme.directory points at staging (enforced below)
#   - dig (BIND utils), sqlite3
#
# It never touches production and never binds a CLB.
set -euo pipefail

DOMAIN="${1:-}"
CONFIG="${2:-./e2e-config-wildcard.yaml}"
BIN="${BIN:-./bin/wecert}"
# The resolver command. Overridable only so the sampling and coalescing logic can be tested
# against canned responses; production runs use dig.
DIG="${DIG:-dig}"
# How long to sample the challenge name while issuance runs. Must comfortably exceed the
# configured dns.propagationTimeout, or the one property this script exists to observe can
# be missed entirely.
SAMPLE_SECONDS="${SAMPLE_SECONDS:-600}"
# How often to sample.
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-2}"

if ! command -v "${DIG}" >/dev/null 2>&1; then
	echo "Error: ${DIG} is required (dig / BIND utils)." >&2
	exit 1
fi
if ! command -v sqlite3 >/dev/null 2>&1; then
	echo "Error: sqlite3 is required." >&2
	exit 1
fi

if [[ -z "${DOMAIN}" ]]; then
	echo "Usage: $0 <apex domain> [config file]" >&2
	echo "  e.g. $0 test1.example.com e2e-config-wildcard.yaml" >&2
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

# Safety gate, same as e2e-test.sh: anchored to the directory key, because a bare
# "acme-staging" anywhere in the file -- a comment, say -- would pass while the real
# directory points at production.
if ! grep -qE '^[[:space:]]*directory:.*acme-staging' "${CONFIG}"; then
	echo "Error: acme.directory in ${CONFIG} is not staging, refusing to run." >&2
	echo "      This test issues real certificates; against production it burns quota." >&2
	exit 1
fi

CHALLENGE="_acme-challenge.${DOMAIN}"

# The authoritative nameservers, asked of a public resolver. Every later query goes to
# these directly: a recursive resolver's answer may be a cached negative (DNSPod's 600s
# TTL floor applies to the negative entry too), which is exactly the reading this test
# must not depend on.
echo "==> Discovering the authoritative nameservers for ${DOMAIN}"
# read loop rather than mapfile: mapfile is bash 4+, and macOS still ships bash 3.2.
NS_LIST=()
while read -r ns; do
	[[ -n "${ns}" ]] && NS_LIST+=("${ns}")
done < <("${DIG}" +short NS "${DOMAIN}" @1.1.1.1 2>/dev/null | sed 's/\.$//' | sort)
if [[ "${#NS_LIST[@]}" -eq 0 ]]; then
	echo "Error: could not find NS records for ${DOMAIN} via 1.1.1.1." >&2
	echo "       Check the name and this host's outbound DNS." >&2
	exit 1
fi
printf '    %s\n' "${NS_LIST[@]}"

# Resolve each NS name to an address; query addresses, not names, so we never re-enter the
# recursive path we are trying to avoid.
NS_ADDRS=()
_seen_addrs=""
for ns in "${NS_LIST[@]}"; do
	while read -r ip; do
		[[ -z "${ip}" ]] && continue
		case "${_seen_addrs}" in
			*" ${ip} "*) continue ;;
		esac
		_seen_addrs+=" ${ip} "
		NS_ADDRS+=("${ip}")
	done < <("${DIG}" +short A "${ns}" @1.1.1.1 2>/dev/null; "${DIG}" +short AAAA "${ns}" @1.1.1.1 2>/dev/null)
done
if [[ "${#NS_ADDRS[@]}" -eq 0 ]]; then
	echo "Error: none of ${DOMAIN}'s nameservers resolve to an address." >&2
	exit 1
fi

# Distinct TXT values currently visible at the challenge name, asked of one authoritative
# server. Printed one per line, deduplicated, quotes stripped.
txt_values_from() {
	local server="$1"
	# A failed query is "no answer", not an error: the name legitimately does not exist
	# before the run, and a server can be briefly unreachable. Both must not abort the
	# sampling loop.
	"${DIG}" +short +time=3 +tries=1 TXT "${CHALLENGE}" "@${server}" 2>/dev/null |
		sed -e 's/^"//' -e 's/"$//' -e 's/" "//g' |
		grep -v '^$' | sort -u || true
}

# All distinct values across every authoritative server. A value counts as visible if any
# authority reports it: the test is about coexistence, and requiring unanimity here would
# make the observation depend on propagation timing we are deliberately sampling through.
all_txt_values() {
	local seen="" server
	for server in "${NS_ADDRS[@]}"; do
		while read -r v; do
			[[ -z "${v}" ]] && continue
			seen+="${v}"$'\n'
		done < <(txt_values_from "${server}")
	done
	printf '%s' "${seen}" | grep -v '^$' | sort -u || true
}

STATE_DIR="$(mktemp -d)"
CERT_PID=""
SAMPLE_PID=""
# shellcheck disable=SC2329  # invoked indirectly by the EXIT trap below
cleanup() {
	[[ -n "${SAMPLE_PID}" ]] && kill "${SAMPLE_PID}" 2>/dev/null || true
	[[ -n "${CERT_PID}" ]] && kill "${CERT_PID}" 2>/dev/null || true
	rm -rf "${STATE_DIR}"
}
trap cleanup EXIT

MAX_COEXISTING=0
SAMPLE_LOG="${STATE_DIR}/samples.log"
# Created up front: the sampler is a background subshell, and if it dies before its first
# iteration (a broken resolver, say) the log would never exist and the reader below would
# fail with an awk error instead of reporting the real problem.
: >"${SAMPLE_LOG}"

echo
echo "=============================================="
echo " wecert wildcard + apex end-to-end test"
echo " apex   : ${DOMAIN}"
echo " name   : ${CHALLENGE}"
echo " config : ${CONFIG}"
echo " state  : ${STATE_DIR}/state.db (temporary)"
echo "=============================================="
echo

echo "--- [1/6] baseline: what is at ${CHALLENGE} before we start ---"
BASELINE="$(all_txt_values)"
if [[ -n "${BASELINE}" ]]; then
	echo "    pre-existing TXT values (the run must not leave these changed):"
	printf '      %s\n' "${BASELINE}"
else
	echo "    none"
fi
echo

echo "--- [2/6] dry-run: validate the config and the ACME account ---"
"${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -dry-run || {
	echo "dry-run failed; the remaining steps would be pointless." >&2
	exit 1
}
echo

echo "--- [3/6] issuance, sampling ${CHALLENGE} every ${SAMPLE_INTERVAL}s for up to ${SAMPLE_SECONDS}s ---"
# The sampler runs alongside the issuance and records the highest number of distinct TXT
# values it ever sees. That maximum is the whole point: it is only >= 2 if the apex's and
# the wildcard's records genuinely coexisted.
(
	deadline=$(( $(date +%s) + SAMPLE_SECONDS ))
	while [[ "$(date +%s)" -lt "${deadline}" ]]; do
		values="$(all_txt_values)"
		# awk, not `grep -c`: grep -c prints 0 and exits 1 when there is no match, so a
		# `|| echo 0` fallback would append a second 0 and the variable would hold "0\n0".
		# That is a syntax error in the `[[ -ge 2 ]]` below, which silently turns into
		# "coexistence was never observed" regardless of what DNS answered.
		count="$(printf '%s\n' "${values}" | awk 'NF { n++ } END { print n + 0 }')"
		echo "${count} $(date -u +%H:%M:%S) $(printf '%s' "${values}" | tr '\n' ' ')" >>"${SAMPLE_LOG}"
		sleep "${SAMPLE_INTERVAL}"
	done
) &
SAMPLE_PID=$!

set +e
"${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -once
CERT_RC=$?
set -e

kill "${SAMPLE_PID}" 2>/dev/null || true
wait "${SAMPLE_PID}" 2>/dev/null || true
SAMPLE_PID=""

# awk, not `grep -c ... || echo 0`: grep -c prints 0 and exits 1 when nothing matches, and
# the fallback then appends a second 0 -- the variable holds "0\n0", and the comparison
# below dies with a syntax error instead of reporting "the sampler never ran".
SAMPLES_TAKEN="$(awk 'NF { n++ } END { print n + 0 }' "${SAMPLE_LOG}" 2>/dev/null || echo 0)"
if [[ "${SAMPLES_TAKEN}" -eq 0 ]]; then
	echo "Error: the sampler never completed a single query." >&2
	echo "       Nothing about coexistence can be concluded. Check that this host can reach" >&2
	echo "       the authoritative nameservers directly (UDP/53 outbound)." >&2
	exit 1
fi

if [[ "${CERT_RC}" -ne 0 ]]; then
	echo "issuance failed (exit ${CERT_RC}). Common causes:" >&2
	echo "  - the TXT records did not propagate to every authoritative NS" >&2
	echo "  - the DNS credentials lack permission for this zone" >&2
	echo "  - the apex is not in that DNS account" >&2
	echo >&2
	echo "sampling log (count, time, values seen):" >&2
	cat "${SAMPLE_LOG}" >&2 || true
	exit 1
fi

MAX_COEXISTING="$(awk '{ if ($1 + 0 > m) m = $1 + 0 } END { print m + 0 }' "${SAMPLE_LOG}" 2>/dev/null || echo 0)"
[[ "${MAX_COEXISTING}" =~ ^[0-9]+$ ]] || MAX_COEXISTING=0
echo "    issuance succeeded"
echo "    peak distinct TXT values observed at ${CHALLENGE}: ${MAX_COEXISTING}"
if [[ "${MAX_COEXISTING}" -ge 2 ]]; then
	# Show the first sample that had both, so the evidence is in the transcript.
	grep -E '^[2-9] ' "${SAMPLE_LOG}" | head -1 | sed 's/^/    first coexistence: /'
fi
echo

FAILED=0
fail() { echo "  ❌ $*" >&2; FAILED=1; }
pass() { echo "  ✅ $*"; }

echo "--- [4/6] assert: the apex and the wildcard coexisted ---"
if [[ "${MAX_COEXISTING}" -ge 2 ]]; then
	pass "two distinct TXT values were present at ${CHALLENGE} at the same time"
	pass "this is the invariant that forbids write-one/validate-one/delete-one"
else
	fail "only ${MAX_COEXISTING} distinct TXT value(s) were ever visible at ${CHALLENGE}"
	echo "     Either the apex and the wildcard are not both in the certificate, or the" >&2
	echo "     records were written and cleaned up one at a time. Check that the config" >&2
	echo "     lists both '${DOMAIN}' and '*.${DOMAIN}'." >&2
	echo "     sampling log:" >&2
	cat "${SAMPLE_LOG}" >&2 || true
fi
echo

echo "--- [5/6] assert: cleanup left nothing behind ---"
REMAINING="$(all_txt_values)"
if [[ -z "${REMAINING}" ]]; then
	pass "no TXT values remain at ${CHALLENGE}"
else
	fail "TXT values were left behind at ${CHALLENGE}:"
	printf '       %s\n' "${REMAINING}" >&2
	echo "     Leftovers consume the DNSPod record quota and are the classic DNS-01 leak." >&2
	if [[ -n "${BASELINE}" ]]; then
		echo "     (values present before the run: $(printf '%s ' "${BASELINE}"))" >&2
	fi
fi
echo

echo "--- [6/6] assert: state store is clean and the certificate covers both names ---"
PRESENTED="$(sqlite3 "${STATE_DIR}/state.db" "SELECT count(*) FROM authorizations WHERE presented = 1;" 2>/dev/null || echo "?")"
if [[ "${PRESENTED}" == "?" ]]; then
	fail "could not read the authorizations table; the state database is unusable"
elif [[ "${PRESENTED}" == "0" ]]; then
	pass "no authorization row is still marked presented"
else
	fail "${PRESENTED} authorization row(s) still marked presented; the next round would try to clean up records that are gone"
fi

SAN_LIST="$(sqlite3 "${STATE_DIR}/state.db" "SELECT count(*) FROM certificates;" 2>/dev/null || echo "?")"
if [[ "${SAN_LIST}" == "1" ]]; then
	pass "exactly one certificate recorded"
else
	fail "expected 1 certificate in the state store, found '${SAN_LIST}' (a '?' means the database is unreadable or has no schema)"
fi

# The SAN set is read back from the certificate wecert holds, which is what the probe and
# the CLB will actually serve.
SAN_CHECK="$(sqlite3 "${STATE_DIR}/state.db" "SELECT length(cert_pem) FROM certificates;" 2>/dev/null || echo 0)"
if [[ "${SAN_CHECK}" -gt 0 ]]; then
	pass "a certificate is persisted (cert_pem ${SAN_CHECK} bytes)"
else
	fail "no certificate is persisted in the state store"
fi
echo

echo "--- idempotency: a second round must reuse the order, not place a new one ---"
ORDER_BEFORE="$(sqlite3 "${STATE_DIR}/state.db" "SELECT coalesce(order_url,'') FROM orders LIMIT 1;" 2>/dev/null || echo "")"
if ! "${BIN}" -config "${CONFIG}" -state "${STATE_DIR}/state.db" -once; then
	fail "the second round failed"
else
	ORDER_AFTER="$(sqlite3 "${STATE_DIR}/state.db" "SELECT coalesce(order_url,'') FROM orders LIMIT 1;" 2>/dev/null || echo "")"
	if [[ -z "${ORDER_BEFORE}" ]]; then
		ORDERS="$(sqlite3 "${STATE_DIR}/state.db" "SELECT count(*) FROM orders;" 2>/dev/null || echo "?")"
		if [[ "${ORDERS}" == "0" ]]; then
			pass "the first round succeeded, so the second created no order"
		else
			fail "an order was created in the second round when the first one had already succeeded"
		fi
	elif [[ "${ORDER_BEFORE}" == "${ORDER_AFTER}" ]]; then
		pass "the pending order was reused (${ORDER_BEFORE})"
	else
		fail "the second round placed a new order: ${ORDER_BEFORE} -> ${ORDER_AFTER}"
	fi
fi
echo

echo "=============================================="
if [[ "${FAILED}" -eq 0 ]]; then
	echo " ✅ wildcard + apex end-to-end: PASS"
	echo "=============================================="
	exit 0
fi
echo " ❌ wildcard + apex end-to-end: FAIL"
echo "=============================================="
exit 1
