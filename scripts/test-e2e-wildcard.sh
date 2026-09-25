#!/usr/bin/env bash
#
# Self-test for scripts/e2e-wildcard.sh.
#
#   ./scripts/test-e2e-wildcard.sh
#
# e2e-wildcard.sh needs real DNS, real DNSPod credentials and real Let's Encrypt staging,
# so its assertions could not otherwise be tested at all -- including the one that matters,
# "did coexistence ever get observed?". This drives it with a canned resolver and a stub
# wecert binary, over the five states the assertion has to distinguish:
#
#   A. both TXT values coexist, cleanup is clean        -> must PASS
#   B. only one value is ever visible                   -> must FAIL (write/validate/delete
#                                                          one authorization at a time)
#   C. no value at all                                  -> must FAIL
#   D. one value first, then two                        -> must PASS (the peak is the signal)
#   E. both coexist but cleanup leaves a value behind   -> must FAIL
#   F. two certificates in the state store              -> must FAIL on the count check,
#                                                          without a bash syntax error
#
# Every run also asserts that the script only ever queried IP literals: the canned
# resolver answers one NS lookup with a CNAME target line, which real `dig +short A`
# prints for an alias, and a hostname in NS_ADDRS would silently re-enter the recursive
# path the script exists to avoid.
#
# No network, no credentials, no certificates. Runs in a few seconds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/e2e-wildcard.sh"

if [[ ! -x "${TARGET}" ]]; then
	echo "Error: ${TARGET} not found or not executable." >&2
	exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
cd "${WORK}"

cat > staging.yaml <<'YAML'
statePath: /tmp/wecert-selftest.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: selftest@atomwangnus.com
dns:
  provider: dnspod
  loginToken: token
tencent:
  credentialMode: static
  regions: [ap-guangzhou]
certificates:
  - name: selftest
    domains: [example.com, "*.example.com"]
YAML

# ── the stub wecert ──────────────────────────────────────────────────────────────────
# Creates the schema-shaped state store the script inspects, and marks the run finished on
# the first -once (NOT on -dry-run: the script runs that first, and treating it as the
# issuance would make the resolver report its post-issuance view during the whole sampling
# window). MOCK_EXTRA_CERT=1 leaves a second certificate row behind, for the case where the
# certificate-count check fails and the SAN-length query returns several rows.
cat > fake-wecert <<'SH'
#!/bin/sh
state=""; prev=""; once=0
for a in "$@"; do
	[ "${prev}" = "-state" ] && state="$a"
	[ "$a" = "-once" ] && once=1
	prev="$a"
done
[ -z "${state}" ] && exit 0
sqlite3 "${state}" "CREATE TABLE IF NOT EXISTS certificates(name TEXT, cert_pem BLOB);" 2>/dev/null
sqlite3 "${state}" "CREATE TABLE IF NOT EXISTS orders(cert_name TEXT, order_url TEXT);" 2>/dev/null
sqlite3 "${state}" "CREATE TABLE IF NOT EXISTS authorizations(cert_name TEXT, presented INTEGER);" 2>/dev/null
if [ "${once}" = "1" ]; then
	# Stay alive while the sampler is watching, so the canned resolver keeps answering with
	# the during-issuance view. The markers are created at the end, which is also when real
	# cleanup would have happened.
	sleep "${ISSUE_SECONDS:-0}"
	sqlite3 "${state}" "INSERT INTO certificates SELECT 'selftest','x' WHERE NOT EXISTS (SELECT 1 FROM certificates);" 2>/dev/null
	[ "${MOCK_EXTRA_CERT:-0}" = "1" ] && sqlite3 "${state}" "INSERT INTO certificates SELECT 'extra','y' WHERE NOT EXISTS (SELECT 1 FROM certificates WHERE name='extra');" 2>/dev/null
	: >"${MOCK_DONE}"
fi
exit 0
SH
chmod +x fake-wecert

# ── the canned resolver ──────────────────────────────────────────────────────────────
# MOCK_MODE is the answer during sampling; MOCK_AFTER is the answer once MOCK_DONE exists,
# i.e. what cleanup left behind.
#
# ns3's A answer deliberately includes a CNAME target line, which is what real
# `dig +short A` prints when the name is an alias -- the script must keep IP literals
# only, or a hostname lands in NS_ADDRS and every later @server query silently goes back
# through the recursive resolver. Every @target dig is invoked with is logged, so the
# test can assert nothing but addresses was ever queried.
cat > fake-dig <<'SH'
#!/bin/sh
for a in "$@"; do
	case "$a" in @*) echo "${a#@}" >> "${WORK}/dig-targets.log";; esac
done
args="$*"
case "${args}" in
	*"NS example.com"*) echo "ns1.example.com."; echo "ns2.example.com."; echo "ns3.example.com."; exit 0;;
	*"A ns1.example.com"*|*"A ns2.example.com"*) echo "192.0.2.1"; exit 0;;
	*"A ns3.example.com"*) echo "ns3-cname.example.com."; echo "192.0.2.2"; exit 0;;
	*"AAAA "*) exit 0;;
	*TXT*_acme-challenge.example.com*)
		if [ -f "${MOCK_DONE:-/dev/null}" ]; then
			case "${MOCK_AFTER:-clean}" in
				clean) exit 0;;
				dirty) echo '"leftover-value"'; exit 0;;
			esac
		fi
		case "${MOCK_MODE:-two}" in
			two)  echo '"value-apex"'; echo '"value-wildcard"';;
			one)  echo '"value-apex"';;
			none) : ;;
			seq)  if [ -f "${WORK}/.seq1" ]; then
					echo '"value-apex"'; echo '"value-wildcard"'
				else
					: >"${WORK}/.seq1"; echo '"value-apex"'
				fi;;
		esac
		exit 0;;
esac
exit 0
SH
chmod +x fake-dig

# The canned resolver uses ${WORK} for its one-shot marker.
export WORK

PASS=0
FAIL=0

ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
bad() {
	echo "  ❌ $1" >&2
	FAIL=$((FAIL + 1))
}

# run <mode> <after> <expected-exit> <expected-peak> <label>
run() {
	local mode="$1" after="$2" want_rc="$3" want_peak="$4" label="$5"
	rm -f "${WORK}/.done" "${WORK}/.seq1" "${WORK}/dig-targets.log"

	# Assignments go on their own lines first: an env assignment on the same command line
	# is not visible to expansions in that line (SC2097/SC2098), so "${WORK}" inside the
	# same invocation would expand to the outer value.
	local out rc peak
	export MOCK_MODE="${mode}" MOCK_AFTER="${after}" MOCK_DONE="${WORK}/.done"
	export DIG="${WORK}/fake-dig" BIN="${WORK}/fake-wecert"
	export SAMPLE_SECONDS=5 SAMPLE_INTERVAL=1 SETTLE_SECONDS=0 SETTLE_INTERVAL=1
	# The stub lives 2s; sampling covers 5s, so the during-issuance view is observed and the
	# post-issuance view is not mistaken for it.
	export ISSUE_SECONDS=2
	set +e
	out="$(bash "${TARGET}" example.com "${WORK}/staging.yaml" 2>&1)"
	rc=$?
	set -e
	unset MOCK_MODE MOCK_AFTER MOCK_DONE DIG BIN SAMPLE_SECONDS SAMPLE_INTERVAL ISSUE_SECONDS SETTLE_SECONDS SETTLE_INTERVAL

	peak="$(printf '%s' "${out}" | grep -oE 'peak distinct TXT values observed at [^ ]+: [0-9]+' | sed 's/.*: //' || true)"
	peak="${peak:-0}"

	if [[ "${rc}" -eq "${want_rc}" && "${peak}" -eq "${want_peak}" ]]; then
		echo "  ✅ ${label}: exit=${rc} peak=${peak}"
		PASS=$((PASS + 1))
	else
		echo "  ❌ ${label}: exit=${rc} (want ${want_rc}) peak=${peak} (want ${want_peak})" >&2
		printf '%s\n' "${out}" | sed 's/^/       | /' >&2
		FAIL=$((FAIL + 1))
	fi

	# The canned resolver answers ns3's A query with a CNAME target line; every address the
	# script then queried must be an IP literal (a letter = a hostname leaked through). The
	# fixtures only use IPv4, so "contains a letter" is the whole check.
	if [[ -f "${WORK}/dig-targets.log" ]] && grep -q '[a-zA-Z]' "${WORK}/dig-targets.log"; then
		bad "${label}: a hostname leaked into the authoritative-server addresses"
		sed 's/^/       | /' "${WORK}/dig-targets.log" >&2
	fi
}

echo "=== e2e-wildcard.sh self-test (canned resolver, no network) ==="
run two  clean 0 2 "A. apex+wildcard coexist, clean cleanup"
run one  clean 1 1 "B. only one value ever visible"
run none clean 1 0 "C. no value at all"
run seq  clean 0 2 "D. one value then two (peak wins)"
run two  dirty 1 2 "E. coexist but a value is left behind"

# F. two certificates in the state store: the count check fails the run, and the
# SAN-length query then returns one row per certificate -- a multi-line value in the
# arithmetic below it used to be a bash syntax error that killed the script before it
# could say why. It must now degrade to the ordinary fail branch.
rm -f "${WORK}/.done" "${WORK}/.seq1" "${WORK}/dig-targets.log"
export MOCK_MODE=two MOCK_AFTER=clean MOCK_DONE="${WORK}/.done" MOCK_EXTRA_CERT=1
export DIG="${WORK}/fake-dig" BIN="${WORK}/fake-wecert"
export SAMPLE_SECONDS=5 SAMPLE_INTERVAL=1 SETTLE_SECONDS=0 SETTLE_INTERVAL=1 ISSUE_SECONDS=2
set +e
out="$(bash "${TARGET}" example.com "${WORK}/staging.yaml" 2>&1)"
rc=$?
set -e
unset MOCK_MODE MOCK_AFTER MOCK_DONE MOCK_EXTRA_CERT DIG BIN SAMPLE_SECONDS SAMPLE_INTERVAL ISSUE_SECONDS SETTLE_SECONDS SETTLE_INTERVAL
if [[ "${rc}" -eq 1 ]] && [[ "${out}" == *"expected 1 certificate"* ]] && [[ "${out}" != *"syntax error"* ]]; then
	ok "F. two certificates in the store: reported as a failure, no bash syntax error"
else
	bad "F. two certificates in the store: exit=${rc} (want 1 with the count failure and no syntax error)"
	printf '%s\n' "${out}" | sed 's/^/       | /' >&2
fi
echo
echo "  ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
