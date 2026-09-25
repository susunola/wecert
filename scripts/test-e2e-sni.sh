#!/usr/bin/env bash
#
# Self-test for the evidence helpers in scripts/e2e-sni.sh.
#
#   ./scripts/test-e2e-sni.sh
#
# e2e-sni.sh needs a real Tencent Cloud account, a real CLB with two certificates on
# one listener, and a human to drive a renewal, so its parsing helpers could not
# otherwise be tested at all. That is how this bug survived: wecert-clbverify -raw
# prints the raw DescribeListeners JSON *and then* a human-readable report, so the
# file the script saved was not JSON on its own, and json.load died with
# "Extra data: line 121 column 1 (char 3414)" against a real listener -- while the
# stub table used during development passed, because a stub printed pure JSON.
#
# This drives the helpers against dumps of that exact shape, with no network and no
# credentials:
#
#   A. JSON followed by a human report  -> keep_first_json trims it, listener_field
#                                          reads the CertId/ExtCertIds back out
#   B. pure JSON                        -> still parses (the shape the stub produced)
#   C. no JSON at all                   -> exits non-zero, writes nothing
#
# The helpers are sourced out of e2e-sni.sh itself (it stops before its operator
# procedure when sourced), so the test covers the copy that ships rather than a
# lookalike.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/e2e-sni.sh"

if [[ ! -f "${TARGET}" ]]; then
	echo "Error: ${TARGET} not found." >&2
	exit 1
fi

# The helpers under test: keep_first_json, listener_field and the wrappers built on
# them. Sourcing must not parse argv or touch the cloud, and the guard in the target
# is what guarantees that.
# shellcheck source=scripts/e2e-sni.sh
source "${TARGET}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
cd "${WORK}"

PASS=0
FAIL=0

ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
bad() {
	echo "  ❌ $1" >&2
	FAIL=$((FAIL + 1))
}

# expect_eq <label> <want> <got>
expect_eq() {
	if [[ "$2" == "$3" ]]; then
		ok "$1"
	else
		bad "$1: got '$3', want '$2'"
	fi
}

# expect_nonzero <label> <rc>
expect_nonzero() {
	if [[ "$2" -ne 0 ]]; then
		ok "$1 (exit=$2)"
	else
		bad "$1: expected a non-zero exit, got 0"
	fi
}

# ── fixture A: the real -raw shape, JSON *and then* the human report ─────────────
#
# Two listeners, because the script always asks for the one it was given by id and
# the selection is part of what has to keep working; the target is deliberately not
# the first, so a fallback to Listeners[0] cannot pass by accident.
echo "=== e2e-sni.sh self-test (raw-dump parsing, no network) ==="
cat > a.full <<'EOF'
{
  "Listeners": [
    {
      "ListenerId": "lbl-aaaa",
      "Protocol": "HTTPS",
      "Port": 8443,
      "SniSwitch": 1,
      "Certificate": {
        "CertId": "apOTHER01"
      }
    },
    {
      "ListenerId": "lbl-yyyy",
      "Protocol": "HTTPS",
      "Port": 443,
      "SniSwitch": 1,
      "Certificate": {
        "CertId": "apJdfyPa",
        "ExtCertIds": [
          "apJRqDsC"
        ]
      }
    }
  ],
  "RequestId": "6f4a0d1e-2b7c-4d8a-9f11-0a1b2c3d4e5f"
}
listener lbl-yyyy  (HTTPS:443)
  listener certificates: [apJdfyPa apJRqDsC]
  rule  test1.example.com: [apJdfyPa]
  SNI extension certificates: [apJRqDsC]
verdict: apJdfyPa is bound (primary), apJRqDsC is bound (SNI extension)
EOF

# The control that keeps case A honest: this fixture must be a file that a plain
# json.load cannot read, otherwise the test would pass even if the trailing report
# disappeared from the dump.
if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' a.full 2>/dev/null; then
	bad "fixture A is pure JSON, so it no longer reproduces the -raw shape"
else
	ok "fixture A is JSON + a human report (plain json.load rejects it)"
fi

if keep_first_json a.full a.json; then
	ok "A. keep_first_json accepts a dump that ends with a human report"
else
	bad "A. keep_first_json rejected the JSON + report dump"
fi

export LISTENER="lbl-yyyy"
expect_eq "A. listener_field primary is readable" "apJdfyPa" "$(listener_field a.json primary)"
expect_eq "A. listener_field ext is readable" "apJRqDsC" "$(listener_field a.json ext)"
expect_eq "A. listener_field has-certificate" "yes" "$(listener_field a.json has-certificate)"
expect_eq "A. listener_field selects by listener id" "apJdfyPa" "$(listener_field a.json primary)"
expect_eq "A. listener_field sni-switch" "1" "$(listener_field a.json sni-switch)"
expect_eq "A. listener_field bound lists primary then extensions" \
	"apJdfyPa
apJRqDsC" "$(listener_field a.json bound)"

# The id is what the operator passes, so a wrong id must select a different listener
# -- not silently fall back to the first one that has a certificate.
LISTENER="lbl-aaaa"
expect_eq "A. a different listener id reads that listener" "apOTHER01" "$(listener_field a.json primary)"

# bound_certs_are is the assertion the script builds on top of bound_of.
LISTENER="lbl-yyyy"
if bound_certs_are apJRqDsC a.json; then
	ok "A. bound_certs_are finds the SNI extension certificate"
else
	bad "A. bound_certs_are missed apJRqDsC"
fi
if bound_certs_are apNOTBOUND a.json; then
	bad "A. bound_certs_are accepted a certificate that is not bound"
else
	ok "A. bound_certs_are rejects a certificate that is not bound"
fi

# ── fixture D: the after-renewal shape, for assertion 5 ─────────────────────────────
# Assertion 5 ("A is no longer bound anywhere on the listener") is script-side against the
# stored dump, so it runs even when the snapshot fell back to the unfiltered query. The
# after-renewal dump has a NEW primary, B still among the extensions, and A gone: the
# reverse assertion must find A absent, and must not false-positive on B or the new id.
cat > d.full <<'EOF'
{
  "Listeners": [
    {
      "ListenerId": "lbl-yyyy",
      "Protocol": "HTTPS",
      "Port": 443,
      "SniSwitch": 1,
      "Certificate": {
        "CertId": "apNEW001",
        "ExtCertIds": [
          "apJRqDsC"
        ]
      }
    }
  ],
  "RequestId": "after-renewal"
}
EOF
keep_first_json d.full d.json
LISTENER="lbl-yyyy"
if bound_certs_are apJdfyPa d.json; then
	bad "D. bound_certs_are still finds the old A after the renewal (assertion 5 would miss it)"
else
	ok "D. bound_certs_are: the old A is gone after the renewal"
fi
if bound_certs_are apJRqDsC d.json; then
	ok "D. bound_certs_are: B is still bound after the renewal"
else
	bad "D. bound_certs_are lost B after the renewal"
fi
if bound_certs_are apNEW001 d.json; then
	ok "D. bound_certs_are: the new primary is bound"
else
	bad "D. bound_certs_are missed the new primary"
fi

# ── fixture B: pure JSON, the shape a stub prints ────────────────────────────────
cat > b.full <<'EOF'
{"Listeners":[{"ListenerId":"lbl-yyyy","Protocol":"HTTPS","Port":443,"SniSwitch":0,
"Certificate":{"CertId":"apJdfyPa","ExtCertIds":[]}}],"RequestId":"pure-json"}
EOF

if keep_first_json b.full b.json; then
	ok "B. keep_first_json accepts a pure-JSON dump"
else
	bad "B. keep_first_json rejected a pure-JSON dump"
fi
LISTENER="lbl-yyyy"
expect_eq "B. listener_field primary is readable" "apJdfyPa" "$(listener_field b.json primary)"
expect_eq "B. listener_field has-certificate" "yes" "$(listener_field b.json has-certificate)"

# ── fixture C: no JSON at all ────────────────────────────────────────────────────
# A -raw run that failed prints only the report (or an error); that must be a loud
# non-zero, not an empty file that every later assertion reads as "not bound".
cat > c.full <<'EOF'
listener lbl-yyyy  (HTTPS:443)
  listener certificates: none
error: DescribeListeners failed: AuthFailure.SignatureFailure
EOF

rc=0
out="$(keep_first_json c.full c.json 2>&1)" || rc=$?
expect_nonzero "C. keep_first_json rejects a dump with no JSON" "${rc}"
if [[ -e c.json ]]; then
	bad "C. keep_first_json wrote an output file for a dump with no JSON"
else
	ok "C. keep_first_json wrote nothing for a dump with no JSON"
fi
if [[ "${out}" == *"could not find a JSON document"* ]]; then
	ok "C. the failure names the file it could not parse"
else
	bad "C. the failure message is not actionable: ${out}"
fi

# ── listener_field on a file that is not JSON at all ─────────────────────────────
# The other half of the pair: if keep_first_json is ever bypassed, this is the
# failure the caller must see rather than an empty certificate list.
rc=0
out="$(listener_field c.full primary 2>&1)" || rc=$?
expect_nonzero "listener_field fails on a non-JSON dump" "${rc}"

echo
echo "  ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
