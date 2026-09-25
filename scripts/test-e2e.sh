#!/usr/bin/env bash
#
# Self-test for the argument parsing of scripts/e2e.sh.
#
#   ./scripts/test-e2e.sh
#
# The full e2e run needs pebble, port 53 and minutes of wall time, but its argument
# parser can fail before any of that -- and did: `--out` as the last argument read "$2"
# under set -u, so the documented flag's error was "unbound variable" instead of a
# usable message. These cases exit during parsing, so the suites never start.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/e2e.sh"

if [[ ! -f "${TARGET}" ]]; then
	echo "Error: ${TARGET} not found." >&2
	exit 1
fi

PASS=0
FAIL=0

ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
bad() {
	echo "  ❌ $1" >&2
	FAIL=$((FAIL + 1))
}

echo "=== e2e.sh self-test (argument parsing only; the suites never start) ==="

# expect_parse_error <label> <args...>
expect_parse_error() {
	local label="$1"
	shift
	local out rc
	set +e
	out="$(bash "${TARGET}" "$@" 2>&1)"
	rc=$?
	set -e
	if [[ "${rc}" -ne 0 ]] && [[ "${out}" != *"unbound variable"* ]]; then
		ok "${label} (exit=${rc})"
	else
		bad "${label}: exit=${rc}, output: ${out}"
	fi
}

expect_parse_error "--out as the last argument is a clean error, not 'unbound variable'" --out
expect_parse_error "an unknown argument is rejected" --bogus

echo
echo "  ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
