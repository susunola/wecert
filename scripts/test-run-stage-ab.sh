#!/usr/bin/env bash
#
# Self-test for the config-rendering helpers in scripts/run-stage-ab.sh.
#
#   ./scripts/test-run-stage-ab.sh
#
# run-stage-ab.sh creates real cloud resources, so its sed-based config rendering could
# not otherwise be tested at all. The values it substitutes are operator input, and sed's
# replacement text is not literal: an unescaped `&` expands to the whole match, an
# unescaped `|` ends the s-command early, and a backslash escapes the next character. An
# email like "ops&admin@example.com" used to render as "ops  email: .*@example.com"
# (the pattern glued back in), and one with a `|` aborted the run with a sed error.
#
# The helpers are sourced out of run-stage-ab.sh itself (it stops before its operator
# procedure when sourced), so the test covers the copy that ships rather than a lookalike.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/run-stage-ab.sh"

if [[ ! -f "${TARGET}" ]]; then
	echo "Error: ${TARGET} not found." >&2
	exit 1
fi

# shellcheck source=scripts/run-stage-ab.sh
source "${TARGET}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

PASS=0
FAIL=0

ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
bad() {
	echo "  ❌ $1" >&2
	FAIL=$((FAIL + 1))
}

echo "=== run-stage-ab.sh self-test (config rendering, no network) ==="

# The escape helper itself: every metacharacter of the replacement side survives.
got="$(sed_escape_replacement 'a&b|c\d')"
if [[ "${got}" == 'a\&b\|c\\d' ]]; then
	ok "sed_escape_replacement escapes &, | and backslash"
else
	bad "sed_escape_replacement: got '${got}'"
fi

# A plain value passes through unchanged.
got="$(sed_escape_replacement 'ops@example.com')"
if [[ "${got}" == 'ops@example.com' ]]; then
	ok "sed_escape_replacement leaves a plain value alone"
else
	bad "sed_escape_replacement altered a plain value: '${got}'"
fi

# The shipped pipeline against the real template: an email carrying sed metacharacters
# must land in the config byte-for-byte, and the run must not die inside sed.
email='ops&admin@example.com'
if render_config "example.com" "${email}" "${WORK}/config.yaml"; then
	ok "render_config accepts an email containing '&'"
else
	bad "render_config failed on an email containing '&'"
fi
if grep -qxF "  email: ${email}" "${WORK}/config.yaml"; then
	ok "render_config writes the email literally (& not expanded to the match)"
else
	bad "render_config: the email line is not literal: $(grep -n 'email:' "${WORK}/config.yaml" | head -1)"
fi

email='ops|admin@example.com'
if render_config "example.com" "${email}" "${WORK}/config2.yaml" 2>"${WORK}/sed-err"; then
	ok "render_config accepts an email containing '|' (the s-command delimiter)"
else
	bad "render_config failed on an email containing '|': $(cat "${WORK}/sed-err")"
fi
if grep -qxF "  email: ${email}" "${WORK}/config2.yaml"; then
	ok "render_config writes a '|'-carrying email literally"
else
	bad "render_config: the '|' email line is not literal"
fi

# REPLACE_ME must still all be gone: the domain substitution has to keep working
# alongside the escaping.
if grep -q 'REPLACE_ME' "${WORK}/config.yaml"; then
	bad "render_config left a REPLACE_ME placeholder behind"
else
	ok "render_config substitutes every REPLACE_ME with the domain"
fi
if grep -q 'example.com' "${WORK}/config.yaml"; then
	ok "render_config: the domain landed in the config"
else
	bad "render_config: the domain is missing from the config"
fi

echo
echo "  ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
