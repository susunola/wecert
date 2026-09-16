#!/usr/bin/env bash
#
# Stage A + B end-to-end orchestration
#
#   ./scripts/run-stage-ab.sh <domain> <email> [--yes] [--skip-apply]
#
# Example:
#   ./scripts/run-stage-ab.sh example.com ops@example.com
#
# It does four things:
#   1. terraform apply — create the VPC + CLB + HTTPS listener + placeholder cert
#   2. generate the staging config and register the ACME account
#   3. seed the placeholder cert's CertId into the wecert state store (simulating
#      "a certificate is already bound to the listener")
#   4. run wecert — issue the wildcard certificate and trigger the
#      UpdateCertificateInstance rebind
#
# Finally it uses wecert-clbverify to gather independent evidence from the Tencent
# Cloud side that the listener's CertId really changed.
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"
shift 2 2>/dev/null || true

# By default it only runs plan. Creating real cloud resources requires an explicit
# --yes — a script like this should not have a "run it once by accident and get
# billed" failure mode.
CONFIRM=""
SKIP_APPLY=""
for arg in "$@"; do
	case "${arg}" in
	--yes) CONFIRM="--yes" ;;
	--skip-apply) SKIP_APPLY="--skip-apply" ;;
	*)
		echo "unknown argument: ${arg}" >&2
		exit 1
		;;
	esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTENV="${ROOT}/testenv"
STATE_DIR="/tmp/wecert-e2e"
STATE_DB="${STATE_DIR}/state.db"
CONFIG="${STATE_DIR}/config.yaml"
CREDS="${WECERT_CREDS:-${HOME}/.wecert/tencent.env}"

if [[ -z "${DOMAIN}" || -z "${EMAIL}" ]]; then
	echo "Usage: $0 <domain> <email> [--yes] [--skip-apply]" >&2
	echo "Example: $0 example.com ops@example.com --yes" >&2
	echo >&2
	echo "Without --yes it only generates a terraform plan and stops; no resources are created." >&2
	exit 1
fi

# ── preflight checks ────────────────────────────────────────────────────────

if [[ ! -f "${CREDS}" ]]; then
	echo "Error: credentials file not found: ${CREDS}" >&2
	echo "      Expected format: export TENCENTCLOUD_SECRET_ID=... / export TENCENTCLOUD_SECRET_KEY=..." >&2
	echo "      Point WECERT_CREDS at the file to override the default location." >&2
	exit 1
fi

# Extract only the two variables needed; do not source the whole file.
#
# A credentials file usually holds other secrets too (GitHub tokens, PyPI tokens
# and the like), and sourcing it would push all of them into the current shell for
# child processes to inherit — terraform and wecert have no need for them, so
# there is no reason to hand them over.
#
# This used to be eval "$(grep ...)", which is only marginally safer than sourcing:
# eval executes any command substitution a value happens to contain, and a credentials
# file is data, not code. Extract the values with sed instead and strip one layer of
# surrounding quotes.
#
# Both forms are accepted, with or without "export": a credentials file that is only
# sourced by an interactive shell often omits it, and requiring the keyword here would
# silently report "not set" for a file that does define the variable.
cred_value() {
	sed -n \
		-e "s/^[[:space:]]*export[[:space:]][[:space:]]*$1=\(.*\)/\1/p" \
		-e "s/^[[:space:]]*$1=\(.*\)/\1/p" \
		"${CREDS}" |
		head -n 1 |
		sed -e 's/^["'"'"']//' -e 's/["'"'"']$//'
}
TENCENTCLOUD_SECRET_ID="$(cred_value TENCENTCLOUD_SECRET_ID)"
TENCENTCLOUD_SECRET_KEY="$(cred_value TENCENTCLOUD_SECRET_KEY)"
export TENCENTCLOUD_SECRET_ID TENCENTCLOUD_SECRET_KEY

if [[ -z "${TENCENTCLOUD_SECRET_ID:-}" || -z "${TENCENTCLOUD_SECRET_KEY:-}" ]]; then
	echo "Error: TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY are not set in ${CREDS}" >&2
	exit 1
fi
# Do not echo a prefix of the SecretId. cmd/preflight dropped exactly this: it
# panicked on a truncated variable, and putting part of a credential into terminal
# history and CI logs buys nothing -- knowing it is loaded is the whole signal.
echo "credentials: loaded"

for bin in terraform sqlite3; do
	command -v "${bin}" >/dev/null 2>&1 || { echo "Error: missing ${bin}" >&2; exit 1; }
done

[[ -x "${ROOT}/bin/wecert" ]] || { echo "Error: run make build first" >&2; exit 1; }
[[ -x "${ROOT}/bin/wecert-clbverify" ]] || { echo "Error: build the auxiliary tools first: make tools" >&2; exit 1; }

# Only set a cache dir when the caller (or an existing environment) provides one;
# there is no portable default location.
if [[ -n "${TF_PLUGIN_CACHE_DIR:-}" ]]; then
	export TF_PLUGIN_CACHE_DIR
fi
export TF_IN_AUTOMATION=1

echo "domain: ${DOMAIN} + *.${DOMAIN}"
echo "email: ${EMAIL}"
echo

# ── 1. create the cloud resources ───────────────────────────────────────────

if [[ "${SKIP_APPLY}" != "--skip-apply" ]]; then
	echo "=== [1/4] terraform plan ==="
	(
		cd "${TESTENV}"
		terraform init -input=false >/dev/null
		terraform plan -input=false -out=tfplan
	)

	if [[ "${CONFIRM}" != "--yes" ]]; then
		cat <<'EOF'

⚠️  The plan above has not been applied. This step creates real Tencent Cloud
    resources and incurs charges (VPC / internal CLB / HTTPS listener /
    placeholder cert — 7 resources in total).

    Once you are sure, add --yes and run it again to apply:

        ./scripts/run-stage-ab.sh <domain> <email> --yes

EOF
		exit 0
	fi

	echo
	echo "=== terraform apply ==="
	(cd "${TESTENV}" && terraform apply -input=false tfplan)
	rm -f "${TESTENV}/tfplan"
	echo
else
	echo "=== [1/4] skipping terraform apply ==="
fi

cd "${TESTENV}"
REGION="$(terraform output -raw region)"
CLB_ID="$(terraform output -raw clb_id)"
LISTENER_ID="$(terraform output -raw listener_id)"
PLACEHOLDER_ID="$(terraform output -raw placeholder_cert_id)"

echo "CLB        : ${CLB_ID}"
echo "listener   : ${LISTENER_ID}"
echo "placeholder: ${PLACEHOLDER_ID}"
echo

echo "--- state before the rebind ---"
"${ROOT}/bin/wecert-clbverify" -region "${REGION}" -clb "${CLB_ID}" -listener "${LISTENER_ID}" \
	-expect "${PLACEHOLDER_ID}"
echo

# ── 2. generate the config and initialize ───────────────────────────────────

echo "=== [2/4] generate the config and register the ACME account ==="
mkdir -p "${STATE_DIR}"
rm -f "${STATE_DB}" "${STATE_DB}-wal" "${STATE_DB}-shm"

sed -e "s|REPLACE_ME|${DOMAIN}|g" \
	-e "s|^  email: .*|  email: ${EMAIL}|" \
	"${ROOT}/e2e-config-wildcard.yaml" > "${CONFIG}"

# Force staging: one wrong character here burns real production quota. Anchored to the
# directory key, because a bare "acme-staging" match could come from a comment while the
# real directory points at production.
grep -qE '^[[:space:]]*directory:.*acme-staging' "${CONFIG}" || { echo "Error: the config is not staging" >&2; exit 1; }

"${ROOT}/bin/wecert" -config "${CONFIG}" -state "${STATE_DB}" -dry-run
echo

# ── 3. seed the "certificate is already bound" state ────────────────────────

echo "=== [3/4] seed deployed_cert_id = the placeholder cert ==="
# Simulate "the certificate wecert manages is currently bound to the listener".
# That way, when the first issuance reaches the deploy stage, oldID is non-empty
# and the UpdateCertificateInstance path is actually exercised.
sqlite3 "${STATE_DB}" \
	"INSERT INTO certificates (name, deployed_cert_id) VALUES ('wildcard-test', '${PLACEHOLDER_ID}')
	 ON CONFLICT(name) DO UPDATE SET deployed_cert_id='${PLACEHOLDER_ID}';"
sqlite3 "${STATE_DB}" "SELECT name, deployed_cert_id FROM certificates;"
echo

# ── 4. issue + rebind ───────────────────────────────────────────────────────

echo "=== [4/4] issue the wildcard certificate and trigger the rebind ==="
"${ROOT}/bin/wecert" -config "${CONFIG}" -state "${STATE_DB}" -once

NEW_CERT_ID="$(sqlite3 "${STATE_DB}" "SELECT deployed_cert_id FROM certificates WHERE name='wildcard-test';")"
echo
echo "new certificate CertId: ${NEW_CERT_ID}"

if [[ "${NEW_CERT_ID}" == "${PLACEHOLDER_ID}" || -z "${NEW_CERT_ID}" ]]; then
	echo "Error: the certificate was not uploaded (deployed_cert_id did not change)" >&2
	exit 1
fi

# ── independent evidence ────────────────────────────────────────────────────

echo
echo "=== independently verify the rebind from the Tencent Cloud side ==="
"${ROOT}/bin/wecert-clbverify" -region "${REGION}" -clb "${CLB_ID}" -listener "${LISTENER_ID}" \
	-expect "${NEW_CERT_ID}" \
	-not-expect "${PLACEHOLDER_ID}"

echo
echo "=== verify ARI (decides the rate-limit exemption) ==="
ARI="$(sqlite3 "${STATE_DB}" "SELECT ari_cert_id FROM certificates WHERE name='wildcard-test';")"
if [[ -z "${ARI}" ]]; then
	echo "⚠️  ARI certID is empty — renewals will not get the rate-limit exemption" >&2
else
	echo "ARI certID: ${ARI}"
fi

echo
echo "=== idempotency: another round must not create a new order ==="
"${ROOT}/bin/wecert" -config "${CONFIG}" -state "${STATE_DB}" -once
ORDERS="$(sqlite3 "${STATE_DB}" "SELECT count(*) FROM orders;")"
echo "orders left behind: ${ORDERS} (should be 0)"
[[ "${ORDERS}" == "0" ]] || { echo "Error: idempotency is broken" >&2; exit 1; }

cat <<EOF

==============================================
 ✅ Stage A + B all passed

 What was verified:
   - the path where wildcard + apex share one TXT name works
   - waiting for propagation to the authoritative NS works
   - the certificate was uploaded to Tencent Cloud SSL Certificate Service
   - UpdateCertificateInstance rebound the CLB listener
   - idempotency holds (no new order before the window opens)

 ⚠️  Remember to clean up:
     cd ${TESTENV} && terraform destroy
     plus the test certificate wecert uploaded (the one whose Alias starts with wecert/)
==============================================
EOF
