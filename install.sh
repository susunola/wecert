#!/usr/bin/env bash
#
# wecert install script — run this on the target CVM.
#
#   sudo ./install.sh /path/to/wecert_linux_amd64
#
# What it does: create the system user, install the binary, prepare the config
# directory, install the systemd unit.
# It does not start the service, and it does not fill in the DNSPod token for you
# — both of those steps need your explicit confirmation.
set -euo pipefail

BINARY="${1:-}"
INSTALL_PATH="/usr/local/bin/wecert"
CONFIG_DIR="/etc/wecert"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"

if [[ -z "${BINARY}" ]]; then
	echo "Usage: sudo $0 <path to the wecert binary>" >&2
	echo "Example: sudo $0 ./wecert_linux_amd64" >&2
	exit 1
fi

if [[ ! -f "${BINARY}" ]]; then
	echo "Error: file not found: ${BINARY}" >&2
	exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "Error: must be run as root (sudo)" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Checking binary architecture"
file -- "${BINARY}"
if ! file -- "${BINARY}" | grep -q 'ELF 64-bit'; then
	echo "Error: this is not a Linux ELF binary. The CVM needs a linux/amd64 or linux/arm64 build." >&2
	exit 1
fi

# Verify the artifact before installing it as root.
#
# `make release` writes dist/SHA256SUMS next to the binaries, and nothing ever read
# it: whatever file was passed in became a root-owned binary that systemd then runs
# with the CAM credentials and the private-key database. That is a lot of trust to
# place in a file that may have crossed a build host, a shared directory or a
# download.
#
# Absent sums file: warn rather than refuse, because copying the single binary to a
# CVM is a legitimate workflow. Present but mismatched: refuse, because that is the
# case this check exists for.
BINARY_DIR="$(cd "$(dirname "${BINARY}")" && pwd)"
BINARY_NAME="$(basename "${BINARY}")"
SUMS="${BINARY_DIR}/SHA256SUMS"

if [[ -f "${SUMS}" ]]; then
	echo "==> Verifying ${BINARY_NAME} against ${SUMS}"
	expected="$(awk -v f="${BINARY_NAME}" '$2 == f { print $1 }' "${SUMS}")"
	if [[ -z "${expected}" ]]; then
		echo "Error: ${BINARY_NAME} is not listed in ${SUMS}. Refusing to install an unlisted artifact." >&2
		exit 1
	fi
	if command -v sha256sum >/dev/null 2>&1; then
		actual="$(sha256sum -- "${BINARY}" | awk '{ print $1 }')"
	else
		actual="$(shasum -a 256 -- "${BINARY}" | awk '{ print $1 }')"
	fi
	if [[ "${actual}" != "${expected}" ]]; then
		echo "Error: checksum mismatch for ${BINARY_NAME}." >&2
		echo "  expected ${expected}" >&2
		echo "  actual   ${actual}" >&2
		exit 1
	fi
	echo "    ok"
else
	echo "Warning: no SHA256SUMS beside ${BINARY_NAME}, so the artifact cannot be verified." >&2
	echo "         It will be installed as root and run with the CAM credentials and the" >&2
	echo "         private-key database. Prefer installing from a 'make release' output." >&2
fi

echo "==> Creating system user wecert"
if ! id -u wecert >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin wecert
	echo "    created"
else
	echo "    already exists, skipping"
fi

echo "==> Installing binary to ${INSTALL_PATH}"
install -m 0755 -o root -g root -- "${BINARY}" "${INSTALL_PATH}"

echo "==> Preparing config directory ${CONFIG_DIR}"
mkdir -p "${CONFIG_DIR}"
chown root:wecert "${CONFIG_DIR}"
chmod 0750 "${CONFIG_DIR}"

if [[ -f "${CONFIG_FILE}" ]]; then
	echo "    config already exists, keeping it as is"
else
	if [[ -f "${SCRIPT_DIR}/config.example.yaml" ]]; then
		install -m 0640 -o root -g wecert "${SCRIPT_DIR}/config.example.yaml" "${CONFIG_FILE}"
		echo "    placed the example config; be sure to edit it before starting"
	else
		echo "    warning: config.example.yaml not found, create ${CONFIG_FILE} by hand"
	fi
fi

echo "==> Installing systemd unit"
for unit in wecert.service wecert-once.service wecert-once.timer; do
	if [[ -f "${SCRIPT_DIR}/deploy/systemd/${unit}" ]]; then
		install -m 0644 "${SCRIPT_DIR}/deploy/systemd/${unit}" "/etc/systemd/system/${unit}"
		echo "    ${unit}"
	fi
done
systemctl daemon-reload

cat <<EOF

==> Installation complete

Three steps remain:

1) Edit the config (fill in the DNSPod token; when Tencent Cloud runs with a CVM
   role, no secret key is needed)
     sudo vi ${CONFIG_FILE}

   acme.directory already defaults to Let's Encrypt staging, so the whole flow
   works without changing anything.

2) Validate once against staging first:
     sudo -u wecert ${INSTALL_PATH} -config ${CONFIG_FILE} -dry-run

   Once that looks right, change acme.directory explicitly to the production URL:
     https://acme-v02.api.letsencrypt.org/directory

3) Start the service:
     sudo systemctl enable --now wecert

   If you prefer the "run once and exit" timer mode, use this instead:
     sudo systemctl enable --now wecert-once.timer

View the logs:
     journalctl -u wecert -f

Note: the first issuance only uploads the certificate to Tencent Cloud and prints
the CertId. You have to bind it once by hand in the CLB console; every renewal
after that is fully automatic.
EOF
