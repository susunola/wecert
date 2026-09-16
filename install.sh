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
file "${BINARY}"
if ! file "${BINARY}" | grep -q 'ELF 64-bit'; then
	echo "Error: this is not a Linux ELF binary. The CVM needs a linux/amd64 or linux/arm64 build." >&2
	exit 1
fi

echo "==> Creating system user wecert"
if ! id -u wecert >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin wecert
	echo "    created"
else
	echo "    already exists, skipping"
fi

echo "==> Installing binary to ${INSTALL_PATH}"
install -m 0755 -o root -g root "${BINARY}" "${INSTALL_PATH}"

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
