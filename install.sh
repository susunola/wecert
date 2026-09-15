#!/usr/bin/env bash
#
# wecert 安装脚本 —— 在目标 CVM 上执行。
#
#   sudo ./install.sh /path/to/wecert_linux_amd64
#
# 做的事情：建系统用户、装二进制、准备配置目录、装 systemd unit。
# 不会自动启动服务，也不会替你填 DNSPod token —— 这两步需要你确认。
set -euo pipefail

BINARY="${1:-}"
INSTALL_PATH="/usr/local/bin/wecert"
CONFIG_DIR="/etc/wecert"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"

if [[ -z "${BINARY}" ]]; then
	echo "用法: sudo $0 <wecert 二进制路径>" >&2
	echo "例如: sudo $0 ./wecert_linux_amd64" >&2
	exit 1
fi

if [[ ! -f "${BINARY}" ]]; then
	echo "错误: 找不到文件 ${BINARY}" >&2
	exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "错误: 需要 root 权限运行(sudo)" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> 检查二进制架构"
file "${BINARY}"
if ! file "${BINARY}" | grep -q 'ELF 64-bit'; then
	echo "错误: 这不是 Linux ELF 二进制。CVM 上需要 linux/amd64 或 linux/arm64 的产物。" >&2
	exit 1
fi

echo "==> 创建系统用户 wecert"
if ! id -u wecert >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin wecert
	echo "    已创建"
else
	echo "    已存在，跳过"
fi

echo "==> 安装二进制到 ${INSTALL_PATH}"
install -m 0755 -o root -g root "${BINARY}" "${INSTALL_PATH}"

echo "==> 准备配置目录 ${CONFIG_DIR}"
mkdir -p "${CONFIG_DIR}"
chown root:wecert "${CONFIG_DIR}"
chmod 0750 "${CONFIG_DIR}"

if [[ -f "${CONFIG_FILE}" ]]; then
	echo "    配置已存在，保留不覆盖"
else
	if [[ -f "${SCRIPT_DIR}/config.example.yaml" ]]; then
		install -m 0640 -o root -g wecert "${SCRIPT_DIR}/config.example.yaml" "${CONFIG_FILE}"
		echo "    已放置示例配置，务必先编辑再启动"
	else
		echo "    警告: 未找到 config.example.yaml，请手动创建 ${CONFIG_FILE}"
	fi
fi

echo "==> 安装 systemd unit"
for unit in wecert.service wecert-once.service wecert.timer; do
	if [[ -f "${SCRIPT_DIR}/deploy/systemd/${unit}" ]]; then
		install -m 0644 "${SCRIPT_DIR}/deploy/systemd/${unit}" "/etc/systemd/system/${unit}"
		echo "    ${unit}"
	fi
done
systemctl daemon-reload

cat <<EOF

==> 安装完成

接下来三步：

1) 编辑配置（填入 DNSPod token；腾讯云走 CVM 角色则无需填密钥）
     sudo vi ${CONFIG_FILE}

2) 先指向 Let's Encrypt staging 验证一遍：
     sudo -u wecert ${INSTALL_PATH} -config ${CONFIG_FILE} -dry-run

   确认无误后，把 acme.directory 改成生产地址：
     https://acme-v02.api.letsencrypt.org/directory

3) 启动服务：
     sudo systemctl enable --now wecert

   偏好"跑完就退出"的定时模式则改用：
     sudo systemctl enable --now wecert-once.timer

查看日志：
     journalctl -u wecert -f

注意：首次签发只会把证书上传到腾讯云并打印 CertId，
需要你去 CLB 控制台手动绑定一次；之后每次续期都是全自动的。
EOF
