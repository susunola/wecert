###############################################################################
# CVM（阶段 C）—— 验证 systemd unit 和 CVM 角色凭证路径
#
# 这是最贵的一段（CVM 按小时计费），默认关闭。
# 只有前两个阶段都干净了再打开。
#
# 用 TAT（自动化助手）在机器上跑命令，因此不需要 SSH 密钥，
# 也不需要在安全组上开放任何入站端口。
###############################################################################

resource "tencentcloud_security_group" "test" {
  count = var.create_cvm ? 1 : 0

  name        = "${var.name_prefix}-sg"
  description = "wecert e2e test - no inbound rules needed (TAT is agent-initiated)"
  tags        = local.tags
}

resource "tencentcloud_instance" "test" {
  count = var.create_cvm ? 1 : 0

  instance_name              = "${var.name_prefix}-cvm"
  availability_zone          = var.availability_zone
  image_id                   = var.cvm_image_id
  instance_type              = var.cvm_instance_type
  instance_charge_type       = var.cvm_charge_type
  vpc_id                     = tencentcloud_vpc.test[0].id
  subnet_id                  = tencentcloud_subnet.test[0].id
  security_groups            = [tencentcloud_security_group.test[0].id]
  internet_charge_type       = "TRAFFIC_POSTPAID_BY_HOUR"
  internet_max_bandwidth_out = 1 # 只要够 TAT agent 出网即可，不跑业务流量
  allocate_public_ip         = true

  # 关联 CAM 角色 —— 这正是 wecert 生产环境推荐的凭证方式：
  # 密钥不落盘，从实例元数据服务现取现用。
  cam_role_name = var.enable_cvm_role ? var.cam_role_name : null

  tags = local.tags
}
