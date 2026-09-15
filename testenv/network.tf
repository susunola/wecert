###############################################################################
# 网络：VPC + 子网
#
# 只在需要 CLB 或 CVM 时才创建。纯 wildcard 测试（阶段 A）用不到这个文件。
###############################################################################

resource "tencentcloud_vpc" "test" {
  count = var.create_clb || var.create_cvm ? 1 : 0

  name       = "${var.name_prefix}-vpc"
  cidr_block = "10.99.0.0/16"
  tags       = local.tags
}

resource "tencentcloud_subnet" "test" {
  count = var.create_clb || var.create_cvm ? 1 : 0

  name              = "${var.name_prefix}-subnet"
  vpc_id            = tencentcloud_vpc.test[0].id
  cidr_block        = "10.99.1.0/24"
  availability_zone = var.availability_zone
  tags              = local.tags
}
