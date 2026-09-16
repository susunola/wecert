###############################################################################
# Network: VPC + subnet
#
# Created only when a CLB or CVM is needed. The pure wildcard test (stage A) never
# touches this file.
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
