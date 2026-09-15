# 查询当前账号/地域下真正可用的可用区。
# 可用区名在不同账号和地域下不一样，硬编码很容易撞上
# InvalidZone.MismatchRegion（而且这个报错信息本身有误导性）。
data "tencentcloud_availability_zones_by_product" "cvm" {
  product = "cvm"
}

output "available_zones" {
  description = "该地域下可用的可用区列表。"
  value       = [for z in data.tencentcloud_availability_zones_by_product.cvm.zones : z.name]
}
