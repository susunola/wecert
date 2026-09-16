# Look up the availability zones actually usable in the current account/region.
# Zone names differ between accounts and regions, so hard-coding one easily runs
# into InvalidZone.MismatchRegion (and that error message is itself misleading).
data "tencentcloud_availability_zones_by_product" "cvm" {
  product = "cvm"
}

output "available_zones" {
  description = "List of availability zones available in this region."
  value       = [for z in data.tencentcloud_availability_zones_by_product.cvm.zones : z.name]
}
