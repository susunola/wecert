###############################################################################
# wecert test environment
#
# Created in stages; every resource is managed by Terraform, so `terraform destroy`
# cleans it all up in one shot.
#
#   Stage A: wildcard issuance — needs no cloud resources, this module is not even applied
#   Stage B: create_clb = true (default) — VPC + CLB + HTTPS listener + placeholder cert
#   Stage C: create_cvm = true and enable_cvm_role = true — adds one CVM on top
#
# See README.md for details
###############################################################################
