###############################################################################
# wecert 测试环境
#
# 分阶段创建，全部资源由 Terraform 管理，`terraform destroy` 一键清干净。
#
#   阶段 A：wildcard 签发 —— 不需要云资源，本模块都不用 apply
#   阶段 B：create_clb = true（默认）—— VPC + CLB + HTTPS 监听器 + 占位证书
#   阶段 C：create_cvm = true 且 enable_cvm_role = true —— 再加一台 CVM
#
# 详见 README.md
###############################################################################
