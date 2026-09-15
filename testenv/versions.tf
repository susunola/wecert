terraform {
  required_version = ">= 1.5"

  required_providers {
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "~> 1.81"
    }
    # 只用来在 apply 时生成自签名占位证书，私钥不落盘。
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "tencentcloud" {
  region = var.region
  # 凭证从环境变量读取，不写进任何文件：
  #   TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY
}
