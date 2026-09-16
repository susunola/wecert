terraform {
  required_version = ">= 1.5"

  required_providers {
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "~> 1.81"
    }
    # Used only to generate the self-signed placeholder certificate at apply time;
    # the private key never touches disk.
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "tencentcloud" {
  region = var.region
  # Credentials are read from the environment and written to no file:
  #   TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY
}
