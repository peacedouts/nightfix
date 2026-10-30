terraform {
  # 1.11+ for write-only arguments: the app's database password never enters state.
  required_version = ">= 1.12"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.90"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }
}
