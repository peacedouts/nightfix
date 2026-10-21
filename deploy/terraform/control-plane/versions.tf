terraform {
  # 1.11+ for write-only arguments: the app's database password never enters state.
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.90"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.52"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }

  # Configure with: terraform init -backend-config=backend.hcl
  # (bucket, key, region, use_lockfile = true). See ../README.md.
  backend "s3" {}
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      app         = "nightfix"
      environment = var.environment
      managed_by  = "terraform"
    }
  }
}

# Reads CLOUDFLARE_API_TOKEN from the environment: a token scoped to
# Zone → DNS → Edit on the one zone.
provider "cloudflare" {}
