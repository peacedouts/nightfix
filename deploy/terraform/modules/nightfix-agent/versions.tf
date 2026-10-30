terraform {
  required_version = ">= 1.9" # validations that refer to other variables
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    http = {
      source  = "hashicorp/http"
      version = ">= 3.4"
    }
  }
}
