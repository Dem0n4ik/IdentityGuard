terraform {
  required_version = ">= 1.13, < 2.0"

  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.52"
    }
  }
}

variable "region" {
  type        = string
  description = "Region of the approved AWS staging account."
}

variable "account_id" {
  type        = string
  description = "Only this AWS account may be used by the provider."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Provide a twelve-digit AWS account ID."
  }
}

variable "admin_role_arn" {
  type        = string
  description = "Existing IAM role for administering the private EKS cluster."
}

variable "vpc_cidr" {
  type        = string
  description = "IPv4 VPC range with room for six subnets."
  default     = "10.84.0.0/16"
}

variable "kubernetes_version" {
  type        = string
  description = "An EKS-supported Kubernetes major.minor version for the chosen region."
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = {
      Project     = "IdentityGuard"
      Environment = "staging"
      ManagedBy   = "Terraform"
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  name = "identityguard-staging"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.6.1"

  name                    = local.name
  cidr                    = var.vpc_cidr
  azs                     = local.azs
  private_subnets         = [for index in range(3) : cidrsubnet(var.vpc_cidr, 4, index)]
  public_subnets          = [for index in range(3) : cidrsubnet(var.vpc_cidr, 4, index + 8)]
  enable_nat_gateway      = true
  one_nat_gateway_per_az  = true
  enable_dns_hostnames    = true
  map_public_ip_on_launch = false

  private_subnet_tags = { "kubernetes.io/role/internal-elb" = "1" }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "21.24.2"

  name                    = local.name
  kubernetes_version      = var.kubernetes_version
  endpoint_private_access = true
  endpoint_public_access  = false
  authentication_mode     = "API"
  deletion_protection     = true
  vpc_id                  = module.vpc.vpc_id
  subnet_ids              = module.vpc.private_subnets

  compute_config = {
    enabled    = true
    node_pools = ["general-purpose"]
  }

  access_entries = {
    staging_admin = {
      principal_arn = var.admin_role_arn
      policy_associations = {
        administration = {
          policy_arn   = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = { type = "cluster" }
        }
      }
    }
  }
}

resource "aws_ecr_repository" "console" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "image_repository" {
  value = aws_ecr_repository.console.repository_url
}
