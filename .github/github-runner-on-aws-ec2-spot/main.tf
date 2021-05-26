
variable "github_app_key_base64" {}
variable "github_app_id" {}
variable "github_app_client_id" {}
variable "github_app_client_secret" {}


locals {
  environment = "iroha1"
  aws_region  = "eu-central-1"
}

provider "aws" {
  region  = local.aws_region
}

module "vpc" {
  source = "git::https://github.com/philips-software/terraform-aws-vpc.git?ref=2.2.0"

  environment                = local.environment
  aws_region                 = local.aws_region
  create_private_hosted_zone = false
}

resource "random_password" "random" {
  length = 28
}

module "download-lambda" {
  # source = "philips-labs/github-runner/aws//modules/download-lambda"
  source = "git::https://github.com/philips-labs/terraform-aws-github-runner//modules/download-lambda?ref=v0.13.0"
  tag = "v0.13.0"  ## Must be a Git tag, usually with letter 'v'
}

module "runners" {
  # source  = "philips-labs/github-runner/aws"
  # version = "0.13.0"  ## version without letter 'v'
  source = "git::https://github.com/philips-labs/terraform-aws-github-runner?ref=v0.13.0"

  depends_on = [module.download-lambda]

  aws_region = local.aws_region
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  environment = local.environment
  tags = {
    Project = "iroha1"
  }

  github_app = {
    webhook_secret = random_password.random.result
    key_base64     = var.github_app_key_base64
    id             = var.github_app_id
    client_id      = var.github_app_client_id
    client_secret  = var.github_app_client_secret
  }

  runners_maximum_count = 10
  instance_type = "c5.2xlarge"

  webhook_lambda_zip                = "webhook.zip"
  runner_binaries_syncer_lambda_zip = "runner-binaries-syncer.zip"
  runners_lambda_zip                = "runners.zip"
  enable_organization_runners       = false  ## use organization or repository level runners
  enable_ssm_on_runners             = false  ## for debug purposes
  create_service_linked_role_spot   = true   ## if not need to create it manually
}


output "runners" {
  value = {
    lambda_syncer_name = module.runners.binaries_syncer.lambda.function_name
  }
}

output "webhook" {
  value = {
    secret   = random_password.random.result
    endpoint = module.runners.webhook.endpoint
  }
  sensitive = true  ## To show secrets `terraform output webhook`
}
