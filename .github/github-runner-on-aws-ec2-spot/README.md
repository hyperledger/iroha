# Terraform to configure AWS EC2 Spot as a GitHub runners
## Next way of appling in May 2021 (simplified)
I have slightly updated module `download-lambda`. And a way of using it. Now it could be used in `main.tf` of final terraform and usage code simplified up to one parameter - `tag`.

Now usage in `main.tf` looks like:
```terraform
module "download-lambda" {
  source = "../../modules/download-lambda"
  tag = "v0.13.0"  ## Must be a Git tag, usually with letter 'v'
}

module "runners" {
  # source  = "philips-labs/github-runner/aws"
  # version = "0.13.0"  ## version without letter 'v'
  source = "../.."

  depends_on = [module.download-lambda]

  ## .....................................
  ## .....................................
  ## .....................................
}
```
Commands:
```
terraform init
terraform apply -target module.download-lambda
terraform apply
```
Module `download-lambda` must be applied (lambdas must be downloaded) before configuring (applying) module "runners".
Without second line you will got an error.
> ```
> Call to function "filebase64sha256" failed: no file exists at runner-binaries-syncer.zip; this function works only with files that are distributed as part of the configuration source code, so if this file will be created by a resource in this configuration you must instead obtain this result from an attribute of that resource.

Sure, there is a way to solve that refering to:
* https://stackoverflow.com/a/57469070/3743145
* https://github.com/hashicorp/terraform-guides/blob/master/infrastructure-as-code/terraform-0.13-examples/module-depends-on/README.md

May be I will do that some time later...
