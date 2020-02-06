terraform {
  backend "s3" {
    bucket         = "cx-terraform-state"
    region         = "eu-central-1"
    dynamodb_table = "CXTerraformStatelock"
    key            = "main/terraform-cx.tfstate"
  }
}
