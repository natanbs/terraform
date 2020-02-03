terraform {
  backend "s3" {
    bucket = "cyberx-terraform-state"
    region = "eu-central-1"
    dynamodb_table = "TerraformFuseStatelock"
    key = "eks/terraform.tfstate"
  }
}

