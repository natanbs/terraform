terraform {
  backend "s3" {
    bucket         = "${terraform.workspace}-terraform-state"
    region         = "eu-central-1"
    dynamodb_table = "CXTerraformStatelock"
    key            = "main/terraform-${terraform.workspace}.tfstate"
  }
}
