terraform {
  backend "s3" {
    bucket         = "cx-terraform-state"
    region         = "eu-central-1"
    dynamodb_table = "NatanTerraformStatelock_test"
    key            = "main/terraform${var.env}.tfstate"
  }
}
