data "terraform_remote_state" "main" {
  backend = "s3"

  config {
    bucket         = "la-prod-tfstate"
    dynamodb_table = "TerraformStatelock"
    key            = "main/terraform.tfstate"
    profile        = "cyberx"
    region         = "eu-central-1"
  }
}