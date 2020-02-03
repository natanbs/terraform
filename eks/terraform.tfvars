profile = "cyberx"
vendor_name = "cyberx"
region = "eu-central-1"
bucket = "cyberx-terraform-state"
primary_domain = "cyberx.lab.io"
dynamodb_table = "TerraformFuseStatelock"
env = "dev"


cluster_version = "1.14"

private_subnets = ["172.31.48.0/20", "172.31.64.0/20", "172.31.80.0/20"]

public_subnets = ["172.31.0.0/20", "172.31.16.0/20", "172.31.32.0/20"]

# database_subnets = ["172.31.96.0/20", "172.31.112.0/20", "172.31.128.0/20"]
vpc_cidr_block = "172.31.0.0/16"

operators = [
  "itaior",
]