variable "env" {
  default = "dev"
}

variable "region" {
  description = "The AWS region to use"
}

variable "vendor_name" {
  description = "Usually the org/company name"
  default     = "Cyberx"
}

variable "profile" {
  description = "The AWS profile to use"
}
variable "instance_count" {
  description = "Number of instance"
}
variable "bucket" {
  description = "Terraform state s3 bucket"
}

variable "dynamodb_table" {
  description = "Terraform statelock DynamoDB table"
}

variable "operators" {
  # type        = "list"
  description = "List of IAM users to grant access to state"
}

variable "primary_domain" {
  description = "Domain name to use"
}

variable "vpc_cidr_block" {
  # type = "string"
}

# variable "private_subnets" {
#   type = list(string)
# }

# variable "public_subnets" {
#   type = list(string)
# }

variable "cluster_version" {}

variable "chronos_instance_type" {}
variable "sisense_instance_type" {}
variable "chronos_ami_id" {}
variable "sisense_ami_id" {}
variable "profiling_vpc_id" {}
variable "profiling_vpc_cdir" {}
variable "db_engine" {}
variable "db_version" {}
variable "db_name" {}
variable "db_instance_type" {}
variable "db_user" {}
variable "db_major_engine_version" {}
variable "db_family" {}
variable "key_name" {}
variable "WORKSPACE" {}
variable "lb-description" {}
variable "server_audit_file_rotation" {}
variable "deletion_protection" {}
variable "apply_immediately" {}
variable "backup_retention_period" {}
