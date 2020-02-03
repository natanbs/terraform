provider "aws" {
  region  = "${var.region}"
  profile = "${var.profile}"
}

module "backend" {
  source = "../modules/backend"

  bootstrap      = 1
  operators      = "${var.operators}"
  bucket         = "${var.bucket}"
  dynamodb_table = "${var.dynamodb_table}"
  region         = "${var.region}"
}

# module "credstash-setup" {
#   source = "../../modules/credstash-setup"
#   enable_key_rotation = "true"
#   # db_table_name = "credstash-cred-store"
#   # create credstash reader IAM policy we can attach later to instances / roles (/ users ?)
#   create_reader_policy = "true"
#   # role alowd to update/edit credentaisl 
#   create_writer_policy = "true"
# }

# Create master key
# resource "aws_key_pair" "fuse-master-key" {
#   key_name   = "fuse-master-key"
#   public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCKcnXAtfF3fy2HutDFKKaUUpp05Fi/fzb2kqLTlo2I+x0unswiuN3SkKSykJmf+jqY/k+J75E35NIVpO/4rHI4f3vNBMuOFI4MtLS3YfN3TaqGKRVhHJ0xGGAFRnudYTyx6hUSsVIebWzH72mRU3xTOk96wkgQA339GbQp2sKY+k7yeQc6Bx/mkTIbNLmMZF33jzzRatlZbn32vF6A1t47I3Ljw4Zy6Nj/pZR4W7JUJaWoA8gdWi9cWwjvCr0yfUZR6MaCDGAUXFQzQ3hAK2msG0o4x6oN9O2Y0Ge5jccG4Eh7ysVMquu2vIid453PFQX6tP7YwVT3Avua0Pgz0iZ5 tf@fuse-master-key"
#   public_key = "${var.private_key}"
# }