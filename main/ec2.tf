
# Create key-pair

module "keypair" {
  source = "mitchellh/dynamic-keys/aws"
  name   = "var.key_name"
  path   = "${path.root}/keys"
}

output "private_key_pem" {
  value = "${module.keypair.private_key_pem}"
}

module "chronos_ec2" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 2.0"

  instance_count              = "${var.instance_count}"
  key_name                    = "${module.keypair.key_name}"
  name                        = "chronos-${var.env}"
  ami                         = "${var.chronos_ami_id}"
  instance_type               = "${var.chronos_instance_type}"
  subnet_id                   = tolist(module.vpc.private_subnets)[0]
  vpc_security_group_ids      = [module.env_security_group.this_security_group_id]
  associate_public_ip_address = false
}

module "sisense_ec2" {
  source                      = "terraform-aws-modules/ec2-instance/aws"
  version                     = "~> 2.0"
  instance_count              = "${var.instance_count}"
  key_name                    = "${module.keypair.key_name}"
  name                        = "sisense-${var.env}"
  ami                         = "${var.sisense_ami_id}"
  instance_type               = "${var.sisense_instance_type}"
  subnet_id                   = tolist(module.vpc.private_subnets)[0]
  vpc_security_group_ids      = [module.env_security_group.this_security_group_id]
  associate_public_ip_address = false
}

# resource "aws_volume_attachment" "chronos_ec2_vol" {
#   count = "${var.instance_count}"

#   device_name = "/dev/sdh"
#   volume_id   = aws_ebs_volume.chronos_ebc_vol[count.index].id
#   instance_id = module.chronos_ec2.id[count.index]
# }

# resource "aws_ebs_volume" "chronos_ebc_vol" {
#   count = "${var.instance_count}"

#   availability_zone = module.chronos_ec2.availability_zone[count.index]
#   size              = 1
# }
# resource "aws_volume_attachment" "sisense_ec2_vol" {
#   count = "${var.instance_count}"

#   device_name = "/dev/sdh"
#   volume_id   = aws_ebs_volume.sisense_ebc_vol[count.index].id
#   instance_id = module.chronos_ec2.id[count.index]
# }

# resource "aws_ebs_volume" "sisense_ebc_vol" {
#   count = "${var.instance_count}"

#   availability_zone = module.sisense_ec2.availability_zone[count.index]
#   size              = 1
# }
