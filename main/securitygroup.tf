module "env_security_group"  {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 3.0"

  name        = "sg-${terraform.workspace}"

  description = "Security group for the environment"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "all-icmp"]
  egress_rules        = ["all-all"]
}
#module "sisense_security_group"  {
#  source  = "terraform-aws-modules/security-group/aws"
#  version = "~> 3.0"
#
#  vpc_id      = module.vpc.vpc_id
#
#  ingress_cidr_blocks = ["0.0.0.0/0"]
#  ingress_rules       = ["http-80-tcp", "all-icmp"]
#  egress_rules        = ["all-all"]
#}
#
#module "chronos_security_group"  {
#  source  = "terraform-aws-modules/security-group/aws"
#  version = "~> 3.0"
#
#  name        = "chronos-${var.env}-sg"
#  description = "Security group for chronos EC2 instance"
#  vpc_id      = module.vpc.vpc_id
#
#  ingress_cidr_blocks = ["0.0.0.0/0"]
#  ingress_rules       = ["http-80-tcp", "all-icmp"]
#  egress_rules        = ["all-all"]
#}
#
#module "rds_security_group"  {
#  source  = "terraform-aws-modules/security-group/aws"
#  version = "~> 3.0"
#
#  name        = "rds-${var.env}-sg"
#  description = "Security group for RDS instance"
#  vpc_id      = module.vpc.vpc_id
#
#  ingress_cidr_blocks = ["0.0.0.0/0"]
#  ingress_rules       = ["http-80-tcp", "all-icmp"]
#  ingress_with_cidr_blocks = [
#    {
#      rule        = "postgresql-tcp"
#      cidr_blocks = "37.142.39.186/32"
#    },
#    {
#      rule        = "postgresql-tcp"
#      cidr_blocks = "192.168.0.0/16"
#    },
#    {
#      rule        = "postgresql-tcp"
#      cidr_blocks = "10.212.143.192/28"
#    }
#  ]
#  egress_rules        = ["all-all"]
#}
