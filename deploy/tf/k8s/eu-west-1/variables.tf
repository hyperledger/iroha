data "aws_ami" "ubuntu" {
  most_recent = true
  owners = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

variable "b_vpc_id" {}
variable "b_vpc_cidr_block" {}
variable "c_vpc_id" {}
variable "c_vpc_cidr_block" {}

variable "instance_count_master" {
  default = 1
}

variable "instance_count_node" {
  default = 0
}

variable "instance_type" {
  default = "c5.large"
}

variable "tags" {
  default = {
    Name = "terraform-managed-instance",
    Type = "k8s_caliper_ci_node"
    kubespray-role = "etcd",
    kubespray-role = "kube-master"
  }
}