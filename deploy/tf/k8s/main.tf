provider "aws" {
  region = "eu-west-1"
}

provider "aws" {
  region = "eu-west-2"
  alias = "eu_west_2"
}

provider "aws" {
  region = "eu-west-3"
  alias = "eu_west_3"
}

resource "aws_key_pair" "key_pair_1" {
  count = "${length(keys(var.ssh_key_pairs))}"
  key_name = "${element(keys(var.ssh_key_pairs), count.index)}"
  public_key = "${element(values(var.ssh_key_pairs), count.index)}"
}

resource "aws_key_pair" "key_pair_2" {
  count = "${length(keys(var.ssh_key_pairs))}"
  provider = "aws.eu_west_2"
  key_name = "${element(keys(var.ssh_key_pairs), count.index)}"
  public_key = "${element(values(var.ssh_key_pairs), count.index)}"
}

resource "aws_key_pair" "key_pair_3" {
  count = "${length(keys(var.ssh_key_pairs))}"
  provider = "aws.eu_west_3"
  key_name = "${element(keys(var.ssh_key_pairs), count.index)}"
  public_key = "${element(values(var.ssh_key_pairs), count.index)}"
}

module "eu_west_1" {
  source = "eu-west-1"
  instance_count_master = "${var.eu_west_1_instance_count_master}"
  instance_count_node = "${var.eu_west_1_instance_count_node}"
  b_vpc_id = "${module.eu_west_2.vpc_id}"
  c_vpc_id = "${module.eu_west_3.vpc_id}"
  b_vpc_cidr_block = "${module.eu_west_2.vpc_cidr_block}"
  c_vpc_cidr_block = "${module.eu_west_3.vpc_cidr_block}"
}

module "eu_west_2" {
  instance_count_master = "${var.eu_west_2_instance_count_master}"
  instance_count_node = "${var.eu_west_2_instance_count_node}"
  source = "eu-west-2"
  a_vpc_cidr_block = "${module.eu_west_1.vpc_cidr_block}"
  c_vpc_cidr_block = "${module.eu_west_3.vpc_cidr_block}"
  a_b_peering_id = "${module.eu_west_1.a_b_peering_id}"
  c_vpc_id = "${module.eu_west_3.vpc_id}"
}

module "eu_west_3" {
  instance_count_master = "${var.eu_west_3_instance_count_master}"
  instance_count_node = "${var.eu_west_3_instance_count_node}"
  source = "eu-west-3"
  a_c_peering_id = "${module.eu_west_1.a_c_peering_id}"
  b_c_peering_id = "${module.eu_west_2.b_c_peering_id}"
  a_vpc_cidr_block = "${module.eu_west_1.vpc_cidr_block}"
  b_vpc_cidr_block = "${module.eu_west_2.vpc_cidr_block}"
}