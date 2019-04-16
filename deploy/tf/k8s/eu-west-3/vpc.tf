data "aws_availability_zones" "available" {}

resource "aws_vpc" "k8s_caliper_ci_vpc" {
  cidr_block = "10.4.0.0/16"
  enable_dns_hostnames = "true"
  tags {
    Name = "k8s-caliper-ci-vpc"
  }
}

resource "aws_subnet" "k8s_caliper_ci_subnets" {
  count = 3
  vpc_id     = "${aws_vpc.k8s_caliper_ci_vpc.id}"
  cidr_block = "${cidrsubnet(aws_vpc.k8s_caliper_ci_vpc.cidr_block, 2, count.index)}"
  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
  map_public_ip_on_launch = "true"
  tags {
    Name = "k8s-caliper-ci-${data.aws_availability_zones.available.names[count.index]}"
  }
}

resource "aws_internet_gateway" "k8s_caliper_ci_eu_west_3" {
  vpc_id = "${aws_vpc.k8s_caliper_ci_vpc.id}"
  tags {
    Name = "k8s-caliper-ci-gw"
  }
}

resource "aws_vpc_peering_connection_accepter" "eu_west_1_eu_west_3" {
  vpc_peering_connection_id = "${var.a_c_peering_id}"
  auto_accept = true
  tags = {
    Name = "k8s-caliper-ci-eu-west-1-eu-west-3"
  }
}

resource "aws_vpc_peering_connection_accepter" "eu_west_2_eu_west_3" {
  vpc_peering_connection_id = "${var.b_c_peering_id}"
  auto_accept = true
  tags = {
    Name = "k8s-caliper-ci-eu-west-2-eu-west-3"
  }
}

resource "aws_route_table" "k8s_caliper_ci_r3" {
  vpc_id = "${aws_vpc.k8s_caliper_ci_vpc.id}"
  route {
    cidr_block = "${var.a_vpc_cidr_block}"
    vpc_peering_connection_id = "${aws_vpc_peering_connection_accepter.eu_west_1_eu_west_3.id}"
  }
  route {
    cidr_block = "${var.b_vpc_cidr_block}"
    vpc_peering_connection_id = "${aws_vpc_peering_connection_accepter.eu_west_2_eu_west_3.id}"
  }
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.k8s_caliper_ci_eu_west_3.id}"
  }
}

resource "aws_main_route_table_association" "vpc_main" {
  vpc_id         = "${aws_vpc.k8s_caliper_ci_vpc.id}"
  route_table_id = "${aws_route_table.k8s_caliper_ci_r3.id}"
}
