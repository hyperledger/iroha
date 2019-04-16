output "vpc_id" {
  value = "${aws_vpc.k8s_caliper_ci_vpc.id}"
}
output "b_c_peering_id" {
  value = "${aws_vpc_peering_connection.eu_west_2_eu_west_3.id}"
}

output "vpc_cidr_block" {
  value = "${aws_vpc.k8s_caliper_ci_vpc.cidr_block}"
}
