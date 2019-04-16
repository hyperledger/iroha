output "vpc_id" {
  value = "${aws_vpc.k8s_caliper_ci_vpc.id}"
}
output "vpc_cidr_block" {
  value = "${aws_vpc.k8s_caliper_ci_vpc.cidr_block}"
}