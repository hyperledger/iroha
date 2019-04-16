resource "aws_security_group" "allow_some_traffic" {
  name        = "ssh_internal"
  description = "SSH plus internal"
  vpc_id      = "${aws_vpc.k8s_caliper_ci_vpc.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    #cidr_blocks = ["10.3.0.0/16", "10.4.0.0/16"]
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "allow_internal_vpc" {
  name        = "allow_vpc"
  description = "Allow all intra vpc traffic"
  vpc_id      = "${aws_vpc.k8s_caliper_ci_vpc.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self = "true"
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    self = "true"
  }
}

module "ec2_k8s_caliper_ci_master" {
  source = "terraform-aws-modules/ec2-instance/aws"

  name           = "k8s_caliper_ci"
  instance_count = "${var.instance_count_master}"

  ami                    = "${data.aws_ami.ubuntu.id}"
  instance_type          = "${var.instance_type}"
  key_name               = "example"
  vpc_security_group_ids = ["${aws_security_group.allow_some_traffic.id}", "${aws_security_group.allow_internal_vpc.id}"]
  subnet_id              = "${element(aws_subnet.k8s_caliper_ci_subnets.*.id, 0)}"
  associate_public_ip_address = "true"
  tags = {
    Name = "terraform-managed-instance",
    Type = "k8s_caliper_ci_node",
    kubespray-role = "kube-master, etcd"
  }
}

module "ec2_k8s_caliper_ci_node" {
  source = "terraform-aws-modules/ec2-instance/aws"

  name           = "k8s_caliper_ci"
  instance_count = "${var.instance_count_node}"

  ami                    = "${data.aws_ami.ubuntu.id}"
  instance_type          = "${var.instance_type}"
  key_name               = "example"
  vpc_security_group_ids = ["${aws_security_group.allow_some_traffic.id}", "${aws_security_group.allow_internal_vpc.id}"]
  subnet_id              = "${element(aws_subnet.k8s_caliper_ci_subnets.*.id, 0)}"
  associate_public_ip_address = "true"
  tags = {
    Name = "terraform-managed-instance",
    Type = "k8s_caliper_ci_node",
    kubespray-role = "kube-node, etcd"
  }
}