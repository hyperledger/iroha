variable "ssh_key_pairs" {
  default = {
    example = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCy22zks6tNf+XfLG2RjwCHRx2ESBsilXlcfmnOEUDLSDOw+vyHPdO4QR5soyVBP7AQ5OiiQId2UTIVdWxr4RgmZPYjWyb0h8lk9EL1dSmBj9k/QcPHMqrsP/BFLJFF3ZmlT6xyQEF3Om+dLRMfjH2jelkLBcL18btK6DeaINQOvHCw2xCILye2iMw3/LVHVjnsqWW+IYG41mmxsghSYNyRDoE5fbAPV8kaw/zMuCaZcQWRHkiqnCfGx31hcUP3EV1YaJWvLeoJlwfe67Mr0RzefF413hOuQJNdKVbYkBcO/IIH3RtJyydwl+GSn1qmeShfmkGaXZCHYimGjiC5jJoN"
  }
}

variable "eu_west_1_instance_count_master" {
  default = 1
}

variable "eu_west_1_instance_count_node" {
  default = 0
}

variable "eu_west_2_instance_count_master" {
  default = 0
}

variable "eu_west_2_instance_count_node" {
  default = 1
}

variable "eu_west_3_instance_count_master" {
  default = 0
}

variable "eu_west_3_instance_count_node" {
  default = 1
}