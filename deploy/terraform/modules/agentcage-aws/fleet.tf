resource "aws_launch_template" "cage_host" {
  name_prefix   = "agentcage-host-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      fleet_pool = "provisioning"
    })
  }

  user_data = base64encode(templatefile("${path.module}/userdata.sh.tpl", {
    nomad_version     = "1.7.3"
    spire_version     = "1.9.0"
    falco_version     = "0.37.0"
    agentcage_version = var.agentcage_version
  }))
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_autoscaling_group" "fleet" {
  name                = "agentcage-fleet-${var.environment}"
  min_size            = var.fleet_min_hosts
  max_size            = var.fleet_max_hosts
  desired_capacity    = var.fleet_min_hosts
  vpc_zone_identifier = aws_subnet.private[*].id

  launch_template {
    id      = aws_launch_template.cage_host.id
    version = "$Latest"
  }

  tag {
    key                 = "agentcage_version"
    value               = var.agentcage_version
    propagate_at_launch = true
  }

  tag {
    key                 = "environment"
    value               = var.environment
    propagate_at_launch = true
  }
}
