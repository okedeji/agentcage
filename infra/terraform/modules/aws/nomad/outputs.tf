output "server_asg_name" {
  value = aws_autoscaling_group.nomad_server.name
}

output "security_group_id" {
  value = aws_security_group.nomad.id
}
