output "vpc_id" {
  value = aws_vpc.main.id
}

output "database_endpoint" {
  value = aws_db_instance.postgres.endpoint
}

output "database_name" {
  value = aws_db_instance.postgres.db_name
}

output "fleet_asg_name" {
  value = aws_autoscaling_group.fleet.name
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}
