output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "public_subnet_id" {
  description = "First public subnet (convenience for single-instance modules)"
  value       = aws_subnet.public[0].id
}

output "private_subnet_id" {
  description = "First private subnet (convenience for single-instance modules)"
  value       = aws_subnet.private[0].id
}
