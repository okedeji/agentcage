output "private_ip" {
  value = azurerm_network_interface.nats.private_ip_address
}

output "connection_url" {
  value = "nats://${azurerm_network_interface.nats.private_ip_address}:4222"
}
