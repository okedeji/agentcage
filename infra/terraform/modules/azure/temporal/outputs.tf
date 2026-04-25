output "private_ip" {
  value = azurerm_network_interface.temporal.private_ip_address
}

output "address" {
  value = "${azurerm_network_interface.temporal.private_ip_address}:7233"
}
