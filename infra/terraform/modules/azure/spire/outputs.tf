output "private_ip" {
  value = azurerm_network_interface.spire.private_ip_address
}

output "server_address" {
  value = "${azurerm_network_interface.spire.private_ip_address}:8081"
}
