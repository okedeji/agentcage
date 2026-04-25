output "private_ip" {
  value = google_compute_instance.spire_server.network_interface[0].network_ip
}

output "server_address" {
  value = "${google_compute_instance.spire_server.network_interface[0].network_ip}:8081"
}
