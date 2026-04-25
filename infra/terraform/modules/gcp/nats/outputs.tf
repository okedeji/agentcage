output "private_ip" {
  value = google_compute_instance.nats.network_interface[0].network_ip
}

output "connection_url" {
  value = "nats://${google_compute_instance.nats.network_interface[0].network_ip}:4222"
}
