output "private_ip" {
  value = google_compute_instance.temporal.network_interface[0].network_ip
}

output "address" {
  value = "${google_compute_instance.temporal.network_interface[0].network_ip}:7233"
}
