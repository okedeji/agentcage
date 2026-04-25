output "instance_group" {
  value = google_compute_instance_group_manager.nomad_server.instance_group
}

output "firewall_name" {
  value = google_compute_firewall.nomad.name
}
