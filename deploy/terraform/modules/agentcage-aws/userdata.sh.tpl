#!/bin/bash
set -euo pipefail

# Variables from Terraform template
NOMAD_VERSION="${nomad_version}"
SPIRE_VERSION="${spire_version}"
FALCO_VERSION="${falco_version}"
AGENTCAGE_VERSION="${agentcage_version}"

# System setup
yum update -y
yum install -y docker containerd iptables jq curl wget

# Enable KVM (required for Firecracker)
modprobe kvm
modprobe kvm_intel || modprobe kvm_amd
chmod 666 /dev/kvm

# Install Firecracker
ARCH=$(uname -m)
curl -sSL "https://github.com/firecracker-microvm/firecracker/releases/download/v1.6.0/firecracker-v1.6.0-$${ARCH}.tgz" | tar -xz
mv release-v1.6.0-$${ARCH}/firecracker-v1.6.0-$${ARCH} /usr/local/bin/firecracker
mv release-v1.6.0-$${ARCH}/jailer-v1.6.0-$${ARCH} /usr/local/bin/jailer
chmod +x /usr/local/bin/firecracker /usr/local/bin/jailer

# Install Nomad
curl -sSL "https://releases.hashicorp.com/nomad/$${NOMAD_VERSION}/nomad_$${NOMAD_VERSION}_linux_amd64.zip" -o nomad.zip
unzip nomad.zip -d /usr/local/bin/
rm nomad.zip

# Configure Nomad client
mkdir -p /etc/nomad.d /opt/nomad/data
cat > /etc/nomad.d/client.hcl <<NOMADEOF
datacenter = "dc1"
data_dir   = "/opt/nomad/data"

client {
  enabled = true

  host_volume "firecracker" {
    path      = "/var/lib/firecracker"
    read_only = false
  }
}

plugin "firecracker-task-driver" {
  config {
    firecracker_path = "/usr/local/bin/firecracker"
    jailer_path      = "/usr/local/bin/jailer"
  }
}
NOMADEOF

systemctl enable nomad
systemctl start nomad

# Install SPIRE agent
curl -sSL "https://github.com/spiffe/spire/releases/download/v$${SPIRE_VERSION}/spire-$${SPIRE_VERSION}-linux-amd64-musl.tar.gz" | tar -xz
mv spire-$${SPIRE_VERSION}/bin/spire-agent /usr/local/bin/
mkdir -p /etc/spire /opt/spire/agent/data

cat > /etc/spire/agent.conf <<SPIREEOF
agent {
  data_dir = "/opt/spire/agent/data"
  log_level = "INFO"
  server_address = "spire-server"
  server_port = "8081"
  socket_path = "/run/spire/agent.sock"
  trust_domain = "agentcage.local"
}

plugins {
  NodeAttestor "aws_iid" {
    plugin_data {}
  }
  KeyManager "disk" {
    plugin_data {
      directory = "/opt/spire/agent/data"
    }
  }
  WorkloadAttestor "unix" {
    plugin_data {}
  }
}
SPIREEOF

systemctl enable spire-agent
systemctl start spire-agent

# Install Falco
rpm --import https://falco.org/repo/falcosecurity-packages.asc
curl -s -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
yum install -y "falco-$${FALCO_VERSION}"

# Configure Falco with eBPF probe
mkdir -p /etc/falco/rules.d
cat > /etc/falco/falco.yaml <<FALCOEOF
rules_file:
  - /etc/falco/rules.d/*.yaml
json_output: true
grpc:
  enabled: true
  bind_address: "unix:///run/falco/falco.sock"
  threadiness: 4
grpc_output:
  enabled: true
FALCOEOF

systemctl enable falco
systemctl start falco

# Create agentcage directories
mkdir -p /var/lib/firecracker/images
mkdir -p /var/lib/agentcage/cages
mkdir -p /run/spire
mkdir -p /run/falco

echo "agentcage host bootstrap complete"
