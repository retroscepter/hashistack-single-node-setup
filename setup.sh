#!/bin/bash

set -e

# Update package lists and install prerequisites
sudo apt update
sudo apt upgrade -y
sudo apt install -y wget curl gpg coreutils ca-certificates

# Add HashiCorp GPG key and repository
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update

# Install Nomad and Consul
sudo apt install -y nomad consul

# Install docker
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Get private IP
PRIVATE_IP=$(hostname -I | awk '{print $1}')

# Create Consul configuration directory
sudo mkdir -p /etc/consul.d
sudo chmod a+w /etc/consul.d

# Create Consul data directory
sudo mkdir -p /opt/consul/data
sudo chmod 777 /opt/consul/data

# Create Consul configuration file
cat <<EOF | sudo tee /etc/consul.d/consul.hcl
datacenter = "dc1"
data_dir = "/opt/consul/data"
log_level = "INFO"
server = true
bootstrap_expect = 1
bind_addr = "${PRIVATE_IP}"
client_addr = "0.0.0.0"
ui = true
EOF

# Create Consul service file
cat <<EOF | sudo tee /etc/systemd/system/consul.service
[Unit]
Description=Consul Agent
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill -HUP \$MAINPID
KillSignal=SIGTERM
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start Consul service
sudo systemctl daemon-reload
sudo systemctl enable consul
sudo systemctl start consul

# Create Nomad configuration directory
sudo mkdir -p /etc/nomad.d
sudo chmod a+w /etc/nomad.d

# Create Nomad data directory
sudo mkdir -p /opt/nomad/data
sudo chmod 777 /opt/nomad/data

# Create Nomad configuration file
cat <<EOF | sudo tee /etc/nomad.d/nomad.hcl
data_dir  = "/opt/nomad/data"
bind_addr = "0.0.0.0"

server {
  enabled          = true
  bootstrap_expect = 1
}

client {
  enabled       = true
  network_interface = "eth0"
  servers       = ["127.0.0.1:4647"]
}

consul {
  address = "${PRIVATE_IP}:8500"
}
EOF

# Create Nomad service file
cat <<EOF | sudo tee /etc/systemd/system/nomad.service
[Unit]
Description=Nomad Agent
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/nomad agent -config=/etc/nomad.d/
ExecReload=/bin/kill -HUP \$MAINPID
KillSignal=SIGINT
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start Nomad service
sudo systemctl daemon-reload
sudo systemctl enable nomad
sudo systemctl start nomad

# Open necessary firewall ports
sudo ufw allow ssh
sudo ufw allow 4646/tcp   # Nomad HTTP API
sudo ufw allow 8500/tcp   # Consul HTTP API
sudo ufw enable

echo "Access Nomad UI at http://${PRIVATE_IP}:4646"
echo "Access Consul UI at http://${PRIVATE_IP}:8500"
