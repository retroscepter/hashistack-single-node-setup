#!/bin/bash

set -e

# Update package lists and install prerequisites
sudo apt update
sudo apt upgrade -y
sudo apt install -y wget curl gpg coreutils ca-certificates jq

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

if [ -z "${PRIVATE_IP}" ]; then
  echo "Failed to get private IP"
  exit 1
fi

CONSUL_CONFIG_DIR="/etc/consul.d"
CONSUL_DATA_DIR="/opt/consul/data"

# Create Consul configuration directory
sudo mkdir -p ${CONSUL_CONFIG_DIR}
sudo chmod a+w ${CONSUL_CONFIG_DIR}

# Create Consul data directory
sudo mkdir -p ${CONSUL_DATA_DIR}
sudo chmod 777 ${CONSUL_DATA_DIR}

# Create Consul configuration file
cat <<EOF | sudo tee ${CONSUL_CONFIG_DIR}/consul.hcl > /dev/null
datacenter = "dc1"
data_dir = "${CONSUL_DATA_DIR}"

bind_addr = "${PRIVATE_IP}"
client_addr = "0.0.0.0"

log_level = "INFO"

server = true
bootstrap = true

ui = true

acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
}
EOF

# Create Consul service file
cat <<EOF | sudo tee /etc/systemd/system/consul.service > /dev/null
[Unit]
Description=Consul Agent
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/consul agent -config-dir=${CONSUL_CONFIG_DIR}
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

# Wait for Consul to be reachable
echo "Waiting for Consul to be reachable..."
while ! netcat -z 127.0.0.1 8500 > /dev/null 2>&1; do
  sleep 1
done

# Wait for Consul cluster leader to be elected
echo "Waiting for Consul cluster leader to be elected..."
while ! consul kv get -recurse / > /dev/null 2>&1; do
  sleep 1
done

# Bootstrap Consul ACL and get bootstrap token
CONSUL_SECRET_ID=$(consul acl bootstrap -format=json | jq -r '.SecretID')

if [ -z "${CONSUL_SECRET_ID}" ]; then
  echo "Failed to bootstrap Consul ACL"
  exit 1
fi

NOMAD_CONFIG_DIR="/etc/nomad.d"
NOMAD_DATA_DIR="/opt/nomad/data"

# Create Nomad configuration directory
sudo mkdir -p ${NOMAD_CONFIG_DIR}
sudo chmod a+w ${NOMAD_CONFIG_DIR}

# Create Nomad data directory
sudo mkdir -p ${NOMAD_DATA_DIR}
sudo chmod 777 ${NOMAD_DATA_DIR}

# Create Nomad configuration file
cat <<EOF | sudo tee ${NOMAD_CONFIG_DIR}/nomad.hcl > /dev/null
data_dir  = "${NOMAD_DATA_DIR}"
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
  token = "${CONSUL_SECRET_ID}"
}

acl = {
  enabled = true
}
EOF

# Create Nomad service file
cat <<EOF | sudo tee /etc/systemd/system/nomad.service > /dev/null
[Unit]
Description=Nomad Agent
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/nomad agent -config=${NOMAD_CONFIG_DIR}/nomad.hcl
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

# Wait for Nomad to be reachable
echo "Waiting for Nomad to be reachable..."
while ! netcat -z 127.0.0.1 4646 > /dev/null 2>&1; do
  sleep 1
done

# Bootstrap Nomad ACL and get bootstrap token
NOMAD_SECRET_ID=$(nomad acl bootstrap -json | jq -r '.SecretID')

if [ -z "${NOMAD_SECRET_ID}" ]; then
  echo "Failed to bootstrap Nomad ACL"
  exit 1
fi

# Open necessary firewall ports
sudo ufw allow ssh
sudo ufw allow 4646/tcp
sudo ufw allow 8500/tcp
sudo ufw --force enable

echo " "
echo "----------------------------------------"
echo "Setup complete!"
echo "----------------------------------------"
echo " "
echo "Access Nomad UI at http://${PRIVATE_IP}:4646"
echo "Access Consul UI at http://${PRIVATE_IP}:8500"
echo " "
echo "----------------------------------------"
echo " "
echo "WARNING: Store these tokens in a secure location, you will not be able to access them again!"
echo " "
echo "Nomad bootstrap token: ${NOMAD_SECRET_ID}"
echo "Consul bootstrap token: ${CONSUL_SECRET_ID}"
echo " "
echo "----------------------------------------"
echo " "
echo "Nomad configuration: ${NOMAD_CONFIG_DIR}/nomad.hcl"
echo "Consul configuration: ${CONSUL_CONFIG_DIR}/consul.hcl"
echo " "
echo "----------------------------------------"
