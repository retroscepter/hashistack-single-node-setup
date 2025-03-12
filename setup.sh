#!/bin/bash

set -e

CONSUL_PORT=8500
CONSUL_CONFIG_DIR="/etc/consul.d"
CONSUL_DATA_DIR="/opt/consul/data"

NOMAD_PORT=4646
NOMAD_CONFIG_DIR="/etc/nomad.d"
NOMAD_DATA_DIR="/opt/nomad/data"

REGISTRY_VERSION="2.8.3"
REGISTRY_PORT=5000
REGISTRY_CONFIG_DIR="/etc/registry"
REGISTRY_DATA_DIR="/opt/registry/data"

TRAEFIK_VERSION="3.3.4"
TRAEFIK_CONFIG_DIR="/etc/traefik"
TRAEFIK_LOG_DIR="/var/log/traefik"

# Get private IP
PRIVATE_IP=$(hostname -I | awk '{print $1}')

if [ -z "${PRIVATE_IP}" ]; then
  echo "Failed to get private IP"
  exit 1
fi

read -p "LetsEncrypt email: " LETSENCRYPT_EMAIL
read -p "Nomad dashboard host: " NOMAD_DASHBOARD_HOST
read -p "Consul dashboard host: " CONSUL_DASHBOARD_HOST
read -p "Traefik dashboard host: " TRAEFIK_DASHBOARD_HOST
read -p "Traefik dashboard username: " TRAEFIK_DASHBOARD_USER
read -sp "Traefik dashboard password: " TRAEFIK_DASHBOARD_PASS
echo
read -p "Docker registry host: " DOCKER_REGISTRY_HOST
read -p "Docker registry username: " DOCKER_REGISTRY_USER
read -sp "Docker registry password: " DOCKER_REGISTRY_PASS
echo

# Update package lists and install prerequisites
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y wget curl gpg coreutils ca-certificates jq apache2-utils

# Add HashiCorp GPG key and repository
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update

# Install Nomad and Consul
sudo apt-get install -y nomad consul

# Install Docker
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Install Registry
mkdir -p ./registry
wget -O ./registry/${REGISTRY_VERSION}.tar.gz https://github.com/distribution/distribution/releases/download/v${REGISTRY_VERSION}/registry_${REGISTRY_VERSION}_linux_amd64.tar.gz
tar -xzvf ./registry/${REGISTRY_VERSION}.tar.gz -C ./registry
sudo chmod +x ./registry/registry
sudo mv ./registry/registry /usr/bin/
rm -rf ./registry

# Install Traefik
mkdir -p ./traefik
wget -O ./traefik/${TRAEFIK_VERSION}.tar.gz https://github.com/traefik/traefik/releases/download/v${TRAEFIK_VERSION}/traefik_v${TRAEFIK_VERSION}_linux_amd64.tar.gz
tar -xzvf ./traefik/${TRAEFIK_VERSION}.tar.gz -C ./traefik
sudo chmod +x ./traefik/traefik
sudo mv ./traefik/traefik /usr/bin/
rm -rf ./traefik

# Disable systemd-resolved
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

# Create custom resolved.conf file
cat <<EOF | sudo tee /etc/systemd/resolved.conf > /dev/null
# This file is managed by man:systemd-resolved(8). Do not edit.
#
# This is a dynamic resolv.conf file for connecting local clients directly to
# all known uplink DNS servers. This file lists all configured search domains.
#
# Third party programs must not access this file directly, but only through the
# symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a different way,
# replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

# Docker bridge ip
nameserver 172.17.0.1
nameserver 127.0.0.1
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

# Create custom resolv.conf file
cat <<EOF | sudo tee /etc/resolv.conf > /dev/null
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See resolved.conf(5) for details

[Resolve]
DNS=127.0.0.1
Domains=~consul
#FallbackDNS=
#Domains=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
#DNSOverTLS=no
#Cache=no-negative
DNSStubListener=yes
#ReadEtcHosts=yes
EOF

# Create symlink to systemd-resolved
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

# Create Consul configuration directory
sudo mkdir -p ${CONSUL_CONFIG_DIR}
sudo chmod a+w ${CONSUL_CONFIG_DIR}

# Create Consul data directory
sudo mkdir -p ${CONSUL_DATA_DIR}
sudo chmod 777 ${CONSUL_DATA_DIR}

# Create Consul configuration file
cat <<EOF | sudo tee ${CONSUL_CONFIG_DIR}/consul.hcl > /dev/null
datacenter = "dc1"

log_level = "INFO"

data_dir = "${CONSUL_DATA_DIR}"

bind_addr = "${PRIVATE_IP}"
client_addr = "0.0.0.0"

ports {
  dns = 53
}

recursors = [ "8.8.8.8", "8.8.4.4" ]

server = true
ui = true

bootstrap = true

acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true

  tokens {
    dns = "CONSUL_DNS_SECRET_ID"
  }
}
EOF

# Create Consul service file
cat <<EOF | sudo tee /etc/systemd/system/consul.service > /dev/null
[Unit]
Description=Consul Agent
Requires=network-online.target
After=network-online.target

[Service]
Environment=CONSUL_ALLOW_PRIVILEGED_PORTS=true
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
while ! netcat -z 127.0.0.1 ${CONSUL_PORT} > /dev/null 2>&1; do
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

echo ${CONSUL_SECRET_ID} >> ./consul-bootstrap-token.txt

export CONSUL_HTTP_TOKEN=${CONSUL_SECRET_ID}

# Create Consul DNS token
CONSUL_DNS_SECRET_ID=$(consul acl token create -description "DNS Token" -format json -templated-policy "builtin/dns" | jq -r '.SecretID')

if [ -z "${CONSUL_DNS_SECRET_ID}" ]; then
  echo "Failed to create Consul DNS token"
  exit 1
fi

sudo sed -i "s/CONSUL_DNS_SECRET_ID/${CONSUL_DNS_SECRET_ID}/g" ${CONSUL_CONFIG_DIR}/consul.hcl

sudo systemctl restart consul

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
  address = "${PRIVATE_IP}:${CONSUL_PORT}"
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
while ! netcat -z 127.0.0.1 ${NOMAD_PORT} > /dev/null 2>&1; do
  sleep 1
done

# Bootstrap Nomad ACL and get bootstrap token
NOMAD_SECRET_ID=$(nomad acl bootstrap -json | jq -r '.SecretID')

if [ -z "${NOMAD_SECRET_ID}" ]; then
  echo "Failed to bootstrap Nomad ACL"
  exit 1
fi

echo ${NOMAD_SECRET_ID} >> ./nomad-bootstrap-token.txt

# Create Docker registry user
sudo useradd \
  -U \
  --no-create-home \
  --shell /bin/false \
  --system \
  docker-registry

# Create Docker registry directories and set permissions
sudo mkdir -p ${REGISTRY_CONFIG_DIR}
sudo chmod 755 ${REGISTRY_CONFIG_DIR}
sudo chown -R docker-registry:docker-registry ${REGISTRY_CONFIG_DIR}
sudo mkdir -p ${REGISTRY_DATA_DIR}
sudo chmod 755 ${REGISTRY_DATA_DIR}
sudo chown -R docker-registry:docker-registry ${REGISTRY_DATA_DIR}

# Create Docker registry config file
cat <<EOF | sudo tee ${REGISTRY_CONFIG_DIR}/registry.yml > /dev/null
version: 0.1
log:
  fields:
    service: registry
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: ${REGISTRY_DATA_DIR}
http:
  addr: 0.0.0.0:${REGISTRY_PORT}
  headers:
    X-Content-Type-Options: [nosniff]
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
EOF

# Create Docker registry service file
cat <<EOF | sudo tee /etc/systemd/system/docker-registry.service > /dev/null
[Unit]
Description=Distribution Docker Registry
After=network.target

[Service]
Type=simple
User=docker-registry
Group=docker-registry
ExecStart=/usr/bin/registry serve ${REGISTRY_CONFIG_DIR}/registry.yml

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start Docker registry service
sudo systemctl daemon-reload
sudo systemctl enable docker-registry
sudo systemctl start docker-registry

# Wait for Docker registry to be reachable
echo "Waiting for Docker registry to be reachable..."
while ! netcat -z 127.0.0.1 ${REGISTRY_PORT} > /dev/null 2>&1; do
  sleep 1
done

# Create Traefik user
sudo useradd \
  -U \
  --no-create-home \
  --shell /bin/false \
  --system \
  traefik

# Create Traefik directories and set permissions
sudo mkdir -p ${TRAEFIK_CONFIG_DIR}
sudo chmod 755 ${TRAEFIK_CONFIG_DIR}
sudo chown -R traefik:traefik ${TRAEFIK_CONFIG_DIR}
sudo mkdir -p ${TRAEFIK_LOG_DIR}
sudo chmod 755 ${TRAEFIK_LOG_DIR}
sudo chown -R traefik:traefik ${TRAEFIK_LOG_DIR}

# Create Traefik config file
cat <<EOF | sudo tee ${TRAEFIK_CONFIG_DIR}/traefik.yml > /dev/null
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"

providers:
  file:
    filename: ${TRAEFIK_CONFIG_DIR}/routes.yml
  consulCatalog:
    endpoint:
      address: "127.0.0.1:${CONSUL_PORT}"
      token: "${CONSUL_SECRET_ID}"
    exposedByDefault: false

certificatesResolvers:
  letsencrypt:
    acme:
      email: "${LETSENCRYPT_EMAIL}"
      storage: ${TRAEFIK_CONFIG_DIR}/acme.json
      httpChallenge:
        entryPoint: web

api:
  dashboard: true

accessLog:
  filePath: ${TRAEFIK_LOG_DIR}/access.log
  fields:
    headers:
      names:
        User-Agent: keep

log:
  filePath: ${TRAEFIK_LOG_DIR}/traefik.log
  level: DEBUG
EOF

# Create Traefik routes.yml config
cat <<EOF | sudo tee ${TRAEFIK_CONFIG_DIR}/routes.yml > /dev/null
http:
  routers:
    dashboard:
      rule: Host(\`${TRAEFIK_DASHBOARD_HOST}\`)
      tls:
        certResolver: letsencrypt
      service: api@internal
      middlewares:
        - dashboard-auth
    docker-registry:
      rule: Host(\`${DOCKER_REGISTRY_HOST}\`)
      tls:
        certResolver: letsencrypt
      service: docker-registry
      middlewares:
        - docker-registry-auth
    nomad:
      rule: Host(\`${NOMAD_DASHBOARD_HOST}\`)
      tls:
        certResolver: letsencrypt
      service: nomad
    consul:
      rule: Host(\`${CONSUL_DASHBOARD_HOST}\`)
      tls:
        certResolver: letsencrypt
      service: consul
  services:
    nomad:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:${NOMAD_PORT}/"
    consul:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:${CONSUL_PORT}/"
    docker-registry:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:${REGISTRY_PORT}/"
  middlewares:
    dashboard-auth:
      basicAuth:
        usersFile: ${TRAEFIK_CONFIG_DIR}/dashboard-users
    docker-registry-auth:
      basicAuth:
        usersFile: ${TRAEFIK_CONFIG_DIR}/docker-registry-users
    response-compress:
      compress: {}
EOF

# Hash Traefik dashboard password and write to file
hashed_password=$(htpasswd -bnBC 10 "" "${TRAEFIK_DASHBOARD_PASS}" | tr -d ':\n')
echo "${TRAEFIK_DASHBOARD_USER}:${hashed_password}" | sudo tee ${TRAEFIK_CONFIG_DIR}/dashboard-users > /dev/null

# Hash Docker registry password and write to file
hashed_password=$(htpasswd -bnBC 10 "" "${DOCKER_REGISTRY_PASS}" | tr -d ':\n')
echo "${DOCKER_REGISTRY_USER}:${hashed_password}" | sudo tee ${TRAEFIK_CONFIG_DIR}/docker-registry-users > /dev/null

# Create Traefik service file
cat <<EOF | sudo tee /etc/systemd/system/traefik.service > /dev/null
[Unit]
Description="Traefik Proxy"
Documentation=https://doc.traefik.io/traefik/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=${TRAEFIK_CONFIG_DIR}/traefik.yml

[Service]
User=traefik
Group=traefik
ExecStart=/usr/bin/traefik --configFile=${TRAEFIK_CONFIG_DIR}/traefik.yml
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Open necessary firewall ports
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw --force enable

# Reload systemd and start Traefik service
sudo systemctl daemon-reload
sudo systemctl enable traefik
sudo systemctl start traefik

# Wait for Traefik HTTP to be reachable
echo "Waiting for Traefik HTTP to be reachable..."
while ! netcat -z 127.0.0.1 80 > /dev/null 2>&1; do
  sleep 1
done

# Wait for Traefik HTTPS to be reachable
echo "Waiting for Traefik HTTPS to be reachable..."
while ! netcat -z 127.0.0.1 443 > /dev/null 2>&1; do
  sleep 1
done

# Wait for Docker registry to be reachable over custom host
echo "Waiting for Docker registry to be reachable on the public internet..."
while ! curl -u ${DOCKER_REGISTRY_USER}:${DOCKER_REGISTRY_PASS} https://${DOCKER_REGISTRY_HOST}/ > /dev/null 2>&1; do
  sleep 1
done

# Login to Docker registry
echo "Logging in to Docker registry..."
docker login ${DOCKER_REGISTRY_HOST} -u ${DOCKER_REGISTRY_USER} --password-stdin <<< ${DOCKER_REGISTRY_PASS}

echo " "
echo "----------------------------------------"
echo "Setup complete!"
echo "----------------------------------------"
echo " "
echo "Nomad UI: https://${NOMAD_DASHBOARD_HOST}"
echo "Consul UI: https://${CONSUL_DASHBOARD_HOST}"
echo "Traefik UI: https://${TRAEFIK_DASHBOARD_HOST}"
echo "Docker registry: ${DOCKER_REGISTRY_HOST}"
echo " "
echo "----------------------------------------"
echo " "
echo "WARNING: Store these secrets in a secure location, you will not be able to access them again!"
echo " "
echo "Nomad bootstrap token: ${NOMAD_SECRET_ID}"
echo "Consul bootstrap token: ${CONSUL_SECRET_ID}"
echo " "
echo "Traefik dashboard user: ${TRAEFIK_DASHBOARD_USER}"
echo "Traefik dashboard password: ${TRAEFIK_DASHBOARD_PASS}"
echo " "
echo "Docker registry username: ${DOCKER_REGISTRY_USER}"
echo "Docker registry password: ${DOCKER_REGISTRY_PASS}"
echo " "
echo "----------------------------------------"
echo " "
echo "Nomad config directory: ${NOMAD_CONFIG_DIR}"
echo "Consul config directory: ${CONSUL_CONFIG_DIR}"
echo "Traefik config directory: ${TRAEFIK_CONFIG_DIR}"
echo "Docker registry config directory: ${REGISTRY_CONFIG_DIR}"
echo " "
echo "----------------------------------------"
