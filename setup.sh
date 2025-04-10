#!/bin/bash

set -e

export DEBIAN_FRONTEND=noninteractive

CONSUL_HTTP_PORT=8500
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

CNI_PLUGINS_VERSION="1.6.2"

if [[ ! -f "/etc/debian_version" ]]; then
  echo "This script only works on Debian systems"
  exit 1
fi

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

sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y wget curl gpg coreutils ca-certificates jq apache2-utils netcat-traditional dnsutils ufw

sudo install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
  sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
fi
if [[ ! -f /usr/share/keyrings/hashicorp-archive-keyring.gpg ]]; then
  wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
fi
if [[ ! -f /etc/apt/sources.list.d/docker.list ]]; then
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list
fi
if [[ ! -f /etc/apt/sources.list.d/hashicorp.list ]]; then
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
    | sudo tee /etc/apt/sources.list.d/hashicorp.list
fi
sudo apt-get update
sudo apt-get install -y nomad consul docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

if [[ ! -f /usr/bin/registry ]]; then
  mkdir -p ./registry && \
    wget -qO- "https://github.com/distribution/distribution/releases/download/v${REGISTRY_VERSION}/registry_${REGISTRY_VERSION}_linux_amd64.tar.gz" | \
    tar -xz -C ./registry && \
    sudo install -m 755 ./registry/registry /usr/bin/ && \
    rm -rf ./registry
else
  echo "Registry already installed"
fi

if [[ ! -f /usr/bin/traefik ]]; then
  mkdir -p ./traefik && \
    wget -qO- "https://github.com/traefik/traefik/releases/download/v${TRAEFIK_VERSION}/traefik_v${TRAEFIK_VERSION}_linux_amd64.tar.gz" | \
    tar -xz -C ./traefik && \
    sudo install -m 755 ./traefik/traefik /usr/bin/ && \
    rm -rf ./traefik
else
  echo "Traefik already installed"
fi

if [[ ! -f /opt/cni/bin/cni-plugins ]]; then
  curl -L -o cni-plugins.tgz "https://github.com/containernetworking/plugins/releases/download/v${CNI_PLUGINS_VERSION}/cni-plugins-linux-amd64-v${CNI_PLUGINS_VERSION}.tgz"
  sudo mkdir -p /opt/cni/bin
  sudo tar -C /opt/cni/bin -xzf cni-plugins.tgz
else
  echo "CNI plugins already installed"
fi

DOCKER_BRIDGE_IP_ADDRESS=(`ip -brief addr show docker0 | awk '{print $3}' | awk -F/ '{print $1}'`)
if [ -z "${DOCKER_BRIDGE_IP_ADDRESS}" ]; then
  echo "Failed to get Docker bridge IP address"
  exit 1
fi

sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

echo "127.0.0.1 $(hostname)" | sudo tee --append /etc/hosts

echo "nameserver $DOCKER_BRIDGE_IP_ADDRESS" | sudo tee /etc/resolv.conf.new
cat /etc/resolv.conf | sudo tee --append /etc/resolv.conf.new
sudo mv /etc/resolv.conf.new /etc/resolv.conf

sudo mkdir -p ${CONSUL_CONFIG_DIR} ${CONSUL_DATA_DIR}
sudo chmod a+w ${CONSUL_CONFIG_DIR}
sudo chmod 777 ${CONSUL_DATA_DIR}

cat <<EOF | sudo tee ${CONSUL_CONFIG_DIR}/consul.hcl > /dev/null
advertise_addr = "${PRIVATE_IP}"
bind_addr = "0.0.0.0"
client_addr = "0.0.0.0"
data_dir = "${CONSUL_DATA_DIR}"
log_level = "INFO"
ports = {
  dns = 53
}
recursors = [
  "8.8.8.8",
  "8.8.4.4"
]
server = true
ui_config = {
  enabled = true
}
bootstrap = true
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
  tokens {
    dns = "CONSUL_DNS_SECRET_ID"
    agent = "CONSUL_AGENT_SECRET_ID"
  }
}
EOF

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

sudo systemctl daemon-reload
sudo systemctl enable consul
sudo systemctl start consul

echo "Waiting for Consul to be reachable..."
while ! netcat -z 127.0.0.1 ${CONSUL_HTTP_PORT} > /dev/null 2>&1; do
  sleep 1
done

echo "Waiting for Consul cluster leader to be elected..."
while ! consul kv get -recurse / > /dev/null 2>&1; do
  sleep 1
done

CONSUL_SECRET_ID=$(consul acl bootstrap -format=json | jq -r '.SecretID')
if [ -z "${CONSUL_SECRET_ID}" ]; then
  echo "Failed to bootstrap Consul ACL"
  exit 1
fi
echo ${CONSUL_SECRET_ID} >> ./consul-bootstrap-token.txt
export CONSUL_HTTP_TOKEN=${CONSUL_SECRET_ID}

CONSUL_DNS_SECRET_ID=$(consul acl token create -description "DNS Token" -format json -templated-policy "builtin/dns" | jq -r '.SecretID')
if [ -z "${CONSUL_DNS_SECRET_ID}" ]; then
  echo "Failed to create Consul DNS token"
  exit 1
fi

cat <<EOF | sudo tee ./consul-policy-nomad-agents.hcl > /dev/null
agent_prefix "" {
  policy = "read"
}

node_prefix "" {
  policy = "write"
}

service_prefix "" {
  policy = "write"
}
EOF

cat <<EOF | sudo tee ./consul-policy-nomad-tasks.hcl > /dev/null
key_prefix "" {
  policy = "read"
}

node_prefix "" {
  policy = "read"
}

service_prefix "" {
  policy = "read"
}
EOF

consul acl policy create -name 'nomad-agents' -description 'Nomad agents' -rules '@consul-policy-nomad-agents.hcl'
consul acl policy create -name 'nomad-tasks' -description 'Nomad tasks' -rules '@consul-policy-nomad-tasks.hcl'

CONSUL_NOMAD_AGENTS_SECRET_ID=$(consul acl token create -policy-name 'nomad-agents' -format json | jq -r '.SecretID')
if [ -z "${CONSUL_NOMAD_AGENTS_SECRET_ID}" ]; then
  echo "Failed to create Consul Nomad agents token"
  exit 1
fi

cat <<EOF | sudo tee ./consul-auth-method-nomad-workloads.json > /dev/null
{
  "JWKSURL": "http://0.0.0.0:${CONSUL_HTTP_PORT}/.well-known/jwks.json",
  "JWTSupportedAlgs": ["RS256"],
  "BoundAudiences": ["consul.io"],
  "ClaimMappings": {
    "nomad_namespace": "nomad_namespace",
    "nomad_job_id": "nomad_job_id",
    "nomad_task": "nomad_task",
    "nomad_service": "nomad_service"
  }
}
EOF

consul acl auth-method create -name 'nomad-workloads' -type 'jwt' -description 'Nomad services and workloads' -config '@consul-auth-method-nomad-workloads.json'

consul acl binding-rule create -method 'nomad-workloads' -description 'Services registered from Nomad' -bind-type 'service' -bind-name '${value.nomad_service}' -selector '"nomad_service" in value'
consul acl binding-rule create -method 'nomad-workloads' -description 'Nomad tasks' -bind-type 'role' -bind-name 'nomad-tasks-${value.nomad_namespace}' -selector '"nomad_service" not in value'

consul acl role create -name 'nomad-tasks-default' -description 'Nomad tasks in the "default" namespace' -policy-name 'nomad-tasks'

sudo sed -i "s/CONSUL_DNS_SECRET_ID/${CONSUL_DNS_SECRET_ID}/g" ${CONSUL_CONFIG_DIR}/consul.hcl
sudo sed -i "s/CONSUL_AGENT_SECRET_ID/${CONSUL_SECRET_ID}/g" ${CONSUL_CONFIG_DIR}/consul.hcl
sudo systemctl restart consul

sudo mkdir -p ${NOMAD_CONFIG_DIR} ${NOMAD_DATA_DIR}
sudo chmod a+w ${NOMAD_CONFIG_DIR}
sudo chmod 777 ${NOMAD_DATA_DIR}

cat <<EOF | sudo tee ${NOMAD_CONFIG_DIR}/nomad.hcl > /dev/null
data_dir = "${NOMAD_DATA_DIR}"
bind_addr = "0.0.0.0"
server {
  enabled = true
  bootstrap_expect = 1
}
client {
  enabled = true
  servers = ["127.0.0.1:4647"]
}
consul {
  address = "0.0.0.0:${CONSUL_HTTP_PORT}"
  token = "${CONSUL_NOMAD_AGENTS_SECRET_ID}"

  service_identity {
    aud = ["consul.io"]
    ttl = "1h"
  }

  task_identity {
    aud = ["consul.io"]
    ttl = "1h"
  }
}
acl = {
  enabled = true
}
plugin "docker" {
  config {
    auth {
      config = "${NOMAD_CONFIG_DIR}/docker-auth.json"
    }
  }
}
EOF

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

sudo systemctl daemon-reload
sudo systemctl enable nomad
sudo systemctl start nomad

echo "Waiting for Nomad to be reachable..."
while ! netcat -z 127.0.0.1 ${NOMAD_PORT} > /dev/null 2>&1; do
  sleep 1
done

NOMAD_SECRET_ID=$(nomad acl bootstrap -json | jq -r '.SecretID')
if [ -z "${NOMAD_SECRET_ID}" ]; then
  echo "Failed to bootstrap Nomad ACL"
  exit 1
fi
echo ${NOMAD_SECRET_ID} >> ./nomad-bootstrap-token.txt

sudo useradd \
  -U \
  --no-create-home \
  --shell /bin/false \
  --system \
  docker-registry

sudo mkdir -p ${REGISTRY_CONFIG_DIR}
sudo chmod 755 ${REGISTRY_CONFIG_DIR}
sudo chown -R docker-registry:docker-registry ${REGISTRY_CONFIG_DIR}
sudo mkdir -p ${REGISTRY_DATA_DIR}
sudo chmod 755 ${REGISTRY_DATA_DIR}
sudo chown -R docker-registry:docker-registry ${REGISTRY_DATA_DIR}

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

sudo systemctl daemon-reload
sudo systemctl enable docker-registry
sudo systemctl start docker-registry

echo "Waiting for Docker registry to be reachable..."
while ! netcat -z 127.0.0.1 ${REGISTRY_PORT} > /dev/null 2>&1; do
  sleep 1
done

sudo useradd \
  -U \
  --no-create-home \
  --shell /bin/false \
  --system \
  traefik

sudo mkdir -p ${TRAEFIK_CONFIG_DIR}
sudo chmod 755 ${TRAEFIK_CONFIG_DIR}
sudo chown -R traefik:traefik ${TRAEFIK_CONFIG_DIR}
sudo mkdir -p ${TRAEFIK_LOG_DIR}
sudo chmod 755 ${TRAEFIK_LOG_DIR}
sudo chown -R traefik:traefik ${TRAEFIK_LOG_DIR}

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
      address: "127.0.0.1:${CONSUL_HTTP_PORT}"
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
          - url: "http://127.0.0.1:${CONSUL_HTTP_PORT}/"
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

hashed_password=$(htpasswd -bnBC 10 "" "${TRAEFIK_DASHBOARD_PASS}" | tr -d ':\n')
echo "${TRAEFIK_DASHBOARD_USER}:${hashed_password}" | sudo tee ${TRAEFIK_CONFIG_DIR}/dashboard-users > /dev/null

hashed_password=$(htpasswd -bnBC 10 "" "${DOCKER_REGISTRY_PASS}" | tr -d ':\n')
echo "${DOCKER_REGISTRY_USER}:${hashed_password}" | sudo tee ${TRAEFIK_CONFIG_DIR}/docker-registry-users > /dev/null

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

sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow dns
sudo ufw --force enable

sudo systemctl daemon-reload
sudo systemctl enable traefik
sudo systemctl start traefik

echo "Waiting for Traefik HTTP to be reachable..."
while ! netcat -z 127.0.0.1 80 > /dev/null 2>&1; do
  sleep 1
done

echo "Waiting for Traefik HTTPS to be reachable..."
while ! netcat -z 127.0.0.1 443 > /dev/null 2>&1; do
  sleep 1
done

echo "Waiting for Docker registry to be reachable on the public internet..."
while ! curl -u ${DOCKER_REGISTRY_USER}:${DOCKER_REGISTRY_PASS} https://${DOCKER_REGISTRY_HOST}/ > /dev/null 2>&1; do
  sleep 1
done

echo "Logging in to Docker registry..."
docker login ${DOCKER_REGISTRY_HOST} -u ${DOCKER_REGISTRY_USER} --password-stdin <<< ${DOCKER_REGISTRY_PASS}
cp ~/.docker/config.json ${NOMAD_CONFIG_DIR}/docker-auth.json

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
