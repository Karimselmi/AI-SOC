#!/usr/bin/env bash
# Run on the WAZUH VM (Ubuntu 22.04/24.04, 4 vCPU, 8 GB RAM, 40 GB disk) as root.
set -euo pipefail
WAZUH_TAG="${WAZUH_TAG:-v4.14.6}"   # check the latest stable tag in the Wazuh docs before running

sysctl -w vm.max_map_count=262144
grep -q max_map_count /etc/sysctl.conf || echo "vm.max_map_count=262144" >> /etc/sysctl.conf

apt-get update && apt-get install -y git curl ca-certificates
command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh

[ -d /opt/wazuh-docker ] || git clone https://github.com/wazuh/wazuh-docker.git -b "$WAZUH_TAG" /opt/wazuh-docker
cd /opt/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d

echo "Dashboard : https://$(hostname -I | awk '{print $1}')   (default admin / SecretPassword - change it!)"
echo "Indexer   : https://$(hostname -I | awk '{print $1}'):9200  (used by the Python agent)"
echo "Agents    : ports 1514/tcp and 1515/tcp must be reachable from the target VM"
