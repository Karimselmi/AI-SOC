#!/usr/bin/env bash
# Run on the TARGET VM (Ubuntu 22.04/24.04) as root, from the repo root:
#   sudo MANAGER_IP=192.168.56.10 IFACE=enp0s8 bash lab/target/setup_target.sh
set -euo pipefail
: "${MANAGER_IP:?set MANAGER_IP (Wazuh manager VM)}"
: "${IFACE:?set IFACE (host-only interface, e.g. enp0s8)}"
LAB_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1)
HERE="$(cd "$(dirname "$0")" && pwd)"

apt-get update
apt-get install -y openssh-server rsyslog curl gnupg software-properties-common
command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh

# --- lab user + password SSH (needed for the brute-force scenario) ---
id labuser >/dev/null 2>&1 || useradd -m -s /bin/bash labuser
echo 'labuser:Lab!Pass2026' | chpasswd
echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/00-lab.conf
systemctl restart ssh; systemctl enable --now rsyslog

# --- vulnerable web app (DVWA) ---
mkdir -p /opt/soc-lab/target && cp "$HERE/docker-compose.yml" /opt/soc-lab/target/
(cd /opt/soc-lab/target && LAB_IP="$LAB_IP" docker compose up -d)

# --- Suricata ---
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update && apt-get install -y suricata
sed -i "0,/interface: .*/s//interface: ${IFACE}/" /etc/suricata/suricata.yaml
sed -i 's|^\(\s*HOME_NET:\).*|\1 "[192.168.56.0/24]"|' /etc/suricata/suricata.yaml
cp "$HERE/local.rules" /var/lib/suricata/rules/local.rules
grep -q local.rules /etc/suricata/suricata.yaml || sed -i '/^rule-files:/a\  - local.rules' /etc/suricata/suricata.yaml
suricata-update
suricata -T -c /etc/suricata/suricata.yaml -v
systemctl enable --now suricata

# --- Wazuh agent ---
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="target-vm" apt-get install -y wazuh-agent
cat "$HERE/ossec_localfiles.xml" >> /var/ossec/etc/ossec.conf
systemctl daemon-reload && systemctl enable --now wazuh-agent

echo "Target ready: SSH ${LAB_IP}:22, DVWA http://${LAB_IP}:8080"
