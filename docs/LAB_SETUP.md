# Lab setup, step by step

## 0. VMs (VirtualBox or VMware)

| VM | OS | Resources | Network |
|---|---|---|---|
| wazuh | Ubuntu Server 22.04/24.04 | 4 vCPU, 8 GB RAM, 40 GB | NAT (install) + host-only 192.168.56.10 |
| target | Ubuntu Server 22.04/24.04 | 2 vCPU, 4 GB RAM, 25 GB | NAT (install) + host-only 192.168.56.20 |
| attacker | Kali Linux | 2 vCPU, 2 GB RAM, 20 GB | host-only 192.168.56.30 |

Set static IPs on the host-only interface (netplan on Ubuntu), then check `ip -br a` and `ping` between VMs.
If hardware is limited: run Wazuh on the host with Docker and keep only target + attacker as VMs.

## 1. Wazuh VM

```bash
git clone <your-repo-url> ai-powered-soc && cd ai-powered-soc
sudo bash lab/wazuh/setup_wazuh.sh
docker ps                                    # manager, indexer, dashboard must be Up
```

Open https://192.168.56.10 (admin / SecretPassword by default, change it in the compose file and indexer security config for anything beyond the lab).
Check the Wazuh docs for the latest stable tag and pass it with `WAZUH_TAG=vX.Y.Z`.

## 2. Target VM (sshd, DVWA, Suricata, Wazuh agent)

```bash
git clone <your-repo-url> ai-powered-soc && cd ai-powered-soc
ip -br a                                     # find the host-only interface name, e.g. enp0s8
sudo MANAGER_IP=192.168.56.10 IFACE=enp0s8 bash lab/target/setup_target.sh
```

Verify:

```bash
sudo systemctl status wazuh-agent suricata
sudo tail -f /var/log/suricata/eve.json | head
ls /opt/soc-lab/target/logs                   # access.log must appear after a first request
curl -I http://192.168.56.20:8080
```

On the Wazuh VM: `docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l` must list target-vm as Active.
DVWA first use: open http://192.168.56.20:8080/setup.php, click "Create / Reset Database" (login admin / password).

## 3. Attacker VM

```bash
sudo bash lab/attacker/setup_attacker.sh
```

Manual smoke tests (one per scenario), then look at the Wazuh dashboard (Threat Hunting / Events):

```bash
hydra -l labuser -P /usr/share/wordlists/rockyou.txt.gz -t 4 ssh://192.168.56.20   # or use a short list
sudo nmap -sS -p 1-1000 -T4 192.168.56.20
curl "http://192.168.56.20:8080/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null,null--&Submit=Submit"
```

Expected rules: sshd 5710/5760/5712 (SSH), Suricata 86601 "LAB Possible port scan" (scan), web 31101/31103/31105 plus Suricata sid 1000002 (web).
Burp Suite Community (manual): set the browser proxy to 127.0.0.1:8080 on Kali, browse DVWA, replay requests in Repeater with payloads.

## 4. Dataset campaign (this produces the evaluation data)

```bash
# 1) Baseline, 60 min, from the attacker VM
TARGET=192.168.56.20 MINUTES=60 bash lab/attacker/normal_traffic.sh
# 2) Attacks, 6 runs per scenario (about 1 h), writes experiments.csv with UTC labels
TARGET=192.168.56.20 ATT_IP=192.168.56.30 RUNS=6 bash lab/attacker/run_scenarios.sh
# 3) Quick Wazuh check
curl -sk -u admin:SecretPassword "https://192.168.56.10:9200/wazuh-alerts-*/_count"
```

Copy `experiments.csv` into `agent/data/`. Keep VM clocks synchronised (chrony or VirtualBox guest additions), labels depend on timestamps.

## 5. Offline alternative (if indexer access is a problem)

```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/logs/alerts/alerts.json > alerts.json
python -m soc_agent collect --from-file alerts.json
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Indexer container restarts | `sudo sysctl -w vm.max_map_count=262144`, give the VM 8 GB RAM |
| Agent not Active | check 1514/1515 reachability, `sudo tail /var/ossec/logs/ossec.log` on the target |
| No Suricata alerts in Wazuh | wrong interface in suricata.yaml, `sudo suricata -T -c /etc/suricata/suricata.yaml`, check ossec_localfiles block was appended |
| No web alerts | `access.log` path in ossec.conf must match the bind mount, restart wazuh-agent |
| Hydra gets no SSH failures logged | rsyslog missing or PasswordAuthentication not enabled |
| Agent TLS errors | VERIFY_TLS=false in .env (lab certificates are self-signed) |
