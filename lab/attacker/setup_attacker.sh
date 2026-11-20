#!/usr/bin/env bash
# Kali / Ubuntu attacker VM. Lab use ONLY.
set -euo pipefail
sudo apt-get update
sudo apt-get install -y hydra nmap sshpass curl
