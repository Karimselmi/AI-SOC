#!/usr/bin/env bash
# Generates benign activity (baseline for Isolation Forest). Run for >= 60 min BEFORE the attacks.
#   TARGET=192.168.56.20 MINUTES=60 bash normal_traffic.sh
set -euo pipefail
: "${TARGET:?}"; MINUTES="${MINUTES:-60}"
end=$(( $(date +%s) + MINUTES*60 ))
while [ "$(date +%s)" -lt "$end" ]; do
  case $((RANDOM % 4)) in
    0) sshpass -p 'Lab!Pass2026' ssh -o StrictHostKeyChecking=no labuser@"$TARGET" 'uptime; ls /tmp' >/dev/null 2>&1 || true ;;
    1) curl -s -o /dev/null "http://$TARGET:8080/login.php" ;;
    2) curl -s -o /dev/null "http://$TARGET:8080/index.php" ;;
    3) curl -s -o /dev/null "http://$TARGET:8080/does-not-exist-$RANDOM" ;;
  esac
  sleep $(( (RANDOM % 25) + 5 ))
done
