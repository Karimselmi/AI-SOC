#!/usr/bin/env bash
# Runs the 3 scenarios N times and records ground-truth labels in experiments.csv.
# LAB USE ONLY - targets must be your own authorised VMs.
#   TARGET=192.168.56.20 ATT_IP=192.168.56.30 RUNS=6 bash run_scenarios.sh
set -euo pipefail
: "${TARGET:?}"; : "${ATT_IP:?}"
RUNS="${RUNS:-6}"; GAP="${GAP:-150}"; OUT="${OUT:-experiments.csv}"
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
[ -f "$OUT" ] || echo "scenario,start,end,attacker_ip" > "$OUT"

ssh_bruteforce() {
  n=$(( (RANDOM % 120) + 30 )); t=$(( (RANDOM % 4) + 1 ))
  for i in $(seq 1 "$n"); do echo "wrongpass$i"; done > /tmp/wl.txt
  hydra -l labuser -P /tmp/wl.txt -t "$t" "ssh://$TARGET" >/dev/null 2>&1 || true
}
port_scan() {
  T=$(( (RANDOM % 3) + 3 )); hi=$(( (RANDOM % 4) * 500 + 500 ))
  sudo nmap -sS -p "1-$hi" "-T$T" "$TARGET" >/dev/null 2>&1 || true
}
web_attack() {
  P=("1%27%20OR%20%271%27=%271" "1%27%20UNION%20SELECT%20null,null--" "%3Cscript%3Ealert(1)%3C/script%3E" "%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E" "../../../../etc/passwd")
  for i in $(seq 1 $(( (RANDOM % 40) + 20 ))); do
    p=${P[$((RANDOM % ${#P[@]}))]}
    curl -s -o /dev/null "http://$TARGET:8080/vulnerabilities/sqli/?id=$p&Submit=Submit"
    sleep 0.3
  done
}

for r in $(seq 1 "$RUNS"); do
  for sc in ssh scan web; do
    s=$(now)
    case $sc in ssh) ssh_bruteforce;; scan) port_scan;; web) web_attack;; esac
    e=$(now)
    echo "${sc},${s},${e},${ATT_IP}" >> "$OUT"
    echo "[run $r] $sc  $s -> $e"
    sleep "$GAP"
  done
done
echo "Done. Copy $OUT to agent/data/experiments.csv"
