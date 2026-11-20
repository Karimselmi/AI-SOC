# AI-Powered SOC (Wazuh + Suricata + Python agent)

Mini-SOC for the TEK-UP Python project. Wazuh centralises system alerts, Suricata adds network alerts,
a Python agent pulls the alerts, detects anomalies (Isolation Forest), classifies scenarios
(Random Forest, optional), correlates alerts into incidents, and writes incident reports with recommendations.

```
 attacker VM (.30) --attacks--> target VM (.20): sshd + DVWA (Docker) + Suricata + Wazuh agent
                                          |  alerts
                                          v
                        Wazuh VM (.10): manager + indexer + dashboard (Docker)
                                          |  query indexer :9200
                                          v
                            soc_agent (Python): normalise -> windows -> IF/RF -> correlate -> reports
```

Lab network: VirtualBox host-only 192.168.56.0/24 (manager .10, target .20, attacker .30). No internet exposure.

## Repository layout

| Path | Content |
|---|---|
| lab/wazuh | Wazuh single-node install script (Docker) |
| lab/target | Target VM: DVWA compose, Suricata rules, Wazuh localfile config, setup script |
| lab/attacker | Attacker VM: scenario runner (writes ground-truth labels), benign traffic generator |
| agent | Python agent, tests, optional Streamlit dashboard |
| docs | LAB_SETUP.md (step by step), TEAM_PLAN.md (who does what), cahier_ameliorations.md (changes to the cahier des charges) |

## Quick start without the lab (develop the agent first)

```bash
cd agent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m soc_agent collect --synthetic      # fake alerts + experiments.csv
python -m soc_agent train                    # Isolation Forest + Random Forest, metrics in reports/metrics.json
python -m soc_agent analyze                  # incidents in reports/summary.md and reports/INC-*.md
python -m pytest -q tests
streamlit run dashboard.py                   # optional UI
```

## With the real lab

```bash
cp .env.example .env                         # set INDEXER_URL=https://192.168.56.10:9200
python -m soc_agent collect --hours 6        # pulls wazuh-alerts-* from the indexer
cp /path/to/experiments.csv data/experiments.csv   # produced by lab/attacker/run_scenarios.sh
python -m soc_agent train
python -m soc_agent analyze
python -m soc_agent watch --lookback 15 --interval 60   # near real time loop
```

Synthetic data is only for development. The evaluation in the final report must use real lab data.

Authorised lab use only: attack scripts must target your own VMs.
