# Team plan (4 people, 4 weeks)

Roles can be swapped, but each module has one owner. Everybody pushes to Git through branches and pull requests.

| Member | Role | Owns |
|---|---|---|
| Mohamed Rebai | Platform and infrastructure | VMs, host-only network, Wazuh manager/indexer/dashboard, agent enrolment, credentials, backups and snapshots |
| Mohamed Louay Benzarti | Sensors and attack scenarios | Target VM, Suricata and local rules, DVWA, Wazuh localfile config, attack and baseline scripts, experiments.csv labels |
| Neder Jarboui | Agent data and ML | wazuh_client, normalize, features, labeling, models (Isolation Forest, Random Forest), evaluation metrics |
| Karim Selmi | Correlation, reporting and delivery | correlate, report, dashboard, tests, final evaluation tables, technical report and presentation, repo and CI hygiene |

## Weekly plan

| Week | Rebai | Benzarti | Jarboui | Selmi |
|---|---|---|---|---|
| 1 | Network plan, VMs, run setup_wazuh.sh, enrol the target agent | Run setup_target.sh, Suricata rules, DVWA, verify logs reach Wazuh | Set up repo and venv, run the synthetic pipeline, review features | Review the cahier changes, write the report skeleton, set up Git branches and the test command |
| 2 | Dashboards and saved searches in Wazuh, snapshots, health checks | Run normal_traffic then run_scenarios, check every scenario in Wazuh, deliver experiments.csv | Collect real alerts, fix normalisation on real fields, first Isolation Forest | Correlation rules on real alerts, incident card template |
| 3 | Real-time watch mode on the Wazuh VM, alert volume tuning | Second campaign for a held-out test set, add edge cases (slow brute force, benign scans) | Tune windows, contamination, features; Random Forest with group split | Risk score tuning, MITRE mapping, Streamlit dashboard |
| 4 | Final demo environment, reproducibility test from scratch | Final evidence (screenshots, traces) | Final metrics, confusion matrices, limits | Final report, slides, rehearsal, repository cleanup |

## Shared rules

- Never run attack scripts outside the host-only network.
- Take a VM snapshot before each campaign, never commit passwords, `.env` or datasets with secrets.
- Handover files: Benzarti to Jarboui is `experiments.csv`; Rebai to Jarboui is the indexer URL and credentials; Jarboui to Selmi is the trained models and `alerts.csv`.
