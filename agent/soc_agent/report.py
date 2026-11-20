import json
from . import config

NOTE = ("Correlation is based on source IP and time proximity. This is a hypothesis to be validated "
        "by the analyst, not proof. The agent never blocks or changes configuration automatically.")


def write_reports(incidents, outdir=config.REPORTS):
    outdir.mkdir(exist_ok=True)
    (outdir / "incidents.json").write_text(json.dumps(incidents, indent=2, default=str))
    lines = ["# Incident summary", "", "| ID | Type | Source IP | Alerts | Risk |", "|---|---|---|---|---|"]
    for i in incidents:
        lines.append(f"| {i['id']} | {i['type']} | {i['src_ip']} | {i['n_alerts']} | {i['risk_level']} ({i['risk_score']}) |")
        md = [f"# {i['id']} - {i['type']}", "",
              f"- Period: {i['start']} -> {i['end']}", f"- Source IP: {i['src_ip']}",
              f"- Targets: {', '.join(i['targets']) or 'n/a'}",
              f"- Alerts: {i['n_alerts']} (max level {i['max_level']})",
              f"- Risk: {i['risk_level']} ({i['risk_score']}/100)",
              f"- MITRE ATT&CK: {', '.join(i['mitre']) or 'n/a'}",
              f"- RF predicted scenario: {i['ml_predicted_scenario'] or 'n/a'}", "",
              "## Evidence", *[f"- {e}" for e in i["evidence"]], "",
              "## Top rules", *[f"- {r}" for r in i["top_rules"]], "",
              "## Recommendations (for the analyst)", *[f"- {r}" for r in i["recommendations"]], "",
              f"> {NOTE}"]
        (outdir / f"{i['id']}.md").write_text("\n".join(md), encoding="utf-8")
    lines += ["", f"> {NOTE}"]
    (outdir / "summary.md").write_text("\n".join(lines), encoding="utf-8")
