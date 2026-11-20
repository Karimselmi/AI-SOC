import numpy as np
import pandas as pd
from .config import WINDOW_SECONDS, MERGE_GAP_SECONDS

LABELS = {"ssh": "SSH Brute Force", "scan": "Network Port Scanning", "web": "Web Attack (SQLi/XSS)",
          "network": "Suspicious network activity", "other": "Unclassified anomaly"}

RECOMMENDATIONS = {
    "ssh": ["Check whether any login from this IP succeeded after the failures (auth.log).",
            "Consider blocking the source IP at the firewall (manual action, analyst decision).",
            "Disable SSH password authentication and use keys; restrict AllowUsers.",
            "Consider fail2ban or rate limiting on port 22."],
    "scan": ["Identify which ports answered (open services) and confirm they are expected.",
             "Review exposed services on the target and close unused ports.",
             "Watch this IP for follow-up activity (SSH or web attempts) - scans often precede attacks."],
    "web": ["Review the application and web server logs for the requested URLs and HTTP status codes.",
            "Check whether the payloads reached the application (200 vs 4xx/5xx) and whether data leaked.",
            "Patch or harden the vulnerable endpoint; consider a WAF rule; validate and escape inputs."],
    "network": ["Inspect the Suricata alert details and the traffic around that time."],
    "other": ["Manual triage required: the pattern is anomalous but not matched to a known scenario."],
}


def risk_level(score):
    return "critical" if score >= 70 else "high" if score >= 50 else "medium" if score >= 30 else "low"


def _merge_windows(flagged, window_seconds, gap):
    groups = []
    for ip, g in flagged.sort_values("win").groupby("src_ip"):
        cur = None
        for _, r in g.iterrows():
            s, e = r["win"], r["win"] + pd.Timedelta(seconds=window_seconds)
            if cur and (s - cur["end"]).total_seconds() <= gap:
                cur["end"] = max(cur["end"], e)
                cur["score"] = max(cur["score"], r["anomaly_score"])
                cur["ml"].append(r.get("ml_scenario"))
            else:
                if cur:
                    groups.append(cur)
                cur = {"src_ip": ip, "start": s, "end": e, "score": r["anomaly_score"],
                       "ml": [r.get("ml_scenario")]}
        if cur:
            groups.append(cur)
    return sorted(groups, key=lambda x: x["start"])


def correlate(alerts, flagged, window_seconds=WINDOW_SECONDS, gap=MERGE_GAP_SECONDS):
    """Group anomalous windows of the same source IP that are close in time into one incident,
    then attach the matching raw alerts. IP + time proximity is a HYPOTHESIS, not proof."""
    incidents = []
    for n, g in enumerate(_merge_windows(flagged, window_seconds, gap), 1):
        sub = alerts[(alerts["src_ip"] == g["src_ip"]) & (alerts["timestamp"] >= g["start"])
                     & (alerts["timestamp"] < g["end"])]
        if sub.empty:
            continue
        counts = sub["category"].value_counts().to_dict()
        order = (sub[sub["category"].isin(["scan", "ssh", "web"])].groupby("category")["timestamp"]
                 .min().sort_values().index.tolist())
        main = max(("scan", "ssh", "web", "network", "other"), key=lambda c: counts.get(c, 0))
        multi = len(order) >= 2
        agents = sorted(set(sub["agent"]) - {""})
        ctx = alerts[(alerts["src_ip"] == "unknown") & (alerts["timestamp"] >= g["start"])
                     & (alerts["timestamp"] < g["end"]) & (alerts["agent"].isin(agents))]
        a_norm = float(np.clip((g["score"] + 0.1) / 0.4, 0, 1))
        score = 100 * (0.4 * min(sub["level"].max() / 15, 1) + 0.3 * a_norm
                       + 0.2 * min(np.log10(len(sub) + 1) / 3, 1) + 0.1 * (1.0 if multi else 0.0))
        top = sub.groupby(["rule_id", "description"]).size().sort_values(ascending=False).head(5)
        recs = []
        for c in (order or [main]):
            recs += [r for r in RECOMMENDATIONS[c] if r not in recs]
        ports = int(sub["dst_port"].nunique())
        evidence = [f"{len(sub)} alerts from {g['src_ip']} between {g['start']:%H:%M:%S} and "
                    f"{g['end']:%H:%M:%S} UTC", f"max rule level: {int(sub['level'].max())}",
                    f"anomaly score (Isolation Forest): {g['score']:.3f}"]
        if ports > 1:
            evidence.append(f"{ports} distinct destination ports targeted")
        if multi:
            evidence.append("multi-stage sequence: " + " -> ".join(order))
        if len(ctx):
            evidence.append(f"{len(ctx)} host-side alerts without source IP on the same agent in the same period")
        ml = [m for m in g["ml"] if isinstance(m, str)]
        incidents.append({
            "id": f"INC-{g['start']:%Y%m%d}-{n:03d}",
            "start": g["start"].isoformat(), "end": g["end"].isoformat(),
            "type": LABELS[main] if not multi else "Multi-stage: " + " -> ".join(LABELS[c] for c in order),
            "ml_predicted_scenario": max(set(ml), key=ml.count) if ml else None,
            "src_ip": g["src_ip"], "targets": agents, "n_alerts": int(len(sub)),
            "max_level": int(sub["level"].max()), "risk_score": round(float(score), 1),
            "risk_level": risk_level(score), "categories": counts,
            "top_rules": [f"{r} - {d} (x{c})" for (r, d), c in top.items()],
            "mitre": sorted(set(",".join(sub["mitre"].fillna("")).split(",")) - {""}),
            "evidence": evidence, "recommendations": recs,
        })
    return sorted(incidents, key=lambda i: -i["risk_score"])
