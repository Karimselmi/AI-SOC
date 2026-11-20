import pandas as pd

COLUMNS = ["timestamp", "rule_id", "level", "description", "groups", "agent", "src_ip",
           "dst_ip", "dst_port", "signature", "mitre", "category", "full_log"]


def _get(d, path, default=None):
    cur = d
    for k in path.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _first(d, paths):
    for p in paths:
        v = _get(d, p)
        if v not in (None, ""):
            return v
    return None


def categorize(groups, description, signature):
    g = set(str(groups or "").split(","))
    sig = str(signature or "").lower()
    text = f"{description or ''} {sig}".lower()
    if "scan" in sig or "nmap" in text or "port scan" in text:
        return "scan"
    if "sshd" in g or "ssh" in text:
        return "ssh"
    if g & {"web", "accesslog", "sql_injection", "web_scan", "appsec"} or \
            any(k in text for k in ("sql", "xss", "web", "http")):
        return "web"
    if g & {"suricata", "ids"}:
        return "network"
    return "other"


def normalize_alerts(raw):
    rows = []
    for a in raw:
        groups = ",".join(_get(a, "rule.groups", []) or [])
        mitre = _get(a, "rule.mitre.id", []) or []
        desc = _get(a, "rule.description", "")
        sig = _get(a, "data.alert.signature")
        rows.append({
            "timestamp": a.get("timestamp"),
            "rule_id": str(_get(a, "rule.id", "")),
            "level": _get(a, "rule.level", 0),
            "description": desc,
            "groups": groups,
            "agent": _get(a, "agent.name", ""),
            "src_ip": _first(a, ["data.srcip", "data.src_ip", "data.win.eventdata.ipAddress"]),
            "dst_ip": _first(a, ["data.dest_ip", "data.dstip"]),
            "dst_port": _first(a, ["data.dest_port", "data.dstport"]),
            "signature": sig,
            "mitre": ",".join(mitre) if isinstance(mitre, list) else str(mitre),
            "category": categorize(groups, desc, sig),
            "full_log": str(a.get("full_log", ""))[:300],
        })
    df = pd.DataFrame(rows, columns=COLUMNS)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601")
    df["level"] = pd.to_numeric(df["level"], errors="coerce").fillna(0).astype(int)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    df["src_ip"] = df["src_ip"].fillna("unknown")
    return df.sort_values("timestamp").reset_index(drop=True)


def load_alerts_csv(path):
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601")
    for c in ("description", "groups", "agent", "mitre", "full_log"):
        df[c] = df[c].fillna("")
    df["src_ip"] = df["src_ip"].fillna("unknown")
    df["rule_id"] = df["rule_id"].astype(str)
    return df.sort_values("timestamp").reset_index(drop=True)
