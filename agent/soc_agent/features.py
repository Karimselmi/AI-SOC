import numpy as np
import pandas as pd
from .config import WINDOW_SECONDS

FEATURES = ["n_events", "events_per_sec", "n_rules", "n_sig", "max_level", "mean_level",
            "n_ports", "n_agents", "n_ssh", "n_scan", "n_web", "n_network"]


def build_windows(df, window_seconds=WINDOW_SECONDS):
    """One row per (source IP, time window) with behavioural features."""
    if df.empty:
        return pd.DataFrame(columns=["src_ip", "win"] + FEATURES)
    d = df.copy()
    d["signature"] = d["signature"].replace("", np.nan)
    d["win"] = d["timestamp"].dt.floor(f"{window_seconds}s")
    f = d.groupby(["src_ip", "win"]).agg(
        n_events=("rule_id", "size"), n_rules=("rule_id", "nunique"),
        n_sig=("signature", "nunique"), max_level=("level", "max"),
        mean_level=("level", "mean"), n_ports=("dst_port", "nunique"),
        n_agents=("agent", "nunique"))
    c = d.groupby(["src_ip", "win", "category"]).size().unstack(fill_value=0)
    for k in ("ssh", "scan", "web", "network"):
        if k not in c:
            c[k] = 0
    f = f.join(c[["ssh", "scan", "web", "network"]].add_prefix("n_"))
    f["events_per_sec"] = f["n_events"] / window_seconds
    return f.reset_index()[["src_ip", "win"] + FEATURES]
