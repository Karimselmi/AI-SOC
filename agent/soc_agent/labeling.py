import pandas as pd
from .config import WINDOW_SECONDS


def load_experiments(path):
    e = pd.read_csv(path)
    e["start"] = pd.to_datetime(e["start"], utc=True, format="ISO8601")
    e["end"] = pd.to_datetime(e["end"], utc=True, format="ISO8601")
    return e


def label_windows(feat, exp, window_seconds=WINDOW_SECONDS, pad_seconds=30):
    """Ground truth: a window is an attack window if it overlaps an executed experiment
    (+pad for ingestion delay) and comes from the attacker IP. Everything else = normal."""
    f = feat.copy().reset_index(drop=True)
    f["label"], f["run_id"] = "normal", -1
    wend = f["win"] + pd.Timedelta(seconds=window_seconds)
    for i, r in exp.iterrows():
        m = (f["win"] < r["end"] + pd.Timedelta(seconds=pad_seconds)) & (wend > r["start"])
        ip = r.get("attacker_ip")
        if isinstance(ip, str) and ip:
            m &= f["src_ip"] == ip
        f.loc[m, "label"] = r["scenario"]
        f.loc[m, "run_id"] = i
    f["is_attack"] = (f["label"] != "normal").astype(int)
    return f
