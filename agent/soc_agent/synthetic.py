"""Synthetic Wazuh-like alerts so the ML/correlation code can be developed and tested
BEFORE the lab produces real data. Never use synthetic results in the final evaluation."""
import numpy as np
import pandas as pd
from .normalize import COLUMNS, categorize

ATT, TGT, USER_IP = "192.168.56.30", "192.168.56.20", "192.168.56.40"


def generate(seed=42, hours=6, runs=6):
    rng = np.random.default_rng(seed)
    t0 = pd.Timestamp("2026-11-10T08:00:00Z")
    rows = []

    def add(ts, rule, lvl, desc, groups, src=None, dst=None, port=None, sig=None):
        rows.append({"timestamp": ts, "rule_id": rule, "level": lvl, "description": desc, "groups": groups,
                     "agent": "target-vm", "src_ip": src or "unknown", "dst_ip": dst, "dst_port": port,
                     "signature": sig, "mitre": "", "category": categorize(groups, desc, sig), "full_log": ""})

    normal = [("5715", 3, "sshd: authentication success.", "sshd,authentication_success", USER_IP),
              ("5501", 3, "PAM: Login session opened.", "pam,syslog", None),
              ("5402", 3, "Successful sudo to ROOT executed.", "sudo", None),
              ("31101", 5, "Web server 400 error code.", "web,accesslog", USER_IP),
              ("5716", 5, "sshd: authentication failed.", "sshd,authentication_failed", USER_IP),
              ("550", 7, "Integrity checksum changed.", "ossec,syscheck", None)]
    w = [.3, .25, .1, .15, .1, .1]
    for s in rng.uniform(0, hours * 3600, rng.poisson(hours * 3600 / 25)):
        r = normal[rng.choice(len(normal), p=w)]
        add(t0 + pd.Timedelta(seconds=float(s)), r[0], r[1], r[2], r[3], r[4])
    for s in rng.uniform(0, hours * 3600, 15):          # attacker's own benign activity
        add(t0 + pd.Timedelta(seconds=float(s)), "5715", 3, "sshd: authentication success.",
            "sshd,authentication_success", ATT)

    exp, step = [], (hours * 60 - 50) / (3 * runs)
    for k in range(3 * runs):
        sc = ["ssh", "scan", "web"][k % 3]
        start = t0 + pd.Timedelta(minutes=40 + k * step)
        dur = {"ssh": rng.integers(45, 90), "scan": rng.integers(15, 30), "web": rng.integers(40, 80)}[sc]
        n = {"ssh": rng.integers(40, 120), "scan": rng.integers(150, 400), "web": rng.integers(25, 70)}[sc]
        for s in rng.uniform(0, dur, n):
            ts = start + pd.Timedelta(seconds=float(s))
            if sc == "ssh":
                r = rng.choice(["5760", "5710", "5712"], p=[.7, .2, .1])
                d = {"5760": (5, "sshd: authentication failed."), "5710": (5, "sshd: Attempt to login using a non-existent user"),
                     "5712": (10, "sshd: brute force trying to get access to the system.")}[r]
                add(ts, r, d[0], d[1], "sshd,authentication_failed", ATT)
            elif sc == "scan":
                add(ts, "86601", 3, "Suricata: Alert - LAB Possible port scan", "ids,suricata", ATT, TGT,
                    int(rng.integers(1, 1000)), "LAB Possible port scan (SYN to non-service port)")
            else:
                r = rng.choice(["31103", "31105", "31101"], p=[.4, .3, .3])
                d = {"31103": (7, "SQL injection attempt."), "31105": (6, "XSS (Cross Site Scripting) attempt."),
                     "31101": (5, "Web server 400 error code.")}[r]
                add(ts, r, d[0], d[1], "web,accesslog,attack", ATT)
        exp.append({"scenario": sc, "start": start.isoformat(),
                    "end": (start + pd.Timedelta(seconds=int(dur))).isoformat(), "attacker_ip": ATT})
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df.sort_values("timestamp").reset_index(drop=True), pd.DataFrame(exp)
