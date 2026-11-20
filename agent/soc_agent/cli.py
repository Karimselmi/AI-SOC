import argparse
import json
import time
from . import config
from .normalize import normalize_alerts, load_alerts_csv
from .features import build_windows
from .labeling import load_experiments, label_windows
from .models import (load_model, train_isolation_forest, train_random_forest, save_metrics)
from .pipeline import analyze
from .report import write_reports

ALERTS_CSV = config.DATA / "alerts.csv"
EXP_CSV = config.DATA / "experiments.csv"


def cmd_collect(a):
    if a.synthetic:
        from .synthetic import generate
        df, exp = generate()
        exp.to_csv(EXP_CSV, index=False)
    elif a.from_file:
        from .wazuh_client import load_alerts_file
        df = normalize_alerts(load_alerts_file(a.from_file))
    else:
        from .wazuh_client import fetch_alerts
        df = normalize_alerts(fetch_alerts(hours=a.hours))
    df.to_csv(ALERTS_CSV, index=False)
    print(f"{len(df)} alerts saved to {ALERTS_CSV}")


def cmd_train(a):
    alerts = load_alerts_csv(ALERTS_CSV)
    labeled = label_windows(build_windows(alerts), load_experiments(a.experiments))
    print(labeled["label"].value_counts().to_string())
    _, m_if = train_isolation_forest(labeled)
    out = {"isolation_forest": m_if}
    if labeled["label"].nunique() > 2:
        _, rep = train_random_forest(labeled)
        out["random_forest"] = rep
    save_metrics(out)
    print(json.dumps({"isolation_forest": m_if}, indent=2))
    if "random_forest" in out:
        rf = out["random_forest"]
        print("Random Forest macro F1:", round(rf["macro avg"]["f1-score"], 3))


def _run(alerts):
    if_model = load_model("isolation_forest")
    if if_model is None:
        raise SystemExit("No model found: run `train` first.")
    incidents, _, dt = analyze(alerts, if_model, load_model("random_forest"))
    write_reports(incidents)
    print(f"{len(incidents)} incident(s) in {dt:.3f}s -> {config.REPORTS}/summary.md")


def cmd_analyze(a):
    _run(load_alerts_csv(ALERTS_CSV))


def cmd_watch(a):
    from .wazuh_client import fetch_alerts
    while True:
        df = normalize_alerts(fetch_alerts(hours=a.lookback / 60))
        if not df.empty:
            _run(df)
        time.sleep(a.interval)


def main():
    p = argparse.ArgumentParser(prog="soc_agent")
    s = p.add_subparsers(required=True)
    c = s.add_parser("collect"); c.add_argument("--hours", type=float, default=24)
    c.add_argument("--from-file"); c.add_argument("--synthetic", action="store_true"); c.set_defaults(f=cmd_collect)
    t = s.add_parser("train"); t.add_argument("--experiments", default=str(EXP_CSV)); t.set_defaults(f=cmd_train)
    s.add_parser("analyze").set_defaults(f=cmd_analyze)
    w = s.add_parser("watch"); w.add_argument("--lookback", type=float, default=15, help="minutes")
    w.add_argument("--interval", type=int, default=60, help="seconds"); w.set_defaults(f=cmd_watch)
    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
