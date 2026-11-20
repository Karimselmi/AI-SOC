import time
from .features import FEATURES, build_windows
from .models import anomaly_scores
from .correlate import correlate


def analyze(alerts, if_model, rf_model=None):
    """alerts (normalized DataFrame) -> (incidents, scored windows, seconds elapsed)."""
    t0 = time.perf_counter()
    win = build_windows(alerts)
    if win.empty:
        return [], win, 0.0
    win["anomaly_score"] = anomaly_scores(if_model, win)
    win["is_anomaly"] = if_model.predict(win[FEATURES]) == -1
    win["ml_scenario"] = rf_model.predict(win[FEATURES]) if rf_model is not None else None
    flagged = win[win["is_anomaly"]]
    incidents = correlate(alerts, flagged)
    return incidents, win, time.perf_counter() - t0
