from soc_agent.synthetic import generate
from soc_agent.features import build_windows
from soc_agent.labeling import label_windows
from soc_agent.models import train_isolation_forest
from soc_agent.pipeline import analyze


def test_end_to_end_on_synthetic():
    alerts, exp = generate()
    import pandas as pd
    exp["start"] = pd.to_datetime(exp["start"], utc=True, format="ISO8601"); exp["end"] = pd.to_datetime(exp["end"], utc=True, format="ISO8601")
    labeled = label_windows(build_windows(alerts), exp)
    model, m = train_isolation_forest(labeled)
    assert m["recall"] >= 0.8
    incidents, _, _ = analyze(alerts, model)
    assert incidents and incidents[0]["risk_score"] > 0
