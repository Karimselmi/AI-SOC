import json
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from . import config
from .features import FEATURES


def make_isolation_forest(contamination=config.CONTAMINATION):
    return Pipeline([
        ("log", FunctionTransformer(np.log1p)),
        ("scale", StandardScaler()),
        ("iforest", IsolationForest(n_estimators=300, contamination=contamination, random_state=42)),
    ])


def anomaly_scores(model, X):
    """Higher = more anomalous."""
    return -model.decision_function(X[FEATURES])


def binary_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def train_isolation_forest(labeled, baseline_ratio=0.7):
    """Train on the first 70% (in time) of NORMAL windows only; test on everything else."""
    normal = labeled[labeled["label"] == "normal"].sort_values("win")
    train = normal.iloc[: int(len(normal) * baseline_ratio)]
    test = labeled.drop(train.index)
    model = make_isolation_forest().fit(train[FEATURES])
    pred = (model.predict(test[FEATURES]) == -1).astype(int)
    metrics = binary_metrics(test["is_attack"], pred)
    metrics.update(n_train_windows=len(train), n_test_windows=len(test))
    joblib.dump(model, config.MODELS / "isolation_forest.joblib")
    return model, metrics


def train_random_forest(labeled):
    """Supervised scenario classifier. Group split by experiment run so that windows of the
    same attack run never appear in both train and test (avoids optimistic leakage)."""
    X, y = labeled[FEATURES], labeled["label"]
    groups = np.where(labeled["run_id"] >= 0, "run" + labeled["run_id"].astype(str),
                      "n" + labeled["win"].dt.strftime("%Y%m%d%H"))
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42).split(X, y, groups))
    rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42)
    rf.fit(X.iloc[tr], y.iloc[tr])
    rep = classification_report(y.iloc[te], rf.predict(X.iloc[te]), output_dict=True, zero_division=0)
    rep["feature_importance"] = dict(sorted(zip(FEATURES, map(float, rf.feature_importances_)),
                                            key=lambda kv: -kv[1]))
    joblib.dump(rf, config.MODELS / "random_forest.joblib")
    return rf, rep


def load_model(name):
    p = config.MODELS / f"{name}.joblib"
    return joblib.load(p) if p.exists() else None


def save_metrics(d):
    (config.REPORTS / "metrics.json").write_text(json.dumps(d, indent=2))
