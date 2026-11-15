"""Evaluation against ground truth. This is the ONLY module allowed to read the labels (spec 6.2, 9.4)."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from . import THRESHOLD, WINDOW_MINUTES
from .features import window_id_for


def label_windows(events: list[dict]) -> dict[str, bool]:
    """Map window_id to True when any event in that host window is labelled malicious."""
    labels: dict[str, bool] = {}
    for e in events:
        ts = pd.Timestamp(e["ts"])
        ts = ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")
        wid = window_id_for(e["host"], ts.floor(f"{WINDOW_MINUTES}min"))
        bad = bool((e.get("gt") or {}).get("is_malicious", False))
        labels[wid] = labels.get(wid, False) or bad
    return labels


def evaluate_windows(scored: list[dict], events: list[dict], threshold: float = THRESHOLD) -> dict:
    """Precision, recall, F1, PR-AUC and false positives per host-day at the given threshold."""
    labels = label_windows(events)
    y = np.array([labels.get(w["window_id"], False) for w in scored], dtype=bool)
    s = np.array([w["anomaly"] for w in scored], dtype=float)
    pred = s >= threshold
    tp, fp, fn = int(np.sum(pred & y)), int(np.sum(pred & ~y)), int(np.sum(~pred & y))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    pr_auc = float(average_precision_score(y, s)) if y.any() else 0.0
    return {
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4), "pr_auc": round(pr_auc, 4),
        "false_positives_per_host_day": round(fp / _host_days(scored), 4),
        "tp": tp, "fp": fp, "fn": fn, "n_windows": int(len(scored)), "n_positive_windows": int(y.sum()),
        "threshold": threshold,
    }


def _host_days(scored: list[dict]) -> float:
    """Number of hosts times the span in days (at least one day)."""
    if not scored:
        return 1.0
    hosts = {w["host"] for w in scored}
    first = min(pd.Timestamp(w["ts_first"]) for w in scored)
    last = max(pd.Timestamp(w["ts_last"]) for w in scored)
    span = max((last - first).total_seconds() / 86400.0, 1.0)
    return len(hosts) * span
