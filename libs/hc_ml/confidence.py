"""Hunt confidence score (spec Section 9.3) and its deterministic English rationale."""
from __future__ import annotations

import math
from typing import Iterable, Optional

from hc_common.constants import CRITICALITY, STAGES

W_ANOMALY, W_COVERAGE, W_CRITICALITY, W_CERTAINTY = 0.35, 0.25, 0.20, 0.20
DEFAULT_CRITICALITY = 1


def _clip01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def label_for(confidence: float) -> str:
    """80 or more is high, 60 to 79 medium, below 60 low."""
    if confidence >= 80:
        return "high"
    if confidence >= 60:
        return "medium"
    return "low"


def _round_half_up(v: float) -> int:
    return int(math.floor(v + 0.5))


def _fmt(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else f"{v:.2f}"


def _stage_order(stages: Iterable[str]) -> list[str]:
    known = [s for s in STAGES if s in set(stages)]
    return known + sorted(set(stages) - set(STAGES))


def _top_host(hosts: list[str]) -> tuple[int, str]:
    best, name = 0, ""
    for h in sorted(set(hosts)):
        k = CRITICALITY.get(h, DEFAULT_CRITICALITY)
        if k > best:
            best, name = k, h
    return best, name


def compute_confidence(window: dict, stages_found: list[str], expected_stages: list[str],
                       hosts: list[str]) -> tuple[dict, str]:
    """Return (ScoreBreakdown dict, rationale). Pure and deterministic.

    window needs anomaly_if, anomaly_seq, anomaly, uncertainty and top_features (name, value, z).
    """
    a = _clip01(window.get("anomaly", 0.0))
    u = _clip01(window.get("uncertainty", 0.0))
    expected = sorted(set(expected_stages))
    found = sorted(set(stages_found) & set(expected))
    v = len(found) / len(expected) if expected else 0.0
    kmax, khost = _top_host(list(hosts))
    k = kmax / 5.0
    conf = 100.0 * (W_ANOMALY * a + W_COVERAGE * v + W_CRITICALITY * k + W_CERTAINTY * (1.0 - u))
    conf = max(0.0, min(100.0, conf))
    scores = {
        "anomaly_if": round(_clip01(window.get("anomaly_if", 0.0)), 4),
        "anomaly_seq": round(_clip01(window.get("anomaly_seq", 0.0)), 4),
        "anomaly": round(a, 4),
        "coverage": round(v, 4),
        "criticality": round(k, 4),
        "uncertainty": round(u, 4),
        "confidence": round(conf, 2),
    }
    return scores, build_rationale(scores, found, expected, kmax, khost, window.get("top_features", []))


def build_rationale(scores: dict, found: list[str], expected: list[str], kmax: int, khost: str,
                    top_features: Optional[list] = None) -> str:
    """Deterministic paragraph: same inputs always give the same text."""
    conf = scores["confidence"]
    parts = [
        f"Confidence {_round_half_up(conf)} of 100 ({label_for(conf)}).",
        f"Anomaly strength {scores['anomaly']:.2f} (isolation forest {scores['anomaly_if']:.2f}, "
        f"sequence model {scores['anomaly_seq']:.2f}).",
    ]
    names = ", ".join(_stage_order(found)) if found else "none"
    parts.append(f"Evidence coverage {len(found)} of {len(expected)} expected stages ({names}).")
    where = f" ({khost})" if khost else ""
    parts.append(f"Asset criticality {kmax} of 5{where}.")
    parts.append(f"Model uncertainty {scores['uncertainty']:.2f}.")
    signals = [f"{f['name']} = {_fmt(f['value'])} (z = {f['z']:.1f})" for f in (top_features or [])]
    if signals:
        parts.append("Strongest signals: " + ", ".join(signals) + ".")
    else:
        parts.append("No single feature stood out against the training baseline.")
    return " ".join(parts)
