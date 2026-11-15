"""Confidence formula, labels and deterministic rationale."""
from hc_ml.confidence import compute_confidence, label_for

WINDOW = {"anomaly_if": 0.8, "anomaly_seq": 0.6, "anomaly": 0.72, "uncertainty": 0.18,
          "top_features": [{"name": "n_smb_winrm", "value": 12.0, "z": 6.1},
                           {"name": "n_ps_encoded", "value": 1.0, "z": 4.8}]}


def test_formula_matches_spec():
    scores, _ = compute_confidence(WINDOW, ["execution", "lateral_movement"], ["execution", "lateral_movement"],
                                   ["WS-03", "DB-01"])
    expected = 100 * (0.35 * 0.72 + 0.25 * 1.0 + 0.20 * 1.0 + 0.20 * (1 - 0.18))
    assert abs(scores["confidence"] - expected) < 0.01
    assert scores["coverage"] == 1.0 and scores["criticality"] == 1.0


def test_rationale_text_is_exact_and_deterministic():
    args = (WINDOW, ["lateral_movement", "execution"], ["execution", "lateral_movement"], ["WS-03", "DB-01"])
    s1, t1 = compute_confidence(*args)
    s2, t2 = compute_confidence(*args)
    assert (s1, t1) == (s2, t2)
    assert t1 == ("Confidence 87 of 100 (high). Anomaly strength 0.72 (isolation forest 0.80, sequence model 0.60). "
                  "Evidence coverage 2 of 2 expected stages (execution, lateral_movement). "
                  "Asset criticality 5 of 5 (DB-01). Model uncertainty 0.18. "
                  "Strongest signals: n_smb_winrm = 12 (z = 6.1), n_ps_encoded = 1 (z = 4.8).")


def test_label_boundaries():
    assert label_for(80) == "high" and label_for(79.99) == "medium"
    assert label_for(60) == "medium" and label_for(59.99) == "low"


def test_partial_coverage_and_workstation_criticality():
    scores, text = compute_confidence(WINDOW, ["execution"], ["execution", "lateral_movement"], ["WS-03"])
    assert scores["coverage"] == 0.5 and scores["criticality"] == 0.4
    assert "1 of 2 expected stages (execution)" in text and "2 of 5 (WS-03)" in text


def test_no_expected_stages_and_no_features():
    scores, text = compute_confidence({"anomaly_if": 0, "anomaly_seq": 0, "anomaly": 0, "uncertainty": 1,
                                       "top_features": []}, [], [], ["UNKNOWN-1"])
    assert scores["coverage"] == 0.0 and scores["confidence"] == 4.0
    assert "No single feature stood out" in text and "(none)" in text


def test_extra_found_stages_do_not_inflate_coverage():
    scores, _ = compute_confidence(WINDOW, ["execution", "c2", "initial_access"], ["execution"], ["WS-03"])
    assert scores["coverage"] == 1.0


def test_values_stay_in_range():
    wild = {"anomaly_if": 5, "anomaly_seq": -2, "anomaly": 9, "uncertainty": -3, "top_features": []}
    scores, _ = compute_confidence(wild, ["execution"], ["execution"], ["DC-01"])
    assert 0 <= scores["confidence"] <= 100
    for k in ("anomaly_if", "anomaly_seq", "anomaly", "uncertainty"):
        assert 0 <= scores[k] <= 1
