"""Service JSON must validate against hc_common.schemas (ScoredWindow, ScoreBreakdown)."""
import pytest

pytest.importorskip("pydantic")

import synth  # noqa: E402
from hc_common.schemas import ScoreBreakdown, ScoredWindow  # noqa: E402
from hc_ml.confidence import compute_confidence  # noqa: E402
from hc_ml.model import AnomalyModel  # noqa: E402


def test_scored_windows_and_scores_validate_against_schemas():
    model = AnomalyModel.train(synth.make_train(1001, 0.4), seed=1001)
    windows = model.score_events(synth.make_eval(2002, 0.4))
    assert windows
    for w in windows:
        parsed = ScoredWindow(**w)
        assert parsed.window_id == w["window_id"]
    top = max(windows, key=lambda w: w["anomaly"])
    scores, rationale = compute_confidence(top, ["execution"], ["execution", "lateral_movement"], [top["host"]])
    assert ScoreBreakdown(**scores).confidence == scores["confidence"] and rationale
