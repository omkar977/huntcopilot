"""Evaluation metrics (the only code allowed to read labels) and JSONL helpers."""
import json

from hc_ml.cli import main
from hc_ml.evaluate import evaluate_windows, label_windows
from hc_ml.features import window_id_for
from hc_ml.jsonl import read_jsonl, tag_train
import pandas as pd


def _ev(i, ts, host, mal):
    return {"event_id": f"e{i}", "ts": ts, "host": host, "gt": {"is_malicious": mal}}


def _w(host, start, anomaly, ts_first, ts_last):
    wid = window_id_for(host, pd.Timestamp(start))
    return {"window_id": wid, "host": host, "anomaly": anomaly, "ts_first": pd.Timestamp(ts_first),
            "ts_last": pd.Timestamp(ts_last)}


def test_label_windows_any_malicious_event_makes_window_positive():
    events = [_ev(1, "2026-11-12T10:01:00Z", "A", False), _ev(2, "2026-11-12T10:05:00Z", "A", True),
              _ev(3, "2026-11-12T10:20:00Z", "A", False)]
    labels = label_windows(events)
    assert labels[window_id_for("A", pd.Timestamp("2026-11-12T10:00:00Z"))] is True
    assert labels[window_id_for("A", pd.Timestamp("2026-11-12T10:15:00Z"))] is False


def test_metrics_values():
    events = [_ev(1, "2026-11-12T10:01:00Z", "A", True), _ev(2, "2026-11-12T10:16:00Z", "A", False),
              _ev(3, "2026-11-12T10:31:00Z", "A", True), _ev(4, "2026-11-12T10:46:00Z", "A", False)]
    scored = [_w("A", "2026-11-12T10:00:00Z", 0.9, "2026-11-12T10:01:00Z", "2026-11-12T10:01:00Z"),
              _w("A", "2026-11-12T10:15:00Z", 0.7, "2026-11-12T10:16:00Z", "2026-11-12T10:16:00Z"),
              _w("A", "2026-11-12T10:30:00Z", 0.2, "2026-11-12T10:31:00Z", "2026-11-12T10:31:00Z"),
              _w("A", "2026-11-12T10:45:00Z", 0.1, "2026-11-12T10:46:00Z", "2026-11-12T10:46:00Z")]
    r = evaluate_windows(scored, events)
    assert (r["tp"], r["fp"], r["fn"]) == (1, 1, 1)
    assert r["precision"] == 0.5 and r["recall"] == 0.5 and r["f1"] == 0.5
    assert r["false_positives_per_host_day"] == 1.0
    assert 0 < r["pr_auc"] <= 1


def test_empty_scored_list_is_safe():
    r = evaluate_windows([], [])
    assert r["precision"] == 0.0 and r["recall"] == 0.0 and r["n_windows"] == 0


def test_jsonl_roundtrip_and_tag_train(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text(json.dumps({"event_id": "1", "tags": []}) + "\n\n", encoding="utf-8")
    events = tag_train(read_jsonl(str(p)))
    assert events[0]["tags"] == ["train"]
    assert tag_train(events)[0]["tags"] == ["train"]


def test_cli_train_and_evaluate(tmp_path, capsys):
    import synth
    tr = synth.make_train(5, scale=0.4)
    ev = synth.make_eval(6, scale=0.4)
    f1, f2 = tmp_path / "train.jsonl", tmp_path / "eval.jsonl"
    f1.write_text("\n".join(json.dumps(e) for e in tr), encoding="utf-8")
    f2.write_text("\n".join(json.dumps(e) for e in ev), encoding="utf-8")
    assert main(["train", "--events", str(f1), "--model-dir", str(tmp_path / "m"), "--seed", "1001"]) == 0
    assert main(["evaluate", "--events", str(f2), "--model-dir", str(tmp_path / "m")]) == 0
    out = capsys.readouterr().out
    assert '"precision"' in out and '"model_id"' in out
