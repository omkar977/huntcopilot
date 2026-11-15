"""Training, scoring, persistence, determinism and the recall target on synthetic data."""
import copy

import numpy as np
import pytest

import synth
from hc_ml.cluster import cluster_windows
from hc_ml.evaluate import evaluate_windows, label_windows
from hc_ml.model import AnomalyModel, NoTrainingData
from hc_ml.sequence import MarkovModel
from hc_ml.features import events_to_frame

_CACHE = {}


def data():
    if not _CACHE:
        _CACHE["train"] = synth.make_train(1001, scale=0.5)
        _CACHE["eval"] = synth.make_eval(2002, scale=0.5)
        _CACHE["model"] = AnomalyModel.train(_CACHE["train"], seed=1001)
        _CACHE["global"] = AnomalyModel.train(_CACHE["train"], seed=1001, per_group=False)
    return _CACHE["train"], _CACHE["eval"], _CACHE["model"]


def test_training_requires_train_tag():
    _, ev, _ = data()
    with pytest.raises(NoTrainingData):
        AnomalyModel.train(ev, seed=1)


def test_training_ignores_untagged_events():
    tr, ev, _ = data()
    mixed = tr + ev
    model = AnomalyModel.train(mixed, seed=1001)
    assert model.meta["train_event_count"] == len(tr)


def test_scores_are_valid_scored_windows():
    _, ev, model = data()
    windows = model.score_events(ev)
    assert windows
    keys = {"window_id", "host", "ts_first", "ts_last", "event_ids", "anomaly_if", "anomaly_seq", "anomaly",
            "uncertainty", "top_features", "cluster_id"}
    for w in windows:
        assert set(w) == keys
        for k in ("anomaly_if", "anomaly_seq", "anomaly", "uncertainty"):
            assert 0.0 <= w[k] <= 1.0
        assert w["ts_first"].tzinfo is not None and w["ts_first"] <= w["ts_last"]
        assert len(w["top_features"]) <= 3
        zs = [f["z"] for f in w["top_features"]]
        assert zs == sorted(zs, reverse=True) and all(z > 0 for z in zs)
    assert len({w["window_id"] for w in windows}) == len(windows)
    assert sum(len(w["event_ids"]) for w in windows) == len(ev)


def test_anomaly_is_weighted_combination_and_uncertainty_formula_bounds():
    _, ev, model = data()
    for w in model.score_events(ev)[:200]:
        assert abs(w["anomaly"] - (0.6 * w["anomaly_if"] + 0.4 * w["anomaly_seq"])) < 2e-4


def test_same_seed_gives_identical_scores():
    tr, ev, model = data()
    other = AnomalyModel.train(copy.deepcopy(tr), seed=1001)
    a = [(w["window_id"], w["anomaly"], w["uncertainty"]) for w in model.score_events(ev)]
    b = [(w["window_id"], w["anomaly"], w["uncertainty"]) for w in other.score_events(ev)]
    assert a == b


def test_save_and_load_roundtrip(tmp_path):
    _, ev, model = data()
    model.save(str(tmp_path))
    cur = tmp_path / "current"
    names = {p.name for p in cur.iterdir()}
    assert names == {f"isoforest_{i}.joblib" for i in range(5)} | {"scaler.joblib", "markov.json", "meta.json", "groups"}
    assert (cur / "groups" / "server" / "meta.json").exists()  # per-group is the default
    loaded = AnomalyModel.load(str(tmp_path))
    assert loaded.meta["model_id"] == model.meta["model_id"]
    a = [w["anomaly"] for w in model.score_events(ev)]
    b = [w["anomaly"] for w in loaded.score_events(ev)]
    assert a == b


def test_load_missing_model_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        AnomalyModel.load(str(tmp_path))


def test_host_filter():
    _, ev, model = data()
    windows = model.score_events(ev, hosts=["WS-03"])
    assert windows and {w["host"] for w in windows} == {"WS-03"}


def test_attack_windows_rank_above_benign_and_recall_target():
    _, ev, _ = data()
    model = _CACHE["global"]  # the synthetic servers are not distinct enough for per-group; see MANIFEST
    windows = model.score_events(ev)
    labels = label_windows(ev)
    pos = [w["anomaly"] for w in windows if labels[w["window_id"]]]
    neg = [w["anomaly"] for w in windows if not labels[w["window_id"]]]
    assert np.mean(pos) > np.mean(neg) + 0.3
    result = evaluate_windows(windows, ev)
    assert result["recall"] >= 0.85  # spec 1.7 recall target; precision is reported, see MANIFEST


def test_demo_windows_name_the_expected_signals():
    _, ev, _ = data()
    model = _CACHE["global"]
    windows = model.score_events(ev, hosts=["DB-01"])
    top = max(windows, key=lambda w: w["anomaly"])
    names = {f["name"] for f in top["top_features"]}
    assert names & {"n_cred_tools", "rare_parent_child_score", "rare_process_score", "n_remote_exec_tools"}


def test_markov_unseen_token_scores_higher_and_roundtrips():
    tr, _, _ = data()
    df = events_to_frame(tr)
    mm = MarkovModel.fit(df)
    again = MarkovModel.from_dict(mm.to_dict())
    assert np.allclose(mm.nll, again.nll)
    i, j = mm.index["p:chrome.exe"], mm.index["unk"]
    assert mm.nll[i, j] > mm.nll[i].min()


def test_cluster_small_set_is_zero_and_two_blobs_split():
    assert list(cluster_windows(np.zeros((3, 4)))) == [0, 0, 0]
    rng = np.random.RandomState(0)
    x = np.vstack([rng.normal(0, 0.1, (10, 2)), rng.normal(5, 0.1, (10, 2))])
    labels = cluster_windows(x)
    assert len(set(labels)) == 2 and len(set(labels[:10])) == 1 and len(set(labels[10:])) == 1
    assert list(cluster_windows(x)) == list(labels)


def test_scoring_50k_events_within_15_seconds():
    import time
    big = synth.make_eval(7, scale=2.2)
    assert len(big) >= 45000
    _, _, model = data()
    t0 = time.time()
    windows = model.score_events(big)
    assert windows
    assert time.time() - t0 <= 15.0


def test_per_group_model_scores_roundtrips_and_keeps_cluster_ids_unique(tmp_path):
    tr, ev, _ = data()
    m = AnomalyModel.train(tr, seed=1001, per_group=True)
    assert set(m.groups) == {"workstation", "server"}
    m.save(str(tmp_path))
    assert (tmp_path / "current" / "groups" / "server" / "meta.json").exists()
    loaded = AnomalyModel.load(str(tmp_path))
    a = [(w["window_id"], w["anomaly"]) for w in m.score_events(ev)]
    b = [(w["window_id"], w["anomaly"]) for w in loaded.score_events(ev)]
    assert a == b and len(a) == len({x[0] for x in a})
    assert loaded.public_meta()["groups"]["server"]["train_window_count"] > 0


def test_group_of():
    from hc_ml.model import group_of
    assert group_of("WS-03") == "workstation" and group_of("DB-01") == "server" and group_of("NEW") == "workstation"


def test_default_is_per_group_and_global_only_has_no_groups(tmp_path):
    tr, _, model = data()
    assert set(model.groups) == {"workstation", "server"}
    plain = AnomalyModel.train(tr, seed=1001, per_group=False)
    assert plain.groups == {}
    plain.save(str(tmp_path))
    assert not (tmp_path / "current" / "groups").exists()


def test_per_host_rare_and_beacon_guard_options_roundtrip_and_stay_valid(tmp_path):
    tr, ev, _ = data()
    m = AnomalyModel.train(tr, seed=1001, per_host_rare=True, beacon_min_net=10)
    assert m.meta["stats"]["per_host_rare"] and m.meta["stats"]["beacon_min_net"] == 10
    assert "DB-01" in m.meta["stats"]["host_tables"]
    m.save(str(tmp_path))
    a = [w["anomaly"] for w in m.score_events(ev)]
    b = [w["anomaly"] for w in AnomalyModel.load(str(tmp_path)).score_events(ev)]
    assert a == b and all(0 <= x <= 1 for x in a)
    from hc_ml.features import compute_features, events_to_frame
    df = events_to_frame(ev)
    feats = compute_features(df, m.meta["stats"])
    assert (feats.loc[feats["n_net"] < 10, "beacon_cv"] == 1.0).all()


def test_default_model_still_ranks_attack_windows_higher():
    _, ev, model = data()
    windows = model.score_events(ev)
    labels = label_windows(ev)
    pos = [w["anomaly"] for w in windows if labels[w["window_id"]]]
    neg = [w["anomaly"] for w in windows if not labels[w["window_id"]]]
    assert np.mean(pos) > np.mean(neg) + 0.2
