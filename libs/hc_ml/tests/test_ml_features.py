"""Feature tests on the shared fixture and on small hand-built event lists (no network)."""
import copy
import json
import os
import re
from pathlib import Path

import pandas as pd

from hc_ml import features as F
from hc_ml.features import FEATURE_NAMES, compute_features, events_to_frame, build_stats, window_id_for

FIX = Path(os.getenv("HC_FIXTURES", Path(__file__).resolve().parents[3] / "tests" / "fixtures"))
EXPECTED = ["n_events", "n_process", "n_net", "n_auth", "n_file", "n_dns", "distinct_dst_ips",
            "distinct_dst_ports", "distinct_internal_dst_hosts", "n_smb_winrm", "n_ps_encoded",
            "n_office_child_ps", "n_remote_exec_tools", "n_cred_tools", "rare_process_score",
            "rare_parent_child_score", "bytes_out_sum", "beacon_cv", "new_domain_count", "auth_fail_rate",
            "hour_sin", "hour_cos"]


def load_fixture() -> list:
    return [json.loads(x) for x in (FIX / "events_sample.jsonl").read_text(encoding="utf-8").splitlines()]


def ev(i, ts, host, etype, **payload):
    base = {"event_id": f"x{i}", "ts": ts, "host": host, "event_type": etype, "tags": [],
            "process": None, "net": None, "auth": None, "file": None, "dns": None}
    key = {"process_create": "process", "network_conn": "net", "auth": "auth", "file_create": "file",
           "dns_query": "dns"}[etype]
    base[key] = payload
    return base


def test_feature_names_exact_and_ordered():
    assert FEATURE_NAMES == EXPECTED
    assert len(set(FEATURE_NAMES)) == 22


def test_window_id_is_sha1_of_host_and_start():
    import hashlib
    wid = window_id_for("WS-03", pd.Timestamp("2026-11-12T09:30:00Z"))
    assert wid == hashlib.sha1(b"WS-03|2026-11-12T09:30:00Z").hexdigest()
    assert len(wid) == 40


def test_windows_are_15_minute_tumbling_utc():
    events = load_fixture()
    df = events_to_frame(events)
    assert (df["win"].dt.minute % 15 == 0).all()
    assert (df["win"].dt.second == 0).all()
    assert (df["ts"] >= df["win"]).all()
    assert ((df["ts"] - df["win"]).dt.total_seconds() < 900).all()


def test_fixture_features_have_all_columns_and_no_nans():
    df = events_to_frame(load_fixture())
    feats = compute_features(df, build_stats(df))
    assert list(feats.columns) == FEATURE_NAMES
    assert not feats.isna().any().any()
    assert feats["n_events"].sum() == len(df)
    total = feats[["n_process", "n_net", "n_auth", "n_file", "n_dns"]].sum(axis=1)
    assert (total == feats["n_events"]).all()


def test_attack_counters_on_handbuilt_window():
    t = "2026-11-12T10:01:00Z"
    events = [
        ev(1, t, "WS-03", "process_create", name="powershell.exe", pid=1, cmdline="powershell.exe -nop -enc SQBFAFgAaABlAGw",
           parent_name="winword.exe"),
        ev(2, t, "WS-03", "process_create", name="psexec.exe", pid=2, cmdline="psexec.exe \\\\10.10.2.31 cmd",
           parent_name="powershell.exe"),
        ev(3, t, "WS-03", "process_create", name="procdump.exe", pid=3,
           cmdline="procdump.exe -ma lsass.exe x.dmp", parent_name="cmd.exe"),
        ev(4, t, "WS-03", "process_create", name="reg.exe", pid=4, cmdline="reg.exe save HKLM\\SAM s.save",
           parent_name="cmd.exe"),
        ev(5, t, "WS-03", "network_conn", dst_ip="10.10.2.21", dst_port=445, direction="internal", dst_host="FILE-01",
           bytes_out=100),
        ev(6, t, "WS-03", "network_conn", dst_ip="10.10.2.31", dst_port=5985, direction="internal", dst_host="DB-01",
           bytes_out=50),
        ev(7, t, "WS-03", "auth", logon_type=3, result="failure", target_user="adm_it"),
        ev(8, t, "WS-03", "auth", logon_type=3, result="success", target_user="adm_it"),
    ]
    df = events_to_frame(events)
    feats = compute_features(df, {"proc_freq": {"chrome.exe": 10}, "pair_freq": {}, "n_proc": 10, "domains": []})
    row = feats.iloc[0]
    assert row["n_ps_encoded"] == 1
    assert row["n_office_child_ps"] == 1
    assert row["n_remote_exec_tools"] == 1
    assert row["n_cred_tools"] == 2
    assert row["n_smb_winrm"] == 2
    assert row["distinct_internal_dst_hosts"] == 2
    assert row["bytes_out_sum"] == 150
    assert row["auth_fail_rate"] == 0.5
    assert row["rare_process_score"] > 0


def test_beacon_cv_regular_vs_irregular_vs_few_events():
    regular = [ev(i, f"2026-11-12T10:0{i}:00Z", "WS-01", "network_conn", dst_ip="203.0.113.50", dst_port=443,
                  direction="outbound") for i in range(6)]
    df = events_to_frame(regular)
    feats = compute_features(df, {"proc_freq": {}, "pair_freq": {}, "n_proc": 0, "domains": []})
    assert feats["beacon_cv"].iloc[0] < 0.01
    few = events_to_frame(regular[:4])
    assert compute_features(few, {"proc_freq": {}, "pair_freq": {}, "n_proc": 0, "domains": []})["beacon_cv"].iloc[0] == 1.0


def test_new_domain_count_uses_training_domains():
    t = "2026-11-12T10:01:00Z"
    events = [ev(1, t, "WS-01", "dns_query", query="mail.corp.test"),
              ev(2, t, "WS-01", "dns_query", query="cdn-sync.badhost.test")]
    stats = {"proc_freq": {}, "pair_freq": {}, "n_proc": 0, "domains": ["mail.corp.test"]}
    feats = compute_features(events_to_frame(events), stats)
    assert feats["new_domain_count"].iloc[0] == 1


def test_ground_truth_never_changes_features():
    events = load_fixture()
    flipped = copy.deepcopy(events)
    for e in flipped:
        e["gt"] = {"is_malicious": not e["gt"]["is_malicious"], "scenario": "x", "stage": "y"}
    a = events_to_frame(events)
    b = events_to_frame(flipped)
    fa = compute_features(a, build_stats(a))
    fb = compute_features(b, build_stats(b))
    pd.testing.assert_frame_equal(fa, fb)
    assert "gt" not in " ".join(a.columns)


def test_no_library_file_except_evaluate_reads_ground_truth():
    pattern = re.compile(r"""['"]gt['"]|['"]gt\.|\.gt\b|\bgt\.(?:is_malicious|scenario|stage)""")
    root = Path(F.__file__).parent
    for p in root.glob("*.py"):
        if p.name == "evaluate.py":
            continue
        assert not pattern.search(p.read_text(encoding="utf-8")), p.name
