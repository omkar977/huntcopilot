"""Dashboard helpers and a smoke run of pages 1 and 3 with a fake streamlit module. Owner: M2."""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

from hc_hunt import views
from hc_hunt.chain import build_chain

from hc_detect.tests.helpers import load_sample

PAGES = Path(__file__).resolve().parents[3] / "services" / "dashboard" / "pages"


def make_finding(fid="f" * 32, confidence=78.4, hosts=("WS-03", "DB-01")):
    events = [e for e in load_sample() if e["gt"]["is_malicious"]]
    chain = build_chain(events, {"WS-03": 0.9})
    return {
        "finding_id": fid, "run_id": "r", "hosts": list(hosts), "users": ["carol"],
        "ts_first": "2026-11-12T09:30:00Z", "ts_last": "2026-11-12T10:00:03Z", "event_ids": ["a"], "alert_ids": ["b"],
        "technique_ids": ["T1059.001"], "stages_found": ["execution", "lateral_movement"],
        "scores": {"anomaly_if": 0.8, "anomaly_seq": 0.6, "anomaly": 0.72, "coverage": 1.0, "criticality": 1.0,
                   "uncertainty": 0.18, "confidence": confidence},
        "cluster_id": 0, "top_features": [{"name": "n_smb_winrm", "value": 12.0, "z": 6.1}],
        "rationale": "Confidence 78 of 100 (medium).", "chain": chain.model_dump(mode="json"),
        "recommended_actions": [], "created_at": "2026-11-12T10:05:00Z",
    }


def test_confidence_label_thresholds():
    assert [views.confidence_label(x) for x in (100, 80, 79.9, 60, 59.9, 0)] == ["high", "high", "medium", "medium", "low", "low"]


def test_finding_rows_sorted_by_confidence():
    rows = views.finding_rows([make_finding("a" * 32, 50), make_finding("b" * 32, 91), make_finding("c" * 32, 70)])
    assert [r["confidence"] for r in rows] == [91, 70, 50]
    assert [r["level"] for r in rows] == ["high", "medium", "low"]
    assert rows[0]["hosts"] == "WS-03, DB-01" and rows[0]["first_seen"] == "2026-11-12 09:30:00"


def test_score_components_and_rows():
    comp = views.score_components(make_finding())
    assert comp == {"Anomaly (A)": 0.72, "Evidence coverage (V)": 1.0, "Asset criticality (K)": 1.0,
                    "Certainty (1 - U)": 0.82}
    assert views.feature_rows(make_finding()) == [{"feature": "n_smb_winrm", "value": 12.0, "z_score": 6.1}]
    assert views.score_components({}) == {"Anomaly (A)": 0.0, "Evidence coverage (V)": 0.0,
                                          "Asset criticality (K)": 0.0, "Certainty (1 - U)": 1.0}


def test_alert_rows_newest_first():
    rows = views.alert_rows([{"ts_first": "2026-11-12T09:00:00Z", "rule_id": "HC-001"},
                             {"ts_first": "2026-11-12T10:00:00Z", "rule_id": "HC-002", "event_ids": ["x", "y"]}])
    assert [r["rule_id"] for r in rows] == ["HC-002", "HC-001"] and rows[0]["events"] == 2


def test_chain_helpers():
    chain = views.chain_of(make_finding())
    assert views.host_edge_count(chain) >= 2
    rows = views.edge_rows(chain)
    assert rows and {"time", "kind", "from", "to", "event_id"} == set(rows[0])
    assert views.chain_of({}).nodes == []
    assert len(views.legend_rows()) == 3


def test_items_of_and_short_ts():
    assert views.items_of({"items": [1, 2], "total": 2}) == [1, 2]
    assert views.items_of([3]) == [3] and views.items_of(None) == []
    assert views.short_ts("2026-11-12T09:30:00Z") == "2026-11-12 09:30:00" and views.short_ts(None) == ""


def test_call_api_picks_name_and_filters_kwargs():
    seen = {}
    module = types.SimpleNamespace(get_findings=lambda min_confidence=0: seen.update(m=min_confidence) or {"items": []})
    assert views.call_api(module, ("list_findings", "get_findings"), min_confidence=5, host="x", limit=9) == {"items": []}
    assert seen == {"m": 5}
    wide = types.SimpleNamespace(list_alerts=lambda **kw: kw)
    assert views.call_api(wide, ("list_alerts",), status="new", limit=3) == {"status": "new", "limit": 3}
    with pytest.raises(views.ApiClientError):
        views.call_api(types.SimpleNamespace(), ("list_findings", "findings"))


# ------------------------------------------------------------------ fake streamlit
class _Ctx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __getattr__(self, name):
        return lambda *a, **k: None


class FakeStreamlit:
    def __init__(self):
        self.calls = []
        self.session_state = {}

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            if name == "columns":
                spec = args[0]
                return [_Ctx() for _ in range(spec if isinstance(spec, int) else len(spec))]
            if name == "tabs":
                return [_Ctx() for _ in args[0]]
            if name == "slider":
                return args[1] if len(args) > 1 else 0
            if name == "selectbox":
                options = list(args[1])
                return options[0] if options else None
            if name == "text_input":
                return kwargs.get("value", "")
            if name in ("expander", "container", "spinner"):
                return _Ctx()
            return None
        return call

    def names(self):
        return [c[0] for c in self.calls]


def load_page(filename, fake_st, fake_api):
    sys.modules["streamlit"] = fake_st
    if fake_api is None:
        sys.modules.pop("api_client", None)
    else:
        sys.modules["api_client"] = fake_api
    spec = importlib.util.spec_from_file_location("page_" + filename[0], PAGES / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def restore_modules():
    saved = {k: sys.modules.get(k) for k in ("streamlit", "api_client")}
    yield
    for key, value in saved.items():
        if value is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = value


def fake_api(findings=None, alerts=None, fail=False):
    def list_findings(min_confidence=0, host=None, limit=100):
        if fail:
            raise RuntimeError("API down")
        return {"items": findings or [], "total": len(findings or [])}

    def list_alerts(status=None, rule_id=None, host=None, limit=100):
        return {"items": alerts or [], "total": len(alerts or [])}

    return types.SimpleNamespace(list_findings=list_findings, list_alerts=list_alerts)


def test_page1_renders_findings_and_alerts():
    st = FakeStreamlit()
    api = fake_api([make_finding()], [{"ts_first": "2026-11-12T09:30:08Z", "rule_id": "HC-001", "severity": 4}])
    load_page("1_Alert_Queue.py", st, api).render()
    names = st.names()
    assert {"title", "tabs", "metric", "bar_chart", "info", "dataframe"} <= set(names)
    assert "error" not in names


def test_page1_shows_error_not_traceback_when_api_fails():
    st = FakeStreamlit()
    load_page("1_Alert_Queue.py", st, fake_api(fail=True)).render()
    assert "error" in st.names()
    assert not any("Traceback" in str(c) for c in st.calls)


def test_page1_without_api_client_shows_error():
    st = FakeStreamlit()
    load_page("1_Alert_Queue.py", st, None).render()
    assert "error" in st.names()


def test_page3_draws_graph_legend_and_edges():
    st = FakeStreamlit()
    load_page("3_Attack_Chain.py", st, fake_api([make_finding()])).render()
    names = st.names()
    assert "graphviz_chart" in names and "dataframe" in names and "error" not in names
    dot = next(c for c in st.calls if c[0] == "graphviz_chart")[1][0]
    assert dot.startswith("digraph attack_chain {")


def test_page3_empty_and_error_states():
    st = FakeStreamlit()
    load_page("3_Attack_Chain.py", st, fake_api([])).render()
    assert "info" in st.names() and "graphviz_chart" not in st.names()
    st2 = FakeStreamlit()
    load_page("3_Attack_Chain.py", st2, fake_api(fail=True)).render()
    assert "error" in st2.names()
    bad = make_finding()
    bad["chain"] = {"nodes": "oops"}
    st3 = FakeStreamlit()
    load_page("3_Attack_Chain.py", st3, fake_api([bad])).render()
    assert "error" in st3.names()
