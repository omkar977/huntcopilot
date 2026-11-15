"""Page 7 helpers against the real control API (Streamlit itself is replaced by a stub)."""
import importlib.util
import sys
import threading
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gen_fake_redis import FakeRedis
from generator.api import create_server
from generator.runner import Runner

_CANDIDATES = [Path(__file__).resolve().parents[3] / "deploy" / "pages" / "7_Simulation.py",
               Path(__file__).resolve().parents[2] / "dashboard" / "pages" / "7_Simulation.py"]
PAGE = next((p for p in _CANDIDATES if p.exists()), _CANDIDATES[0])
pytestmark = pytest.mark.skipif(not PAGE.exists(), reason="page 7 file not found")
KEY = "page-test-key"


@pytest.fixture()
def page(monkeypatch):
    stub = types.ModuleType("streamlit")
    stub.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "streamlit", stub)
    spec = importlib.util.spec_from_file_location("sim_page", PAGE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def server(tmp_path, monkeypatch):
    runner = Runner(redis_factory=lambda: FakeRedis(), labels_path=lambda: str(tmp_path / "labels.json"))
    srv = create_server(runner, KEY, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    monkeypatch.setenv("HC_GENERATOR_URL", base)
    monkeypatch.setenv("HC_API_KEY", KEY)
    yield runner
    srv.shutdown()
    srv.server_close()


def test_page_file_has_no_import_side_effects(page):
    assert page.PROFILES == ["eval", "benign_train"] and "apt_chain" in page.SCENARIOS


def test_build_payload_rules(page):
    p = page.build_payload("benign_train", ["c2"], 1001, 24, "burst")
    assert p["scenarios"] == [] and "events_per_host_hour" not in p
    p = page.build_payload("eval", ["apt_chain"], 2002, 12, "realtime", 100)
    assert p == {"profile": "eval", "scenarios": ["apt_chain"], "seed": 2002, "duration_hours": 12.0,
                 "speed": "realtime", "events_per_host_hour": 100.0}


def test_progress_and_describe(page):
    assert page.progress_fraction({"state": "running", "produced": 50, "total": 200}) == 0.25
    assert page.progress_fraction({"state": "done", "produced": 200, "total": 200}) == 1.0
    assert page.progress_fraction({"state": "idle"}) == 0.0
    assert "failed" in page.describe({"state": "done", "run_id": "abcdef123", "error": "boom"})
    assert page.describe({"state": "idle"}) == "No run yet."


def test_full_run_through_real_api(page, server):
    body = page.build_payload("eval", ["phishing"], 5, 12, "burst", 60)
    run = page.request("POST", "/v1/run", body)
    server.wait(30)
    status = page.request("GET", "/v1/status")
    assert status["run_id"] == run["run_id"] and status["state"] == "done" and status["produced"] > 0
    assert page.progress_fraction(status) == 1.0


def test_errors_are_readable(page, server, monkeypatch):
    with pytest.raises(RuntimeError, match="at least|scenarios|unknown"):
        page.request("POST", "/v1/run", {"scenarios": ["nope"]})
    monkeypatch.setenv("HC_API_KEY", "wrong")
    with pytest.raises(RuntimeError, match="API key"):
        page.request("GET", "/v1/status")
    monkeypatch.setenv("HC_GENERATOR_URL", "http://127.0.0.1:1")
    with pytest.raises(RuntimeError, match="Cannot reach"):
        page.request("GET", "/v1/status")


def test_main_renders_without_crashing(page, monkeypatch):
    st = page.st
    st.columns = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
    st.selectbox = lambda *a, **k: "eval"
    st.multiselect = lambda *a, **k: ["apt_chain"]
    st.radio = lambda *a, **k: "burst"
    st.number_input = lambda *a, **k: 1
    page.main()
