"""Entry point tests for main.py (batch mode, argument handling). Owner: M2."""
import importlib.util
import json
import types
from pathlib import Path

from test_detector_service import FakeOpenSearch, FakeRedis

from hc_detect.tests.helpers import load_sample

spec = importlib.util.spec_from_file_location("detector_main_under_test", Path(__file__).resolve().parents[1] / "main.py")
main_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main_module)

SETTINGS = types.SimpleNamespace(hc_events_index_prefix="hc-events", hc_alerts_index="hc-alerts", hc_api_key="k")


def test_batch_mode_prints_summary(capsys):
    client = FakeOpenSearch(load_sample())
    code = main_module.main(["batch", "--from", "2026-11-12T09:00:00Z", "--to", "2026-11-12T11:00:00Z"],
                            settings=SETTINGS, client=client, redis_client=FakeRedis())
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out["alerts_created"] > 0 and "per_rule" in out


def test_batch_mode_needs_range_and_follow_needs_key(capsys):
    client = FakeOpenSearch([])
    assert main_module.main(["batch"], settings=SETTINGS, client=client, redis_client=None) == 2
    nokey = types.SimpleNamespace(hc_events_index_prefix="hc-events", hc_alerts_index="hc-alerts", hc_api_key="")
    assert main_module.main(["follow"], settings=nokey, client=client, redis_client=None) == 2
