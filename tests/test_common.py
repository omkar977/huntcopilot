"""Tests for hc_common helpers (needs pydantic-settings only for clients.py)."""
from datetime import datetime, timezone

import pytest

from hc_common import constants, ids


def test_uuid5_is_deterministic():
    assert ids.uuid5_hex(7, 1) == ids.uuid5_hex(7, 1)
    assert ids.uuid5_hex(7, 1) != ids.uuid5_hex(7, 2)
    assert len(ids.uuid5_hex(7, 1)) == 32


def test_sha1_hex_joins_with_pipe():
    assert ids.sha1_hex("a", "b") == ids.sha1_hex("a|b")
    assert len(ids.sha1_hex("x")) == 40


def test_constants_consistent():
    assert len(constants.ASSETS) == 12
    assert set(constants.RULE_STAGE.values()) <= set(constants.STAGES)
    assert set(constants.CRITICALITY) == {a["host"] for a in constants.ASSETS}
    assert not any(f.startswith("gt") for f in constants.ALLOWED_FIELDS)


def test_time_helpers():
    clients = pytest.importorskip("hc_common.clients")
    dt = clients.parse_ts("2026-11-12T09:30:00Z")
    assert dt == datetime(2026, 11, 12, 9, 30, tzinfo=timezone.utc)
    assert clients.iso(dt) == "2026-11-12T09:30:00Z"
    with pytest.raises(ValueError):
        clients.parse_ts("2026-11-12T09:30:00")
