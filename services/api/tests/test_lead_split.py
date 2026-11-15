"""Lead regression test: a benign host with two peers must still be split off (real-data case)."""
from datetime import datetime, timezone

from hc_api.assembly import split_weak_hosts
from hc_common.schemas import Alert, AttackChain, Edge, Node


def _alert(host):
    now = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
    return Alert.model_construct(alert_id="a-" + host, host=host, ts_first=now, ts_last=now)


def _chain(pairs):
    nodes = {h for p in pairs for h in p}
    ts = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
    return AttackChain.model_construct(
        nodes=[Node.model_construct(node_id=f"host:{h}") for h in sorted(nodes)],
        edges=[Edge.model_construct(src=f"host:{a}", dst=f"host:{b}", kind="connected", ts=ts, event_id="e")
               for a, b in pairs])


def test_two_peer_benign_host_is_split():
    chain = _chain([("WS-08", "FILE-01"), ("WS-08", "WEB-01"), ("WS-03", "FILE-01")])
    groups = [["FILE-01", "WEB-01", "WS-03", "WS-08"]]
    out = split_weak_hosts(groups, chain, [_alert("WS-03"), _alert("FILE-01")])
    assert ["FILE-01", "WS-03"] in out and ["WS-08"] in out and ["WEB-01"] in out


def test_group_without_alerts_is_left_alone():
    out = split_weak_hosts([["A", "B"]], _chain([("A", "B")]), [])
    assert out == [["A", "B"]]
