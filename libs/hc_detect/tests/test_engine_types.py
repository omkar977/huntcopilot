"""Threshold, sequence and periodicity semantics (Appendix J). Owner: M2."""
from hc_detect.engine import evaluate
from hc_detect.loader import parse_rule

from .helpers import net, proc

CONN = [
    {"field": "event_type", "op": "eq", "value": "network_conn"},
    {"field": "net.direction", "op": "eq", "value": "internal"},
]


def threshold_rule(**extra):
    data = {"id": "HC-901", "name": "Fan-out", "severity": 4, "type": "threshold", "group_by": ["host"],
            "where": CONN, "window_seconds": 100, "distinct_field": "net.dst_ip", "distinct_gte": 3}
    data.update(extra)
    return parse_rule(data)


def conns(times, ips, **kw):
    return [net(t, ip, port=445, direction="internal", **kw) for t, ip in zip(times, ips)]


def test_threshold_distinct_fires_when_reached():
    events = conns([0, 10, 20], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
    alerts = evaluate(threshold_rule(), events)
    assert len(alerts) == 1
    assert alerts[0].ts_first.second == 0 and alerts[0].ts_last.second == 20 and len(alerts[0].event_ids) == 3


def test_threshold_not_reached_when_outside_window_or_repeats():
    spread = conns([0, 60, 130], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
    assert evaluate(threshold_rule(), spread) == []
    repeat = conns([0, 10, 20], ["10.0.0.1", "10.0.0.1", "10.0.0.1"])
    assert evaluate(threshold_rule(), repeat) == []


def test_threshold_window_boundary_is_inclusive():
    events = conns([0, 50, 100], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
    assert len(evaluate(threshold_rule(), events)) == 1


def test_threshold_count_variant():
    rule = threshold_rule(count_gte=3, distinct_field=None, distinct_gte=None)
    events = conns([0, 10, 20], ["10.0.0.1", "10.0.0.1", "10.0.0.1"])
    assert len(evaluate(rule, events)) == 1


def test_threshold_suppresses_group_until_window_after_ts_last():
    ips = [f"10.0.0.{i}" for i in range(1, 9)]
    # first alert at t=20 (ts_last), quiet until t=120; events at 30..110 are ignored
    events = conns([0, 10, 20, 30, 40, 50, 130, 135], ips)
    alerts = evaluate(threshold_rule(), events)
    assert len(alerts) == 1
    late = conns([0, 10, 20, 120, 125, 130], ips[:6])
    assert len(evaluate(threshold_rule(), late)) == 2


def test_threshold_groups_are_independent():
    events = conns([0, 10], ["10.0.0.1", "10.0.0.2"], host="WS-03") + conns([20], ["10.0.0.3"], host="WS-04")
    assert evaluate(threshold_rule(), events) == []


def test_threshold_exclusion():
    rule = threshold_rule(exclusions=[[{"field": "user", "op": "eq", "value": "svc_backup"}]])
    events = conns([0, 10, 20], ["10.0.0.1", "10.0.0.2", "10.0.0.3"], user="svc_backup")
    assert evaluate(rule, events) == []


def sequence_rule(within=60, group_by=("host",)):
    return parse_rule({
        "id": "HC-902", "name": "Seq", "severity": 4, "type": "sequence", "group_by": list(group_by),
        "steps": [
            {"id": "a", "where": [{"field": "process.name", "op": "eq", "value": "a.exe"}]},
            {"id": "b", "within_seconds": within, "where": [{"field": "event_type", "op": "eq", "value": "network_conn"}]},
            {"id": "c", "within_seconds": within, "where": [{"field": "process.name", "op": "eq", "value": "c.exe"}]},
        ],
    })


def test_sequence_fires_in_order_and_holds_all_step_events():
    events = [proc(0, "a.exe"), net(10, "203.0.113.50"), proc(20, "c.exe")]
    alerts = evaluate(sequence_rule(), events)
    assert len(alerts) == 1
    assert alerts[0].event_ids == [e["event_id"] for e in events]
    assert alerts[0].ts_first.second == 0 and alerts[0].ts_last.second == 20


def test_sequence_wrong_order_or_too_slow_or_other_host_does_not_fire():
    assert evaluate(sequence_rule(), [proc(0, "c.exe"), net(10, "203.0.113.50"), proc(20, "a.exe")]) == []
    assert evaluate(sequence_rule(within=5), [proc(0, "a.exe"), net(10, "203.0.113.50"), proc(12, "c.exe")]) == []
    other = [proc(0, "a.exe"), net(10, "203.0.113.50", host="WS-04"), proc(20, "c.exe")]
    assert evaluate(sequence_rule(), other) == []


def test_sequence_step_must_come_strictly_after_previous_step():
    events = [proc(0, "a.exe"), net(0, "203.0.113.50"), proc(5, "c.exe")]
    assert evaluate(sequence_rule(), events) == []


def test_sequence_closes_chain_after_alert_and_starts_fresh_chains():
    events = [proc(0, "a.exe"), net(10, "203.0.113.50"), proc(20, "c.exe"), proc(25, "c.exe")]
    assert len(evaluate(sequence_rule(), events)) == 1
    two = [proc(0, "a.exe"), proc(5, "a.exe"), net(10, "203.0.113.50"), proc(20, "c.exe")]
    alerts = evaluate(sequence_rule(), two)
    assert len(alerts) == 2 and alerts[0].ts_first.second == 0 and alerts[1].ts_first.second == 5


def test_sequence_chain_expires_and_open_chain_cap():
    expired = [proc(0, "a.exe"), net(200, "203.0.113.50"), proc(210, "c.exe")]
    assert evaluate(sequence_rule(), expired) == []
    many = [proc(i, "a.exe") for i in range(60)] + [net(61, "203.0.113.50"), proc(62, "c.exe")]
    alerts = evaluate(sequence_rule(within=100), many)
    assert len(alerts) == 50  # only the 50 newest chains stay open
    assert min(a.ts_first.second for a in alerts) == 10


def test_sequence_rule_exclusions_apply_to_all_steps():
    rule = parse_rule({
        "id": "HC-903", "name": "Seq", "severity": 4, "type": "sequence", "group_by": ["host"],
        "steps": [
            {"id": "a", "where": [{"field": "process.name", "op": "eq", "value": "a.exe"}]},
            {"id": "b", "within_seconds": 60, "where": [{"field": "event_type", "op": "eq", "value": "network_conn"}]},
        ],
        "exclusions": [[{"field": "user", "op": "eq", "value": "adm_it"}]],
    })
    assert evaluate(rule, [proc(0, "a.exe", user="adm_it"), net(5, "1.2.3.4", user="carol")]) == []
    assert len(evaluate(rule, [proc(0, "a.exe"), net(5, "1.2.3.4")])) == 1


def periodic_rule(**extra):
    data = {"id": "HC-904", "name": "Beacon", "severity": 4, "type": "periodicity",
            "group_by": ["host", "net.dst_ip"],
            "where": [{"field": "event_type", "op": "eq", "value": "network_conn"}],
            "min_events": 5, "max_cv": 0.25, "window_seconds": 1000}
    data.update(extra)
    return parse_rule(data)


def test_periodicity_regular_gaps_fire_irregular_do_not():
    regular = [net(i * 60 + (i % 3), "203.0.113.50") for i in range(8)]
    alerts = evaluate(periodic_rule(), regular)
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 5 and alerts[0].ts_last.minute == 4  # fires as soon as min_events is reached
    gaps = [0, 5, 6, 200, 210, 215, 500, 505]
    irregular = [net(t, "203.0.113.50") for t in gaps]
    assert evaluate(periodic_rule(), irregular) == []


def test_periodicity_min_events_and_other_destination_and_exclusion():
    few = [net(i * 60, "203.0.113.50") for i in range(4)]
    assert evaluate(periodic_rule(), few) == []
    mixed = [net(i * 60, "203.0.113.50" if i % 2 else "203.0.113.51") for i in range(8)]
    assert evaluate(periodic_rule(), mixed) == []
    excl = periodic_rule(exclusions=[[{"field": "net.dst_ip", "op": "eq", "value": "198.51.100.77"}]])
    assert evaluate(excl, [net(i * 300, "198.51.100.77") for i in range(10)]) == []


def test_periodicity_suppresses_until_window_after_ts_last():
    events = [net(i * 60, "203.0.113.50") for i in range(40)]
    alerts = evaluate(periodic_rule(), events)
    assert len(alerts) == 2  # t=240 alert, quiet until t=1240; next window starts at t=1260
    assert alerts[1].ts_first.minute * 60 + alerts[1].ts_first.second >= 1240


def test_periodicity_cv_uses_population_std_and_threshold_is_inclusive():
    # gaps 10,30 -> mean 20, pstdev 10 -> cv 0.5
    events = [net(0, "1.1.1.1"), net(10, "1.1.1.1"), net(40, "1.1.1.1")]
    assert len(evaluate(periodic_rule(min_events=3, max_cv=0.5), events)) == 1
    assert evaluate(periodic_rule(min_events=3, max_cv=0.49), events) == []
