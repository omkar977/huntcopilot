"""build_chain and chain_to_dot. Owner: M2."""
import json
import shutil
import subprocess

import pytest

from hc_common.schemas import AttackChain, Edge, Node
from hc_hunt.chain import MAX_NODES, build_chain, chain_to_dot, risk_color

from hc_detect.tests.helpers import auth, dns, load_sample, net, proc


def ids(chain):
    return {n.id for n in chain.nodes}


def edges(chain, kind):
    return [(e.src, e.dst) for e in chain.edges if e.kind == kind]


def test_internal_connection_is_host_to_host_and_deduplicated_on_port():
    events = [net(0, "10.10.2.21", port=445, direction="internal", event_id="first"),
              net(5, "10.10.2.21", port=445, direction="internal", event_id="second"),
              net(9, "10.10.2.21", port=135, direction="internal", event_id="other-port")]
    chain = build_chain(events, {})
    assert edges(chain, "connected") == [("host:WS-03", "host:FILE-01")] * 2
    assert [e.event_id for e in chain.edges] == ["first", "other-port"]
    assert "host:FILE-01" in ids(chain)


def test_external_connection_goes_to_ip_node_with_evidence_risk():
    chain = build_chain([net(0, "203.0.113.50")], {"WS-03": 0.9})
    assert edges(chain, "connected") == [("host:WS-03", "ip:203.0.113.50")]
    risks = {n.id: n.risk for n in chain.nodes}
    assert risks["host:WS-03"] == 0.9 and risks["ip:203.0.113.50"] == 0.5


def test_host_risk_default_and_clamping():
    chain = build_chain([net(0, "10.10.2.21", direction="internal")], {"WS-03": 4.0})
    risks = {n.id: n.risk for n in chain.nodes}
    assert risks["host:WS-03"] == 1.0 and risks["host:FILE-01"] == 0.2


def test_authenticated_edge_only_for_successful_network_logon_with_source_host():
    events = [auth(0, host="DB-01", src_host="WS-03"),
              auth(1, host="FILE-01", result="failure", src_host="WS-03"),
              auth(2, host="WS-05", logon=2, src_host="WS-03"),
              auth(3, host="WS-06", src_host="")]
    assert edges(build_chain(events, {}), "authenticated") == [("host:WS-03", "host:DB-01")]


def test_queried_edge_and_domain_node():
    chain = build_chain([dns(0, "cdn-sync.badhost.test"), dns(5, "cdn-sync.badhost.test")], {})
    assert edges(chain, "queried") == [("host:WS-03", "domain:cdn-sync.badhost.test")]


def test_spawned_edge_uses_process_nodes_and_skips_unknown_parent():
    child = proc(0, "powershell.exe", parent="winword.exe")
    child["process"].update(pid=4312, parent_pid=3120)
    orphan = proc(1, "cmd.exe")
    orphan["process"]["parent_pid"] = 0
    chain = build_chain([child, orphan], {})
    assert edges(chain, "spawned") == [("proc:WS-03:3120", "proc:WS-03:4312")]
    labels = {n.id: n.label for n in chain.nodes}
    assert labels["proc:WS-03:4312"] == "powershell.exe (4312)" and labels["proc:WS-03:3120"] == "winword.exe (3120)"
    assert not any(e.kind == "dropped" for e in chain.edges)


def test_inbound_connection_points_at_this_host():
    event = net(0, "10.10.1.13", direction="inbound", host="DB-01")
    event["net"]["src_ip"] = "10.10.1.15"
    assert edges(build_chain([event], {}), "connected") == [("host:WS-05", "host:DB-01")]


def test_events_without_time_or_host_are_ignored():
    broken = net(0, "10.10.2.21", direction="internal")
    del broken["ts"]
    nohost = net(1, "10.10.2.21", direction="internal")
    nohost["host"] = ""
    assert build_chain([broken, nohost], {}).nodes == []


def test_cap_at_80_nodes_removes_process_nodes_first_and_keeps_hosts():
    events = [net(0, "10.10.2.21", direction="internal")]
    for i in range(60):
        child = proc(i + 1, f"p{i}.exe", parent="cmd.exe")
        child["process"].update(pid=1000 + i, parent_pid=900 + i)
        events.append(child)
    chain = build_chain(events, {"WS-03": 0.9})
    assert len(chain.nodes) == MAX_NODES
    assert {"host:WS-03", "host:FILE-01"} <= ids(chain)
    remaining = {n.id for n in chain.nodes}
    assert all(e.src in remaining and e.dst in remaining for e in chain.edges)
    many_ips = build_chain([net(i, f"203.0.113.{i % 250}", host=f"WS-0{1 + i % 8}") for i in range(200)], {})
    assert len(many_ips.nodes) <= MAX_NODES


def test_output_is_deterministic_and_order_independent():
    events = [e for e in load_sample() if e["gt"]["is_malicious"]]
    first = build_chain(events, {"WS-03": 0.9})
    assert build_chain(list(reversed(events)), {"WS-03": 0.9}) == first
    assert chain_to_dot(first) == chain_to_dot(build_chain(events, {"WS-03": 0.9}))


def test_fixture_attack_has_host_to_host_edges_for_the_demo():
    events = [e for e in load_sample() if e["gt"]["is_malicious"]]
    chain = build_chain(events, {})
    lateral = {dst for src, dst in edges(chain, "connected") if src == "host:WS-03" and dst.startswith("host:")}
    assert {"host:FILE-01", "host:DB-01", "host:WS-05", "host:WS-06"} <= lateral
    assert len(edges(chain, "authenticated")) == 4


def test_risk_colour_bands():
    assert risk_color(0.0) == risk_color(0.39) == "#bdbdbd"
    assert risk_color(0.4) == risk_color(0.7) == "#f5a623"
    assert risk_color(0.71) == risk_color(1.0) == "#d0021b"


def test_dot_structure_colours_and_escaping():
    chain = AttackChain(
        nodes=[Node(id="host:A", type="host", label='A "quoted" \\ name', risk=0.9),
               Node(id="ip:1.2.3.4", type="ip", label="1.2.3.4", risk=0.5),
               Node(id="domain:x.test", type="domain", label="x.test", risk=0.1)],
        edges=[Edge(src="host:A", dst="ip:1.2.3.4", kind="connected", ts="2026-11-12T09:00:00Z", event_id="e1")])
    dot = chain_to_dot(chain)
    assert dot.startswith("digraph attack_chain {") and dot.rstrip().endswith("}")
    assert 'fillcolor="#d0021b"' in dot and 'fillcolor="#f5a623"' in dot and 'fillcolor="#bdbdbd"' in dot
    assert r'label="A \"quoted\" \\ name"' in dot
    assert '"host:A" -> "ip:1.2.3.4" [label="connected"' in dot


@pytest.mark.skipif(shutil.which("dot") is None, reason="graphviz not installed")
def test_dot_is_accepted_by_graphviz(tmp_path):
    events = [e for e in load_sample() if e["gt"]["is_malicious"]]
    path = tmp_path / "chain.dot"
    path.write_text(chain_to_dot(build_chain(events, {"WS-03": 0.9, "DB-01": 0.8})), encoding="utf-8")
    done = subprocess.run(["dot", "-Tjson", str(path)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["name"] == "attack_chain"
