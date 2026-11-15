"""Demo plan on fixture-style data: the benign WS-08 admin noise must rank below WS-03. Owner: M2."""
from hc_hunt.chain import build_chain
from hc_hunt.executor import run_plan, step_context

from hc_detect.tests.helpers import load_sample

from .plans import demo_plan


def _select(events, step_index, ctx):
    def enc_ps(e):
        p = e.get("process") or {}
        return p.get("name") == "powershell.exe" and "-enc" in p.get("cmdline", "").lower()

    def lateral_conn(e):
        n = e.get("net") or {}
        return (e["event_type"] == "network_conn" and n.get("direction") == "internal"
                and n.get("dst_port") in (445, 135, 5985) and e["host"] in ctx.get("s1", []))

    def auth_ok(e):
        a = e.get("auth") or {}
        return e["event_type"] == "auth" and a.get("logon_type") == 3 and a.get("result") == "success" \
            and e["host"] in ctx.get("s2", [])

    def tools(e):
        return (e.get("process") or {}).get("name") in ("psexec.exe", "wmic.exe", "winrs.exe", "psexesvc.exe")
    return [e for e in events if [enc_ps, lateral_conn, auth_ok, tools][step_index](e)]


class StepwiseClient:
    """Answers each step like OpenSearch would, using the fixture events (host sets come from run_plan order)."""

    def __init__(self, events):
        self.events, self.calls, self.ctx, self.bodies = events, 0, {}, []

    def search(self, index, body):
        step = self.calls
        self.bodies.append(body)
        self.calls += 1
        rows = _select(self.events, step, self.ctx)
        if step == 0:
            self.ctx["s1"] = step_context(rows)["hosts"]
        if step == 1:
            self.ctx["s2"] = step_context(rows)["dst_hosts"] or sorted(
                {{"10.10.2.21": "FILE-01", "10.10.2.31": "DB-01", "10.10.1.15": "WS-05", "10.10.1.16": "WS-06",
                  }.get(r["net"]["dst_ip"], "") for r in rows} - {""})
        return {"hits": {"hits": [{"_source": dict(r)} for r in rows]}}


def test_ws03_outranks_ws08_in_chain_edges_and_evidence():
    events = load_sample()
    client = StepwiseClient(events)
    results, evidence = run_plan(demo_plan(), client, "demo")
    # option A: s2 starts at the earliest s1 event (the benign WS-08 script at 09:12), not at midnight
    assert client.bodies[1]["query"]["bool"]["filter"][-1]["range"]["ts"]["gte"] == "2026-11-12T09:12:00Z"
    assert results[0].hosts == ["WS-03", "WS-08"]            # s1 also matches the benign admin script
    everything = [e for rows in evidence.values() for e in rows]
    chain = build_chain(everything, {"WS-03": 0.9, "WS-08": 0.2})
    out_edges = {}
    for edge in chain.edges:
        if edge.src.startswith("host:"):
            out_edges[edge.src] = out_edges.get(edge.src, 0) + 1
    assert out_edges["host:WS-03"] > out_edges["host:WS-08"]
    lateral = {e.dst for e in chain.edges if e.src == "host:WS-03" and e.kind == "connected"}
    assert {"host:FILE-01", "host:DB-01", "host:WS-05", "host:WS-06"} <= lateral
    risks = {n.id: n.risk for n in chain.nodes}
    assert risks["host:WS-03"] > risks["host:WS-08"]
