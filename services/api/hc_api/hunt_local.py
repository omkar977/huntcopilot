"""Local stand-ins for the hc_hunt library (owner M2): validator V1..V10, build_chain, chain_to_dot.

Used only when hc_hunt cannot be imported (for example in M4 standalone tests). When M2's library is
present, hc_api.hunt_lib prefers it. The behaviour follows spec Sections 5.7 and 10.1.
"""
from __future__ import annotations

import re
from datetime import timedelta

from hc_common.constants import ALLOWED_FIELDS
from hc_common.schemas import AttackChain, Edge, HuntPlan, Node, ValidationResult

NUMERIC_FIELDS = {"net.dst_port", "auth.logon_type"}
OPS_NUMERIC = {"eq", "neq", "in", "gt", "gte", "lt", "lte"}
OPS_TS = {"gt", "gte", "lt", "lte"}
OPS_TEXT = {"eq", "neq", "in", "contains", "startswith"}
VAR_RE = re.compile(r"^\$\{s([1-6])\.(hosts|users|dst_ips|dst_hosts)\}$")
STEP_RE = re.compile(r"^s[1-6]$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_NODES = 80
EXTERNAL_RISK = 0.5
DEFAULT_HOST_RISK = 0.2


def _values(value) -> list:
    return list(value) if isinstance(value, list) else [value]


def _check_value(step_id: str, cond, depends: list[str], errors: list[str]) -> None:
    """V8 and V9 for one condition."""
    for v in _values(cond.value):
        if not isinstance(v, str):
            continue
        if "${" in v:
            m = VAR_RE.match(v)
            if not m:
                errors.append(f"{step_id}: invalid variable {v[:40]!r}")
            elif f"s{m.group(1)}" not in depends:
                errors.append(f"{step_id}: variable {v} refers to a step not listed in depends_on")
            continue
        if len(v) > 200:
            errors.append(f"{step_id}: string value longer than 200 characters")
        if v[:1] in ("*", "?"):
            errors.append(f"{step_id}: value must not start with a wildcard character")
        if CONTROL_RE.search(v):
            errors.append(f"{step_id}: value contains control characters")


def _check_step(idx: int, step, ids: list[str], errors: list[str]) -> None:
    sid = step.step_id
    if not STEP_RE.match(sid):
        errors.append(f"{sid}: step_id must look like s1..s6")
    for dep in step.depends_on:  # V3
        if dep not in ids[:idx]:
            errors.append(f"{sid}: depends_on {dep} must reference an earlier step")
    if not 1 <= step.query.size <= 500:  # V4
        errors.append(f"{sid}: size must be between 1 and 500")
    if len(step.query.filters) > 8:  # V6
        errors.append(f"{sid}: at most 8 filters per step")
    if step.query.group_by is not None and step.query.group_by not in ALLOWED_FIELDS:  # V10
        errors.append(f"{sid}: group_by field {step.query.group_by!r} is not allowed")
    for cond in step.query.filters:
        if cond.field not in ALLOWED_FIELDS:
            errors.append(f"{sid}: field {cond.field!r} is not allowed")
            continue
        allowed = OPS_TS if cond.field == "ts" else OPS_NUMERIC if cond.field in NUMERIC_FIELDS else OPS_TEXT
        if cond.op not in allowed:  # V7
            errors.append(f"{sid}: operator {cond.op} is not allowed for {cond.field}")
        if cond.op == "in" and not isinstance(cond.value, list) and not (
                isinstance(cond.value, str) and VAR_RE.match(cond.value)):
            errors.append(f"{sid}: operator in needs a list or a variable")
        _check_value(sid, cond, step.depends_on, errors)


def validate_plan(plan: HuntPlan) -> ValidationResult:
    """Validate a plan against V1..V10 (plus the ${sN.dst_hosts} addendum)."""
    errors: list[str] = []
    n = len(plan.steps)
    if not 1 <= n <= 6:  # V1
        errors.append("a plan needs 1 to 6 steps")
    ids = [s.step_id for s in plan.steps]
    if len(set(ids)) != len(ids):  # V2
        errors.append("step_id values must be unique")
    for idx, step in enumerate(plan.steps):
        _check_step(idx, step, ids, errors)
    tr = plan.time_range  # V5
    if tr.end <= tr.start:
        errors.append("time range end must be after start")
    elif tr.end - tr.start > timedelta(days=7):
        errors.append("time range must not exceed 7 days")
    return ValidationResult(ok=not errors, errors=errors, warnings=[])


# ---------------------------------------------------------------- chain
def _add_node(nodes: dict[str, Node], nid: str, ntype: str, label: str, risk: float) -> None:
    if nid not in nodes:
        nodes[nid] = Node(id=nid, type=ntype, label=label, risk=risk)


def _host_node(nodes: dict[str, Node], host: str, risk_by_host: dict[str, float]) -> str:
    nid = f"host:{host}"
    _add_node(nodes, nid, "host", host, float(risk_by_host.get(host, DEFAULT_HOST_RISK)))
    return nid


def _net_edge(ev: dict, nodes: dict, risk: dict) -> tuple[str, str, str, str] | None:
    net = ev["net"]
    src = _host_node(nodes, ev["host"], risk)
    if net.get("direction") == "internal" or net.get("dst_host"):
        if net.get("dst_host"):
            return src, _host_node(nodes, net["dst_host"], risk), "connected", str(net.get("dst_port"))
        _add_node(nodes, f"ip:{net['dst_ip']}", "ip", net["dst_ip"], EXTERNAL_RISK)
        return src, f"ip:{net['dst_ip']}", "connected", str(net.get("dst_port"))
    _add_node(nodes, f"ip:{net['dst_ip']}", "ip", net["dst_ip"], EXTERNAL_RISK)
    return src, f"ip:{net['dst_ip']}", "connected", str(net.get("dst_port"))


def _event_edge(ev: dict, nodes: dict, risk: dict) -> tuple[str, str, str, str] | None:
    et = ev.get("event_type")
    if et == "network_conn" and ev.get("net"):
        return _net_edge(ev, nodes, risk)
    if et == "auth" and ev.get("auth"):
        a = ev["auth"]
        if a.get("result") == "success" and a.get("logon_type") == 3 and a.get("src_host"):
            _add_node(nodes, f"user:{a.get('target_user', '')}", "user", a.get("target_user", ""), EXTERNAL_RISK)
            return (_host_node(nodes, a["src_host"], risk), _host_node(nodes, ev["host"], risk),
                    "authenticated", a.get("target_user", ""))
    if et == "dns_query" and ev.get("dns"):
        q = ev["dns"]["query"]
        _add_node(nodes, f"domain:{q}", "domain", q, EXTERNAL_RISK)
        return _host_node(nodes, ev["host"], risk), f"domain:{q}", "queried", q
    if et == "process_create" and ev.get("process"):
        p = ev["process"]
        child = f"proc:{ev['host']}:{p['pid']}"
        parent = f"proc:{ev['host']}:{p.get('parent_pid', 0)}"
        _add_node(nodes, child, "process", p["name"], EXTERNAL_RISK)
        _add_node(nodes, parent, "process", p.get("parent_name") or "unknown", EXTERNAL_RISK)
        return parent, child, "spawned", ""
    return None


def build_chain(events: list[dict], risk_by_host: dict[str, float]) -> AttackChain:
    """Attack chain from evidence events (spec 10.1). Deterministic, at most 80 nodes."""
    nodes: dict[str, Node] = {}
    edges: dict[tuple, Edge] = {}
    for ev in sorted(events, key=lambda e: (str(e.get("ts")), str(e.get("event_id")))):
        _host_node(nodes, ev["host"], risk_by_host)
        found = _event_edge(ev, nodes, risk_by_host)
        if not found:
            continue
        src, dst, kind, extra = found
        key = (src, dst, kind, extra)
        if key not in edges:
            edges[key] = Edge(src=src, dst=dst, kind=kind, ts=ev["ts"], event_id=ev["event_id"])
    return _cap(nodes, list(edges.values()))


def _cap(nodes: dict[str, Node], edges: list[Edge]) -> AttackChain:
    if len(nodes) > MAX_NODES:
        order = sorted(nodes.values(), key=lambda n: (n.type == "host", n.type != "process", n.risk, n.id))
        for node in order:
            if len(nodes) <= MAX_NODES:
                break
            del nodes[node.id]
    kept = [e for e in edges if e.src in nodes and e.dst in nodes]
    kept.sort(key=lambda e: (e.ts, e.src, e.dst, e.kind))
    return AttackChain(nodes=sorted(nodes.values(), key=lambda n: n.id), edges=kept)


def _colour(risk: float) -> str:
    return "#e53935" if risk > 0.7 else "#fb8c00" if risk >= 0.4 else "#9e9e9e"


def _q(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def chain_to_dot(chain: AttackChain) -> str:
    """Graphviz DOT with node fill colours by risk."""
    shape = {"host": "box", "process": "ellipse", "ip": "diamond", "user": "house", "domain": "hexagon"}
    out = ["digraph attack_chain {", "  rankdir=LR;", '  node [style=filled, fontname="Helvetica"];']
    for n in chain.nodes:
        out.append(f"  {_q(n.id)} [label={_q(n.label)}, shape={shape[n.type]}, fillcolor={_q(_colour(n.risk))}];")
    for e in chain.edges:
        out.append(f"  {_q(e.src)} -> {_q(e.dst)} [label={_q(e.kind)}];")
    out.append("}")
    return "\n".join(out)
