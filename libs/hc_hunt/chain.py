"""Attack chain graph from evidence events (spec Section 10.1). Owner: M2.

Node ids: host:NAME, proc:HOST:PID, ip:ADDR, user:NAME, domain:NAME.
Edges: connected, authenticated, queried, spawned (dropped is never created because file events carry
no creating process). The result is deterministic: nodes sorted by id, edges by (ts, src, dst, kind, event_id).
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from hc_common.constants import IP_HOST
from hc_common.schemas import AttackChain, Edge, Node

from hc_detect.timeutil import parse_ts

DEFAULT_HOST_RISK = 0.2
EVIDENCE_RISK = 0.5
MAX_NODES = 80
GREY, ORANGE, RED = "#bdbdbd", "#f5a623", "#d0021b"
_REMOVAL_ORDER = ["process", "domain", "ip", "user", "host"]
_SHAPES = {"host": "box", "process": "ellipse", "ip": "diamond", "user": "house", "domain": "hexagon"}
_EDGE_STYLES = {
    "connected": 'color="#4a4a4a"',
    "authenticated": 'color="#1f77b4", style=dashed',
    "queried": 'color="#7f7f7f", style=dotted',
    "spawned": 'color="#2ca02c", style=bold',
    "dropped": 'color="#9467bd"',
}


class _Builder:
    def __init__(self, risk_by_host: Dict[str, float]) -> None:
        self.risk = risk_by_host
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple, Edge] = {}

    def host(self, name: str) -> str:
        node_id = f"host:{name}"
        if node_id not in self.nodes:
            risk = min(1.0, max(0.0, float(self.risk.get(name, DEFAULT_HOST_RISK))))
            self.nodes[node_id] = Node(id=node_id, type="host", label=name, risk=risk)
        return node_id

    def evidence_node(self, node_id: str, kind: str, label: str) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(id=node_id, type=kind, label=label, risk=EVIDENCE_RISK)  # type: ignore[arg-type]
        return node_id

    def endpoint(self, ip: str, host: str = "") -> str:
        """A host node when the address belongs to an asset, otherwise an ip node."""
        name = host or IP_HOST.get(ip, "")
        if name:
            return self.host(name)
        return self.evidence_node(f"ip:{ip}", "ip", ip)

    def edge(self, key: Tuple, src: str, dst: str, kind: str, ts, event_id: str) -> None:
        if src != dst and key not in self.edges:
            self.edges[key] = Edge(src=src, dst=dst, kind=kind, ts=ts, event_id=event_id)  # type: ignore[arg-type]


def _network(builder: _Builder, event: dict, host_id: str, ts, event_id: str) -> None:
    net = event.get("net") or {}
    dst_ip = str(net.get("dst_ip") or "")
    if not dst_ip:
        return
    port = net.get("dst_port", 0)
    if net.get("direction") == "inbound":
        src = builder.endpoint(str(net.get("src_ip") or dst_ip))
        builder.edge((src, host_id, "connected", port), src, host_id, "connected", ts, event_id)
        return
    dst = builder.endpoint(dst_ip, str(net.get("dst_host") or ""))
    builder.edge((host_id, dst, "connected", port), host_id, dst, "connected", ts, event_id)


def _auth(builder: _Builder, event: dict, host_id: str, ts, event_id: str) -> None:
    auth = event.get("auth") or {}
    src_host = str(auth.get("src_host") or "")
    if auth.get("result") == "success" and auth.get("logon_type") == 3 and src_host:
        src = builder.host(src_host)
        builder.edge((src, host_id, "authenticated"), src, host_id, "authenticated", ts, event_id)


def _dns(builder: _Builder, event: dict, host_id: str, ts, event_id: str) -> None:
    query = str((event.get("dns") or {}).get("query") or "")
    if query:
        domain = builder.evidence_node(f"domain:{query}", "domain", query)
        builder.edge((host_id, domain, "queried"), host_id, domain, "queried", ts, event_id)


def _process(builder: _Builder, event: dict, ts, event_id: str) -> None:
    proc = event.get("process") or {}
    parent_pid = int(proc.get("parent_pid") or 0)
    if parent_pid <= 0 or not proc.get("name"):
        return
    host = str(event.get("host", ""))
    child = builder.evidence_node(f"proc:{host}:{proc.get('pid', 0)}", "process", f"{proc['name']} ({proc.get('pid', 0)})")
    parent_name = str(proc.get("parent_name") or f"pid {parent_pid}")
    parent = builder.evidence_node(f"proc:{host}:{parent_pid}", "process", f"{parent_name} ({parent_pid})")
    builder.edge((parent, child, "spawned"), parent, child, "spawned", ts, event_id)


def _cap_nodes(nodes: Dict[str, Node], edges: List[Edge]) -> Tuple[Dict[str, Node], List[Edge]]:
    """Drop the least valuable nodes (processes first, lowest risk first) until MAX_NODES remain."""
    nodes = dict(nodes)
    while len(nodes) > MAX_NODES:
        degree: Dict[str, int] = {}
        for edge in edges:
            degree[edge.src] = degree.get(edge.src, 0) + 1
            degree[edge.dst] = degree.get(edge.dst, 0) + 1
        for kind in _REMOVAL_ORDER:
            pool = [n for n in nodes.values() if n.type == kind]
            if pool:
                victim = min(pool, key=lambda n: (n.risk, degree.get(n.id, 0), n.id))
                break
        del nodes[victim.id]
        edges = [e for e in edges if victim.id not in (e.src, e.dst)]
    return nodes, edges


def build_chain(events: List[dict], risk_by_host: Optional[Dict[str, float]] = None) -> AttackChain:
    """Build the attack chain graph from evidence events and a host risk map (0..1)."""
    builder = _Builder(risk_by_host or {})
    ordered = []
    for event in events:
        try:
            ordered.append((parse_ts(event["ts"]), str(event.get("event_id", "")), event))
        except (KeyError, ValueError, TypeError):
            continue
    ordered.sort(key=lambda item: (item[0], item[1]))
    for ts, event_id, event in ordered:
        host = str(event.get("host") or "")
        if not host:
            continue
        host_id = builder.host(host)
        kind = event.get("event_type")
        if kind == "network_conn":
            _network(builder, event, host_id, ts, event_id)
        elif kind == "auth":
            _auth(builder, event, host_id, ts, event_id)
        elif kind == "dns_query":
            _dns(builder, event, host_id, ts, event_id)
        elif kind == "process_create":
            _process(builder, event, ts, event_id)
    nodes, edges = _cap_nodes(builder.nodes, list(builder.edges.values()))
    edges.sort(key=lambda e: (e.ts, e.src, e.dst, e.kind, e.event_id))
    return AttackChain(nodes=sorted(nodes.values(), key=lambda n: n.id), edges=edges)


# ------------------------------------------------------------------ Graphviz DOT
def risk_color(risk: float) -> str:
    """Fill colour: below 0.4 grey, 0.4 to 0.7 orange, above 0.7 red."""
    if risk < 0.4:
        return GREY
    if risk <= 0.7:
        return ORANGE
    return RED


def _quote(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")
    return f'"{escaped}"'


def chain_to_dot(chain: AttackChain) -> str:
    """Valid Graphviz DOT for the chain, with node fill colours by risk. Deterministic."""
    lines = [
        "digraph attack_chain {",
        "  rankdir=LR;",
        '  node [style=filled, fontname="Helvetica", fontsize=10];',
        '  edge [fontname="Helvetica", fontsize=9];',
    ]
    for node in sorted(chain.nodes, key=lambda n: n.id):
        fill = risk_color(node.risk)
        font = "white" if fill == RED else "black"
        lines.append(f"  {_quote(node.id)} [label={_quote(node.label)}, shape={_SHAPES[node.type]}, "
                     f'fillcolor="{fill}", fontcolor="{font}"];')
    edges: Iterable[Edge] = sorted(chain.edges, key=lambda e: (e.ts, e.src, e.dst, e.kind, e.event_id))
    for edge in edges:
        lines.append(f"  {_quote(edge.src)} -> {_quote(edge.dst)} [label={_quote(edge.kind)}, {_EDGE_STYLES[edge.kind]}];")
    lines.append("}")
    return "\n".join(lines) + "\n"
