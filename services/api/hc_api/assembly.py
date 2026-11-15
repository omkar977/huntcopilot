"""Finding assembly (spec Section 10.4): components, stages, recommendations, confidence call."""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Callable, Optional

from hc_common.clients import parse_ts
from hc_common.constants import HOST_USER, RULE_STAGE, STAGES
from hc_common.ids import sha1_hex
from hc_common.schemas import (Alert, AttackChain, Finding, HuntPlan, ProposedAction, ScoredWindow, StepResult)

INTERNAL_NET = ipaddress.ip_network("10.10.0.0/16")
DISRUPTIVE_STAGES = {"execution", "c2", "lateral_movement"}
MAX_EVENT_IDS = 1000
MAX_ALERT_EVENTS = 200


def candidate_hosts(step_results: list[StepResult], evidence: dict[str, list[dict]]) -> list[str]:
    """Union of hosts and dst_hosts from all steps."""
    hosts = {h for r in step_results for h in r.hosts}
    for events in evidence.values():
        hosts.update((e.get("net") or {}).get("dst_host", "") for e in events)
    return sorted(h for h in hosts if h)


def components(hosts: list[str], chain: AttackChain) -> list[list[str]]:
    """Connected components of the candidate hosts over host-to-host chain edges (undirected)."""
    parent = {h: h for h in hosts}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for e in chain.edges:
        if e.src.startswith("host:") and e.dst.startswith("host:"):
            a, b = e.src[5:], e.dst[5:]
            if a in parent and b in parent:
                parent[find(a)] = find(b)
    groups: dict[str, list[str]] = {}
    for h in hosts:
        groups.setdefault(find(h), []).append(h)
    return sorted((sorted(g) for g in groups.values()), key=lambda g: g[0])


def split_weak_hosts(groups: list[list[str]], chain: AttackChain, alerts: list[Alert]) -> list[list[str]]:
    """Split off hosts that have no alerts at all from a group that has alerts (for example an admin
    workstation running a benign script that touches the attack hosts). Lead fix v2: the earlier
    "at most one peer" condition failed on real data (WS-08 has two peers)."""
    alerted = {a.host for a in alerts}
    out: list[list[str]] = []
    for grp in groups:
        if len(grp) < 2 or not alerted & set(grp):
            out.append(grp)
            continue
        weak = [h for h in grp if h not in alerted]
        out.append([h for h in grp if h in alerted])
        out.extend([h] for h in weak)
    return sorted(out, key=lambda g: g[0])


def _flatten(evidence: dict[str, list[dict]]) -> list[dict]:
    seen: dict[str, dict] = {}
    for step_id in sorted(evidence):
        for e in evidence[step_id]:
            seen.setdefault(e["event_id"], e)
    return sorted(seen.values(), key=lambda e: (e["ts"], e["event_id"]))


def representative_window(windows: list[ScoredWindow]) -> Optional[ScoredWindow]:
    """Highest anomaly; ties broken by earliest start then host name (deterministic)."""
    if not windows:
        return None
    return sorted(windows, key=lambda w: (-w.anomaly, w.ts_first, w.host))[0]


def stages_found(plan: HuntPlan, evidence: dict[str, list[dict]], comp: set[str], alerts: list[Alert]) -> list[str]:
    """Stages of plan steps with evidence on the component's hosts, plus stages of its alerts' rules."""
    found: set[str] = set()
    for step in plan.steps:
        if step.stage in STAGES and any(
                e["host"] in comp or (e.get("net") or {}).get("dst_host") in comp for e in evidence.get(step.step_id, [])):
            found.add(step.stage)
    found.update(RULE_STAGE[a.rule_id] for a in alerts if a.rule_id in RULE_STAGE)
    return [s for s in STAGES if s in found]


def _is_external(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) not in INTERNAL_NET
    except ValueError:
        return False


def recommend(comp_hosts: list[str], comp_events: list[dict], alerts: list[Alert],
              get_events: Callable[[list[str]], list[dict]]) -> list[ProposedAction]:
    """isolate_host, block_ip and disable_account recommendations with a rationale each."""
    actions: list[ProposedAction] = []
    for host in comp_hosts:
        hits = [a for a in alerts if a.host == host and RULE_STAGE.get(a.rule_id) in DISRUPTIVE_STAGES
                and a.severity >= 4]
        if hits:
            rules = ", ".join(sorted({a.rule_id for a in hits}))
            stages = ", ".join(sorted({RULE_STAGE[a.rule_id] for a in hits}))
            actions.append(ProposedAction(
                action="isolate_host", target=host,
                rationale=f"Rules {rules} ({stages}) fired on {host} with severity {max(a.severity for a in hits)}; "
                          f"isolating the host contains further spread."))
    actions += _block_ips(alerts, get_events)
    actions += _disable_accounts(comp_events, set(comp_hosts))
    return actions


def _block_ips(alerts: list[Alert], get_events: Callable[[list[str]], list[dict]]) -> list[ProposedAction]:
    by_ip: dict[str, set[str]] = {}
    for a in alerts:
        if RULE_STAGE.get(a.rule_id) != "c2":
            continue
        for ev in get_events(a.event_ids[:MAX_ALERT_EVENTS]):
            net = ev.get("net") or {}
            if ev.get("event_type") == "network_conn" and net.get("direction") == "outbound" and _is_external(
                    net.get("dst_ip", "")):
                by_ip.setdefault(net["dst_ip"], set()).add(f"{ev['host']} ({a.rule_id})")
    return [ProposedAction(action="block_ip", target=ip,
                           rationale=f"External address {ip} was contacted in command-and-control activity: "
                                     f"{', '.join(sorted(who))}.") for ip, who in sorted(by_ip.items())]


def _disable_accounts(comp_events: list[dict], comp: set[str]) -> list[ProposedAction]:
    """Accounts used for a type 3 logon that came from another host of the component, other than the
    owner of that source workstation (a user logging on from their own PC is normal)."""
    by_user: dict[str, set[str]] = {}
    for e in comp_events:
        a = e.get("auth") or {}
        if e.get("event_type") == "auth" and a.get("logon_type") == 3 and a.get("result") == "success" \
                and a.get("target_user") and a.get("src_host") in comp and a["src_host"] != e["host"] \
                and HOST_USER.get(a["src_host"]) != a["target_user"]:
            by_user.setdefault(a["target_user"], set()).add(e["host"])
    return [ProposedAction(action="disable_account", target=u,
                           rationale=f"Account {u} logged on over the network (type 3) to "
                                     f"{', '.join(sorted(h))} during the hunt; it may be stolen.")
            for u, h in sorted(by_user.items())]


def _event_ids(comp_events: list[dict], alerts: list[Alert]) -> list[str]:
    ids = [e["event_id"] for e in comp_events]
    for a in alerts:
        ids.extend(i for i in a.event_ids if i not in ids)
    return ids[:MAX_EVENT_IDS]


def _placeholder_window(host: str, comp_events: list[dict], plan: HuntPlan) -> ScoredWindow:
    """No window from ml for this component: maximum uncertainty and zero anomaly (honest default)."""
    first = parse_ts(comp_events[0]["ts"]) if comp_events else plan.time_range.start
    last = parse_ts(comp_events[-1]["ts"]) if comp_events else plan.time_range.start
    return ScoredWindow(window_id=sha1_hex(host, first.isoformat()), host=host, ts_first=first, ts_last=last,
                        event_ids=[e["event_id"] for e in comp_events], anomaly_if=0.0, anomaly_seq=0.0,
                        anomaly=0.0, uncertainty=1.0, top_features=[])


def build_findings(run_id: str, plan: HuntPlan, evidence: dict[str, list[dict]], windows: list[ScoredWindow],
                   alerts: list[Alert], hosts: list[str], lib: Any, ml: Any,
                   get_events: Callable[[list[str]], list[dict]], now: datetime) -> list[Finding]:
    """One finding per connected component of candidate hosts, sorted by confidence (descending)."""
    all_events = _flatten(evidence)
    risk = {}
    for w in windows:
        risk[w.host] = max(risk.get(w.host, 0.0), w.anomaly)
    master = lib.build_chain(all_events, risk)
    findings = []
    for comp_hosts in split_weak_hosts(components(hosts, master), master, alerts):
        comp = set(comp_hosts)
        comp_events = [e for e in all_events if e["host"] in comp]
        comp_alerts = [a for a in alerts if a.host in comp]
        win = representative_window([w for w in windows if w.host in comp]) or _placeholder_window(
            comp_hosts[0], comp_events, plan)
        found = stages_found(plan, evidence, comp, comp_alerts)
        if not comp_alerts and len(found) < 2:
            continue  # Lead fix v2: no alerts and under 2 stages is noise (for example an ML false positive)
        scores, rationale = ml.confidence(win, found, list(plan.expected_stages), comp_hosts)
        times = [parse_ts(e["ts"]) for e in comp_events] or [win.ts_first, win.ts_last]
        users = sorted({u for e in comp_events for u in (e.get("user"), (e.get("auth") or {}).get("target_user")) if u})
        findings.append(Finding(
            finding_id=sha1_hex(run_id, *comp_hosts), run_id=run_id, hosts=comp_hosts, users=users,
            ts_first=min(times), ts_last=max(times), event_ids=_event_ids(comp_events, comp_alerts),
            alert_ids=sorted({a.alert_id for a in comp_alerts}),
            technique_ids=sorted({t for a in comp_alerts for t in a.technique_ids}),
            stages_found=found, scores=scores, cluster_id=win.cluster_id, top_features=win.top_features,
            rationale=rationale, chain=lib.build_chain(comp_events, {h: risk.get(h, 0.2) for h in comp_hosts}),
            recommended_actions=recommend(comp_hosts, comp_events, comp_alerts, get_events), created_at=now))
    return sorted(findings, key=lambda f: (-f.scores.confidence, f.finding_id))
