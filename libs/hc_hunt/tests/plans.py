"""Plan builders for the hc_hunt tests. Owner: M2."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hc_common.schemas import HuntPlan, ValidationResult

START = datetime(2026, 11, 12, 0, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 12, 23, 59, 59, tzinfo=timezone.utc)


def f(field, op, value):
    return {"field": field, "op": op, "value": value}


def step(step_id, filters, depends_on=(), group_by=None, size=200, stage=""):
    return {"step_id": step_id, "description": f"step {step_id}", "stage": stage, "depends_on": list(depends_on),
            "query": {"filters": filters, "group_by": group_by, "size": size}}


def plan(steps, start=START, end=END, expected=("execution", "lateral_movement")):
    return HuntPlan.model_validate({
        "plan_id": "p1", "intent_text": "test", "hypothesis": "h", "source": "fallback", "template": "",
        "time_range": {"start": start, "end": end}, "steps": steps, "expected_stages": list(expected),
        "created_at": START + timedelta(hours=1), "validation": ValidationResult(ok=True).model_dump(),
    })


def demo_plan():
    """The lateral_after_powershell template of Section 10.2."""
    return plan([
        step("s1", [f("event_type", "eq", "process_create"), f("process.name", "eq", "powershell.exe"),
                    f("process.cmdline", "contains", "-enc")], stage="execution"),
        step("s2", [f("event_type", "eq", "network_conn"), f("net.direction", "eq", "internal"),
                    f("net.dst_port", "in", [445, 135, 5985]), f("host", "in", "${s1.hosts}")],
             depends_on=["s1"], stage="lateral_movement"),
        step("s3", [f("event_type", "eq", "auth"), f("auth.logon_type", "eq", 3), f("auth.result", "eq", "success"),
                    f("host", "in", "${s2.dst_hosts}")], depends_on=["s2"], stage="lateral_movement"),
        step("s4", [f("event_type", "eq", "process_create"),
                    f("process.name", "in", ["psexec.exe", "wmic.exe", "winrs.exe", "psexesvc.exe"])],
             depends_on=["s1"], stage="lateral_movement"),
    ])
