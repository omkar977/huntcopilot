"""Deterministic fallback hunt templates and the intent matcher (spec Section 10.2).

Every template takes a TimeRange and returns a HuntPlan with source "fallback". The plan carries a
placeholder validation result; the pipeline replaces it with the real validate_plan output.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from hc_common.schemas import Cond, HuntPlan, HuntStep, Query, TimeRange, ValidationResult

EXAMPLE_INTENTS = [
    "Find possible lateral movement after a suspicious PowerShell execution.",
    "Look for credential dumping from LSASS on servers.",
    "Hunt for C2 beaconing to external hosts.",
    "Check for phishing macros that launched PowerShell.",
]

# Order matters: the first match wins (spec 10.2). Word boundaries avoid false hits such as "same" for "sam".
MATCHERS: list[tuple[str, re.Pattern]] = [
    ("lateral_after_powershell", re.compile(r"\b(lateral\w*|psexec\w*|smb|winrm|pivot\w*)\b")),
    ("credential_dumping", re.compile(r"\b(credential\w*|lsass|ntds|sam|dump\w*)\b")),
    ("c2_beaconing", re.compile(r"\b(c2|beacon\w*|callback\w*|command[\s\-]+and[\s\-]+control)\b")),
    ("phishing_execution", re.compile(r"\b(phish\w*|macro\w*|docm|office)\b")),
]


def match_template(intent: str) -> Optional[str]:
    """Return the template name for an analyst sentence, or None when nothing matches."""
    text = intent.lower()
    for name, rx in MATCHERS:
        if rx.search(text):
            return name
    return None


def _c(field: str, op: str, value) -> Cond:
    return Cond(field=field, op=op, value=value)


def _step(step_id: str, description: str, stage: str, filters: list[Cond], depends_on: Optional[list[str]] = None,
          evidence: str = "", group_by: Optional[str] = None) -> HuntStep:
    return HuntStep(step_id=step_id, description=description, stage=stage, depends_on=depends_on or [],
                    expected_evidence=evidence, query=Query(filters=filters, group_by=group_by, size=500))


def _plan(intent: str, tr: TimeRange, template: str, hypothesis: str, stages: list[str],
          steps: list[HuntStep]) -> HuntPlan:
    return HuntPlan(
        plan_id=uuid.uuid4().hex, intent_text=intent, hypothesis=hypothesis, source="fallback",
        template=template, time_range=tr, steps=steps, expected_stages=stages,
        created_at=datetime.now(timezone.utc).replace(microsecond=0),
        validation=ValidationResult(ok=True),
    )


def lateral_after_powershell(tr: TimeRange, intent: str = "") -> HuntPlan:
    """Encoded PowerShell on a host followed by lateral movement to other hosts (the demo hunt)."""
    steps = [
        _step("s1", "Encoded PowerShell executions", "execution",
              [_c("event_type", "eq", "process_create"), _c("process.name", "eq", "powershell.exe"),
               _c("process.cmdline", "contains", "-enc")],
              evidence="powershell.exe with an encoded command"),
        _step("s2", "Internal SMB, RPC and WinRM connections from those hosts", "lateral_movement",
              [_c("event_type", "eq", "network_conn"), _c("net.direction", "eq", "internal"),
               _c("net.dst_port", "in", [445, 135, 5985]), _c("host", "in", "${s1.hosts}")],
              ["s1"], "internal connections to remote-administration ports"),
        _step("s3", "Network logons on the contacted hosts", "lateral_movement",
              [_c("event_type", "eq", "auth"), _c("auth.logon_type", "eq", 3),
               _c("auth.result", "eq", "success"), _c("host", "in", "${s2.dst_hosts}")],
              ["s2"], "successful type 3 logons on the target hosts"),
        _step("s4", "Remote execution tools", "lateral_movement",
              [_c("event_type", "eq", "process_create"),
               _c("process.name", "in", ["psexec.exe", "wmic.exe", "winrs.exe", "psexesvc.exe"])],
              ["s1"], "psexec, wmic, winrs or the psexec service"),
    ]
    return _plan(intent, tr, "lateral_after_powershell",
                 "Encoded PowerShell on a host was followed by lateral movement to other hosts.",
                 ["execution", "lateral_movement"], steps)


def credential_dumping(tr: TimeRange, intent: str = "") -> HuntPlan:
    """Credential access: LSASS access, registry hive saves and NTDS extraction."""
    steps = [
        _step("s1", "Processes touching LSASS", "credential_access",
              [_c("event_type", "eq", "process_create"), _c("process.cmdline", "contains", "lsass")],
              evidence="procdump or comsvcs against lsass"),
        _step("s2", "Registry hive saves", "credential_access",
              [_c("event_type", "eq", "process_create"), _c("process.cmdline", "contains", "save HKLM")],
              evidence="reg save of SAM or SYSTEM"),
        _step("s3", "NTDS extraction tool", "credential_access",
              [_c("event_type", "eq", "process_create"), _c("process.name", "eq", "ntdsutil.exe")],
              evidence="ntdsutil activity"),
    ]
    return _plan(intent, tr, "credential_dumping",
                 "An attacker dumped credentials from memory, registry hives or the domain database.",
                 ["credential_access"], steps)


def c2_beaconing(tr: TimeRange, intent: str = "") -> HuntPlan:
    """Command and control: DNS lookups and outbound connections grouped for beacon review."""
    steps = [
        _step("s1", "DNS queries grouped by domain", "c2",
              [_c("event_type", "eq", "dns_query")], evidence="domains queried repeatedly",
              group_by="dns.query"),
        _step("s2", "Outbound connections grouped by destination", "c2",
              [_c("event_type", "eq", "network_conn"), _c("net.direction", "eq", "outbound")],
              evidence="regular outbound connections", group_by="net.dst_ip"),
    ]
    return _plan(intent, tr, "c2_beaconing",
                 "A compromised host is beaconing to an external command and control server.",
                 ["c2"], steps)


def phishing_execution(tr: TimeRange, intent: str = "") -> HuntPlan:
    """Initial access through an Office document that launched PowerShell and dropped a binary."""
    steps = [
        _step("s1", "Office applications spawning PowerShell", "execution",
              [_c("event_type", "eq", "process_create"),
               _c("process.parent_name", "in", ["winword.exe", "excel.exe", "outlook.exe"]),
               _c("process.name", "eq", "powershell.exe")],
              evidence="powershell started by an Office application"),
        _step("s2", "Executables dropped under AppData", "initial_access",
              [_c("event_type", "eq", "file_create"), _c("file.path", "contains", "AppData"),
               _c("file.path", "contains", ".exe")],
              evidence="new executable in a user profile"),
    ]
    return _plan(intent, tr, "phishing_execution",
                 "A phishing document ran PowerShell and dropped an executable.",
                 ["initial_access", "execution"], steps)


TEMPLATES: dict[str, Callable[..., HuntPlan]] = {
    "lateral_after_powershell": lateral_after_powershell,
    "credential_dumping": credential_dumping,
    "c2_beaconing": c2_beaconing,
    "phishing_execution": phishing_execution,
}
