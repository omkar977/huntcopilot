"""Event dict builders. Events are plain dicts until the final validation step in core.py."""
from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Optional

from hc_common.constants import HOST_IP, HOST_USER, IP_HOST

Event = dict[str, Any]


def gt(malicious: bool = False, scenario: str = "", stage: str = "") -> dict[str, Any]:
    """Ground-truth block (evaluation only)."""
    return {"is_malicious": malicious, "scenario": scenario, "stage": stage}


def base(ts: datetime, host: str, user: str, event_type: str, payload_key: str, payload: dict,
         truth: Optional[dict] = None, meta: Optional[dict] = None) -> Event:
    """Assemble one event dict. `_meta` carries labelling info and is removed before validation."""
    ev: Event = {
        "ts": ts.replace(microsecond=0),
        "host": host,
        "host_ip": HOST_IP[host],
        "user": user,
        "event_type": event_type,
        "process": None, "net": None, "auth": None, "file": None, "dns": None,
        "tags": [],
        "gt": truth or gt(),
        "_meta": meta or {},
    }
    ev[payload_key] = payload
    return ev


def proc(ts: datetime, host: str, user: str, name: str, pid: int, cmdline: str, parent: str, ppid: int,
         integrity: str = "medium", truth: Optional[dict] = None, meta: Optional[dict] = None,
         proc_user: Optional[str] = None) -> Event:
    payload = {"name": name.lower(), "pid": pid, "cmdline": cmdline, "parent_name": parent.lower(),
               "parent_pid": ppid, "user": proc_user if proc_user is not None else user, "integrity": integrity}
    return base(ts, host, user, "process_create", "process", payload, truth, meta)


def net(ts: datetime, host: str, user: str, src_ip: str, dst_ip: str, dst_port: int, direction: str,
        bytes_out: int, bytes_in: int, rng: random.Random, proto: str = "tcp", src_port: Optional[int] = None,
        truth: Optional[dict] = None, meta: Optional[dict] = None) -> Event:
    payload = {"src_ip": src_ip, "src_port": src_port if src_port is not None else rng.randint(49152, 65535),
               "dst_ip": dst_ip, "dst_port": dst_port, "proto": proto, "bytes_out": bytes_out,
               "bytes_in": bytes_in, "dst_host": IP_HOST.get(dst_ip, ""), "direction": direction}
    return base(ts, host, user, "network_conn", "net", payload, truth, meta)


def auth(ts: datetime, host: str, target_user: str, logon_type: int, result: str, src_host: str = "",
         truth: Optional[dict] = None, meta: Optional[dict] = None) -> Event:
    payload = {"logon_type": logon_type, "result": result, "target_user": target_user, "src_host": src_host,
               "src_ip": HOST_IP.get(src_host, "")}
    return base(ts, host, target_user, "auth", "auth", payload, truth, meta)


def file_ev(ts: datetime, host: str, user: str, path: str, truth: Optional[dict] = None,
            meta: Optional[dict] = None, action: str = "create") -> Event:
    payload = {"path": path, "action": action, "sha256": ""}
    return base(ts, host, user, "file_create", "file", payload, truth, meta)


def dns(ts: datetime, host: str, user: str, query: str, answer: str, truth: Optional[dict] = None,
        meta: Optional[dict] = None) -> Event:
    payload = {"query": query, "qtype": "A", "answer": answer, "rcode": "NOERROR"}
    return base(ts, host, user, "dns_query", "dns", payload, truth, meta)


def user_of(host: str) -> str:
    """Default user of a host: the workstation owner, else system."""
    return HOST_USER.get(host, "system")
