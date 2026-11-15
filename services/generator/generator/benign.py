"""Benign telemetry model and the five hard negatives (spec 7.2 and 7.3)."""
from __future__ import annotations

import base64
import math
import random
from datetime import datetime, timedelta
from typing import Callable

from hc_common.constants import ASSETS, CRITICALITY, HOST_IP, HOST_USER, UPDATE_SERVER_IP

from . import builders as b
from .catalog import (
    ADMIN_SCRIPTS, BENIGN_DOMAINS, DEV_PROCESSES, DOMAIN_ANSWER, DOMAIN_WEIGHTS, EXTERNAL_POOL,
    SERVER_FACTOR, SERVER_FILE_TEMPLATES, SERVER_MIX, SERVER_PROCESSES, SERVERS, WORKSTATIONS,
    WS_FILE_TEMPLATES, WS_MIX, WS_PROCESSES,
)

Event = dict
ASSET_ROLE = {a["host"]: a["role"] for a in ASSETS}
DC_IP = HOST_IP["DC-01"]
FILE_IP = HOST_IP["FILE-01"]
WEB_IP = HOST_IP["WEB-01"]
DB_IP = HOST_IP["DB-01"]


def diurnal(hour: int) -> float:
    """Activity weight for a UTC hour of day: busy 08:00 to 18:00, shoulders, quiet night."""
    if 8 <= hour < 18:
        return 1.0
    if 6 <= hour < 8 or 18 <= hour < 20:
        return 0.5
    return 0.25


def b64(text: str) -> str:
    return base64.b64encode(text.encode("ascii")).decode("ascii")


def _pick(rng: random.Random, items: list, weights: list[float]):
    return rng.choices(items, weights=weights, k=1)[0]


def _count(rng: random.Random, base_n: float) -> int:
    return max(0, int(round(base_n * rng.uniform(0.85, 1.15))))


def _pid(rng: random.Random) -> int:
    return rng.randint(1000, 60000)


def _ws_process(rng: random.Random, ts: datetime, host: str) -> Event:
    user = HOST_USER[host]
    name, parent, tmpl, _ = _pick(rng, WS_PROCESSES, [p[3] for p in WS_PROCESSES])
    cmd = tmpl.format(u=user, doc=f"doc_{rng.randint(1, 400)}")
    return b.proc(ts, host, user, name, _pid(rng), cmd, parent, _pid(rng), "medium")


def _server_process(rng: random.Random, ts: datetime, host: str) -> Event:
    items = SERVER_PROCESSES[host]
    name, parent, cmd, user, integrity, _ = _pick(rng, items, [i[5] for i in items])
    return b.proc(ts, host, user, name, _pid(rng), cmd, parent, _pid(rng), integrity)


def _ws_net(rng: random.Random, ts: datetime, host: str) -> Event:
    user, ip = HOST_USER[host], HOST_IP[host]
    kind = _pick(rng, ["https", "http", "smb", "dns", "ldap", "intranet"], [55, 8, 15, 12, 6, 4])
    out = rng.randint(200, 6000)
    inn = rng.randint(500, 60000)
    if kind == "https":
        return b.net(ts, host, user, ip, rng.choice(EXTERNAL_POOL), 443, "outbound", out, inn, rng)
    if kind == "http":
        return b.net(ts, host, user, ip, rng.choice(EXTERNAL_POOL), 80, "outbound", out, inn, rng)
    if kind == "smb":
        return b.net(ts, host, user, ip, FILE_IP, 445, "internal", out, inn, rng)
    if kind == "dns":
        return b.net(ts, host, user, ip, DC_IP, 53, "internal", 80, 160, rng, proto="udp")
    if kind == "ldap":
        return b.net(ts, host, user, ip, DC_IP, rng.choice([389, 88]), "internal", out, inn, rng)
    return b.net(ts, host, user, ip, WEB_IP, 443, "internal", out, inn, rng)


def _server_net(rng: random.Random, ts: datetime, host: str) -> Event:
    ip = HOST_IP[host]
    out, inn = rng.randint(200, 5000), rng.randint(500, 40000)
    if host == "WEB-01":
        kind = _pick(rng, ["inbound", "db", "ldap", "update"], [60, 20, 10, 10])
        if kind == "inbound":
            src = f"203.0.113.{rng.randint(100, 199)}"
            return b.net(ts, host, "svc_web", src, ip, 443, "inbound", inn, out, rng)
        if kind == "db":
            return b.net(ts, host, "svc_web", ip, DB_IP, 1433, "internal", out, inn, rng)
        if kind == "ldap":
            return b.net(ts, host, "svc_web", ip, DC_IP, 389, "internal", out, inn, rng)
        return b.net(ts, host, "svc_web", ip, rng.choice(EXTERNAL_POOL), 443, "outbound", out, inn, rng)
    if host == "DC-01":
        return b.net(ts, host, "system", ip, FILE_IP, 389, "internal", out, inn, rng)
    kind = _pick(rng, ["ldap", "dns", "update"], [50, 30, 20])
    if kind == "update":
        return b.net(ts, host, "system", ip, rng.choice(EXTERNAL_POOL), 443, "outbound", out, inn, rng)
    port, proto = (389, "tcp") if kind == "ldap" else (53, "udp")
    return b.net(ts, host, "system", ip, DC_IP, port, "internal", out, inn, rng, proto=proto)


def _dns_event(rng: random.Random, ts: datetime, host: str) -> Event:
    domain = _pick(rng, BENIGN_DOMAINS, DOMAIN_WEIGHTS)
    return b.dns(ts, host, b.user_of(host), domain, DOMAIN_ANSWER[domain])


def _file_event(rng: random.Random, ts: datetime, host: str) -> Event:
    if host in HOST_USER:
        user = HOST_USER[host]
        path = rng.choice(WS_FILE_TEMPLATES).format(u=user, n=rng.randint(1, 9999))
    else:
        user = "svc_web" if host == "WEB-01" else "system"
        path = rng.choice(SERVER_FILE_TEMPLATES[host]).format(n=rng.randint(1, 9999))
    return b.file_ev(ts, host, user, path)


def _hour_events(rng: random.Random, host: str, hstart: datetime, peak: float) -> list[Event]:
    """Events of one host for one hour (excluding auth, which is handled per workstation)."""
    is_ws = host in HOST_USER
    mix = WS_MIX if is_ws else SERVER_MIX
    scale = peak * (1.0 if is_ws else SERVER_FACTOR) * diurnal(hstart.hour) / sum(WS_MIX.values())
    makers: dict[str, Callable] = {
        "process": _ws_process if is_ws else _server_process,
        "net": _ws_net if is_ws else _server_net,
        "dns": _dns_event,
        "file": _file_event,
    }
    out: list[Event] = []
    for kind, weight in mix.items():
        if kind == "auth":
            continue
        for _ in range(_count(rng, weight * scale)):
            ts = hstart + timedelta(seconds=rng.randrange(3600))
            out.append(makers[kind](rng, ts, host))
    return out


def _auth_events(rng: random.Random, ws: str, hstart: datetime, peak: float) -> list[Event]:
    """Type 3 logons to FILE-01 (logged on the server) plus the morning type 2 logon on the workstation."""
    user = HOST_USER[ws]
    out: list[Event] = []
    n3 = _count(rng, WS_MIX["auth"] * peak * diurnal(hstart.hour) / sum(WS_MIX.values()))
    for _ in range(n3):
        ts = hstart + timedelta(seconds=rng.randrange(3600))
        result = "failure" if rng.random() < 0.01 else "success"
        out.append(b.auth(ts, "FILE-01", user, 3, result, src_host=ws))
    if hstart.hour == 8:
        ts = hstart + timedelta(seconds=rng.randrange(600, 3000))
        out.append(b.auth(ts, ws, user, 2, "success"))
    return out


def generate_benign(rng: random.Random, start: datetime, end: datetime, peak: float) -> list[Event]:
    """Benign telemetry for every host between start and end."""
    events: list[Event] = []
    hours = int(math.ceil((end - start).total_seconds() / 3600.0))
    for h in range(hours):
        hstart = start + timedelta(hours=h)
        for host in WORKSTATIONS + SERVERS:
            events.extend(_hour_events(rng, host, hstart, peak))
        for ws in WORKSTATIONS:
            events.extend(_auth_events(rng, ws, hstart, peak))
    return [e for e in events if e["ts"] < end]


# ---------------------------------------------------------------- hard negatives (spec 7.3)
def _days(start: datetime, end: datetime) -> list[datetime]:
    n = int(math.ceil((end - start).total_seconds() / 86400.0))
    return [start + timedelta(days=d) for d in range(n)]


def _hn(meta: str) -> dict:
    return {"hard_negative": meta}


def hn_admin_powershell(rng: random.Random, start: datetime, end: datetime) -> list[Event]:
    """HN1: adm_it runs encoded PowerShell on WS-08, about 3 times a day, harmless scripts."""
    out = []
    for day in _days(start, end):
        for _ in range(3):
            ts = day + timedelta(seconds=rng.randrange(8 * 3600 + 1800, 17 * 3600 + 1800))
            cmd = f"powershell.exe -NoProfile -enc {b64(rng.choice(ADMIN_SCRIPTS))}"
            out.append(b.proc(ts, "WS-08", "adm_it", "powershell.exe", _pid(rng), cmd, "explorer.exe", _pid(rng),
                              "high", meta=_hn("adm_powershell")))
    return out


def hn_admin_psexec(rng: random.Random, start: datetime, end: datetime) -> list[Event]:
    """HN2: adm_it uses psexec.exe from WS-08 to one server about once a day."""
    out = []
    for day in _days(start, end):
        ts = day + timedelta(seconds=rng.randrange(9 * 3600, 17 * 3600))
        target = rng.choice(["FILE-01", "DB-01", "WEB-01"])
        cmd = f"psexec.exe \\\\{HOST_IP[target]} -s ipconfig /all"
        out.append(b.proc(ts, "WS-08", "adm_it", "psexec.exe", _pid(rng), cmd, "cmd.exe", _pid(rng), "high",
                          meta=_hn("adm_psexec")))
        out.append(b.net(ts + timedelta(seconds=1), "WS-08", "adm_it", HOST_IP["WS-08"], HOST_IP[target], 445,
                         "internal", 3200, 5400, rng, meta=_hn("adm_psexec")))
    return out


def hn_backup_fanout(rng: random.Random, start: datetime, end: datetime) -> list[Event]:
    """HN3: svc_backup connects from FILE-01 to 10 hosts on 445 around 02:00 every night."""
    out = []
    targets = WORKSTATIONS + ["DB-01", "WEB-01"]
    for day in _days(start, end):
        t = day + timedelta(seconds=2 * 3600 + rng.randrange(-300, 300))
        out.append(b.proc(t, "FILE-01", "svc_backup", "backupagent.exe", _pid(rng), "backupagent.exe /nightly",
                          "services.exe", _pid(rng), "system", meta=_hn("backup_fanout")))
        for target in targets:
            t += timedelta(seconds=rng.randrange(30, 61))
            out.append(b.net(t, "FILE-01", "svc_backup", FILE_IP, HOST_IP[target], 445, "internal",
                             rng.randint(20000, 90000), rng.randint(1000, 4000), rng, meta=_hn("backup_fanout")))
            out.append(b.auth(t + timedelta(seconds=1), target, "svc_backup", 3, "success", src_host="FILE-01",
                              meta=_hn("backup_fanout")))
    return out


def hn_update_beacon(rng: random.Random, start: datetime, end: datetime) -> list[Event]:
    """HN4: every workstation connects to the update server every 300 s with 2 percent jitter."""
    out = []
    for ws in WORKSTATIONS:
        t = start + timedelta(seconds=rng.uniform(0, 300))
        while t < end:
            out.append(b.net(t, ws, HOST_USER[ws], HOST_IP[ws], UPDATE_SERVER_IP, 443, "outbound",
                             rng.randint(550, 650), rng.randint(300, 500), rng, meta=_hn("update_beacon")))
            t += timedelta(seconds=300 * (1 + rng.uniform(-0.02, 0.02)))
    return out


def hn_dev_base64(rng: random.Random, start: datetime, end: datetime) -> list[Event]:
    """HN5: developers on WS-02 run long command lines containing base64 text without -enc flags."""
    out = []
    for day in _days(start, end):
        for _ in range(12):
            ts = day + timedelta(seconds=rng.randrange(9 * 3600, 18 * 3600))
            name, parent, tmpl = rng.choice(DEV_PROCESSES)
            blob = b64("fixture-data-" + "".join(rng.choice("abcdefghijklmnop") for _ in range(48)))
            out.append(b.proc(ts, "WS-02", "bob", name, _pid(rng), tmpl.format(b64=blob), parent, _pid(rng),
                              meta=_hn("dev_base64")))
    return out


HARD_NEGATIVES = {
    "adm_powershell": hn_admin_powershell,
    "adm_psexec": hn_admin_psexec,
    "backup_fanout": hn_backup_fanout,
    "update_beacon": hn_update_beacon,
    "dev_base64": hn_dev_base64,
}


def generate_hard_negatives(seed: int, start: datetime, end: datetime) -> list[Event]:
    """All five hard negatives. Each has its own random stream so it does not disturb the others."""
    out: list[Event] = []
    for name, fn in HARD_NEGATIVES.items():
        out.extend(fn(random.Random(f"{seed}:hn:{name}"), start, end))
    return [e for e in out if start <= e["ts"] < end]


__all__ = ["generate_benign", "generate_hard_negatives", "HARD_NEGATIVES", "diurnal", "b64", "CRITICALITY",
           "ASSET_ROLE"]
