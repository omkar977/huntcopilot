#!/usr/bin/env python3
"""Generate tests/fixtures (deterministic, standard library only). Owner: Lead.

Usage: python tools/make_fixtures.py            (writes the fixture files)
       python tools/make_fixtures.py --check    (also runs the self-check of expected alerts)
All content is synthetic: .test domains, RFC 5737 external IPs, 10.10.0.0/16 internal.
"""
from __future__ import annotations

import base64
import json
import random
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "common"))

from hc_common.constants import (  # noqa: E402
    ADMIN_USER, ASSETS, C2_DOMAIN, C2_IP, HOST_IP, HOST_USER, IP_HOST,
)
from hc_common.ids import uuid5_hex  # noqa: E402

SEED = 7
DAY = datetime(2026, 11, 12, tzinfo=timezone.utc)
T_START = DAY.replace(hour=9)
rng = random.Random(SEED)
_counter = 0
EVENTS: list[dict] = []


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def emit(ts, host, user, etype, payload, gt=None):
    global _counter
    _counter += 1
    ev = {
        "schema_version": "1.0",
        "event_id": uuid5_hex(SEED, _counter),
        "ts": iso(ts),
        "host": host,
        "host_ip": HOST_IP[host],
        "user": user,
        "event_type": etype,
        "process": None, "net": None, "auth": None, "file": None, "dns": None,
        "tags": [],
        "gt": gt or {"is_malicious": False, "scenario": "", "stage": ""},
    }
    ev[{"process_create": "process", "network_conn": "net", "auth": "auth",
        "file_create": "file", "dns_query": "dns"}[etype]] = payload
    EVENTS.append(ev)


def proc(name, cmdline, parent, user, pid=None, ppid=None, integrity="medium"):
    return {"name": name, "pid": pid or rng.randint(1000, 60000), "cmdline": cmdline,
            "parent_name": parent, "parent_pid": ppid or rng.randint(500, 9000),
            "user": user, "integrity": integrity}


def net(src_host, dst_ip, dst_port, direction, bytes_out=0):
    return {"src_ip": HOST_IP[src_host], "src_port": rng.randint(49152, 65535), "dst_ip": dst_ip,
            "dst_port": dst_port, "proto": "tcp", "bytes_out": bytes_out,
            "bytes_in": rng.randint(200, 90000), "dst_host": IP_HOST.get(dst_ip, ""),
            "direction": direction}


def gt(scenario, stage):
    return {"is_malicious": True, "scenario": scenario, "stage": stage}


# ----------------------------------------------------------------------- benign background
BENIGN_DOMAINS = ["mail.corp.test", "intranet.corp.test", "cdn.example.test", "news.example.test",
                  "update.example.test", "files.corp.test", "chat.example.test", "docs.corp.test"]
EXT_IPS = [f"198.51.100.{n}" for n in (10, 20, 30, 40, 50)]
WS_PROCS = [("chrome.exe", "explorer.exe"), ("msedge.exe", "explorer.exe"), ("outlook.exe", "explorer.exe"),
            ("winword.exe", "outlook.exe"), ("excel.exe", "explorer.exe"), ("teams.exe", "explorer.exe"),
            ("notepad.exe", "explorer.exe"), ("svchost.exe", "services.exe")]
SRV_PROCS = [("svchost.exe", "services.exe"), ("taskhostw.exe", "svchost.exe"), ("wmiprvse.exe", "svchost.exe")]


def rand_ts(lo_min=0, hi_min=120):
    return T_START + timedelta(seconds=rng.randint(lo_min * 60, hi_min * 60))


def benign_host(host, count):
    user = HOST_USER.get(host, "svc_web")
    is_ws = host.startswith("WS-")
    for _ in range(count):
        ts = rand_ts()
        kind = rng.choices(["proc", "net", "dns", "auth", "file"], weights=[34, 30, 18, 8, 10])[0]
        if kind == "proc":
            name, parent = rng.choice(WS_PROCS if is_ws else SRV_PROCS)
            cmd = name if name != "winword.exe" else f"winword.exe C:\\Users\\{user}\\Documents\\notes_{rng.randint(1, 30)}.docx"
            emit(ts, host, user, "process_create", proc(name, cmd, parent, user))
        elif kind == "net":
            if is_ws and rng.random() < 0.4:
                emit(ts, host, user, "network_conn", net(host, HOST_IP["FILE-01"], 445, "internal", rng.randint(300, 9000)))
            elif not is_ws and rng.random() < 0.5:
                emit(ts, host, user, "network_conn", net(host, HOST_IP["DC-01"], 389, "internal", rng.randint(200, 4000)))
            else:
                emit(ts, host, user, "network_conn", net(host, rng.choice(EXT_IPS), 443, "outbound", rng.randint(300, 20000)))
        elif kind == "dns":
            d = rng.choice(BENIGN_DOMAINS)
            emit(ts, host, user, "dns_query", {"query": d, "qtype": "A", "answer": rng.choice(EXT_IPS), "rcode": "NOERROR"})
        elif kind == "auth":
            if is_ws:
                emit(ts, host, user, "auth", {"logon_type": 2, "result": "success", "target_user": user,
                                              "src_host": host, "src_ip": HOST_IP[host]})
            else:
                src = rng.choice(["WS-01", "WS-03"])
                emit(ts, host, HOST_USER[src], "auth", {"logon_type": 3, "result": "success",
                                                        "target_user": HOST_USER[src], "src_host": src,
                                                        "src_ip": HOST_IP[src]})
        else:
            path = (f"C:\\Users\\{user}\\Documents\\report_{rng.randint(1, 99)}.xlsx" if is_ws
                    else f"D:\\Shares\\Finance\\q{rng.randint(1, 4)}_{rng.randint(1, 20)}.xlsx")
            emit(ts, host, user, "file_create", {"path": path, "action": "create", "sha256": ""})


benign_host("WS-01", 85)
benign_host("WS-03", 85)
benign_host("FILE-01", 75)

# ----------------------------------------------------------------------- hard negatives on WS-08 (adm_it)
b64 = base64.b64encode("Write-Output hunt-demo".encode("utf-16-le")).decode()
emit(T_START + timedelta(minutes=12), "WS-08", ADMIN_USER, "process_create",
     proc("powershell.exe", f"powershell.exe -NoProfile -enc {b64}", "explorer.exe", ADMIN_USER))
emit(T_START + timedelta(minutes=40), "WS-08", ADMIN_USER, "process_create",
     proc("psexec.exe", "psexec.exe \\\\10.10.2.31 -accepteula ipconfig", "cmd.exe", ADMIN_USER))
emit(T_START + timedelta(minutes=41), "WS-08", ADMIN_USER, "network_conn", net("WS-08", HOST_IP["DB-01"], 445, "internal", 900))
emit(T_START + timedelta(minutes=70), "WS-08", "heidi", "dns_query",
     {"query": "mail.corp.test", "qtype": "A", "answer": "198.51.100.10", "rcode": "NOERROR"})

# ----------------------------------------------------------------------- attack (apt_chain mini)
T0 = T_START + timedelta(minutes=30)  # 09:30:00Z
V, VU = "WS-03", "carol"
S = "apt_chain"
emit(T0, V, VU, "file_create", {"path": "C:\\Users\\carol\\Downloads\\invoice_4471.docm", "action": "create", "sha256": ""}, gt(S, "initial_access"))
emit(T0 + timedelta(seconds=2), V, VU, "process_create",
     proc("winword.exe", "winword.exe /n C:\\Users\\carol\\Downloads\\invoice_4471.docm", "outlook.exe", VU), gt(S, "initial_access"))
emit(T0 + timedelta(seconds=8), V, VU, "process_create",
     proc("powershell.exe", f"powershell.exe -nop -w hidden -enc {b64}", "winword.exe", VU), gt(S, "execution"))
emit(T0 + timedelta(seconds=10), V, VU, "dns_query",
     {"query": C2_DOMAIN, "qtype": "A", "answer": C2_IP, "rcode": "NOERROR"}, gt(S, "c2"))
emit(T0 + timedelta(seconds=12), V, VU, "network_conn", net(V, C2_IP, 443, "outbound", 4200), gt(S, "c2"))
emit(T0 + timedelta(seconds=20), V, VU, "file_create",
     {"path": "C:\\Users\\carol\\AppData\\Roaming\\update.exe", "action": "create", "sha256": ""}, gt(S, "initial_access"))
for i in (1, 2, 3):  # a few beacons
    t = T0 + timedelta(minutes=5 + i)
    emit(t, V, VU, "dns_query", {"query": C2_DOMAIN, "qtype": "A", "answer": C2_IP, "rcode": "NOERROR"}, gt(S, "c2"))
    emit(t + timedelta(seconds=1), V, VU, "network_conn", net(V, C2_IP, 443, "outbound", 300 + 30 * i), gt(S, "c2"))

L0 = T0 + timedelta(minutes=15)  # lateral movement starts 09:45:00Z
targets = ["FILE-01", "DB-01", "WS-05", "WS-06"]
for n in range(3):  # failed logons on the first target
    emit(L0 + timedelta(seconds=n * 5), "FILE-01", ADMIN_USER, "auth",
         {"logon_type": 3, "result": "failure", "target_user": ADMIN_USER, "src_host": V, "src_ip": HOST_IP[V]}, gt(S, "lateral_movement"))
for i, tgt in enumerate(targets):
    t = L0 + timedelta(seconds=30 + i * 90)
    for j, port in enumerate((445, 135, 5985)):
        emit(t + timedelta(seconds=j), V, ADMIN_USER, "network_conn", net(V, HOST_IP[tgt], port, "internal", 700), gt(S, "lateral_movement"))
    emit(t + timedelta(seconds=5), tgt, ADMIN_USER, "auth",
         {"logon_type": 3, "result": "success", "target_user": ADMIN_USER, "src_host": V, "src_ip": HOST_IP[V]}, gt(S, "lateral_movement"))
    emit(t + timedelta(seconds=8), tgt, ADMIN_USER, "process_create",
         proc("psexesvc.exe", "C:\\Windows\\PSEXESVC.exe", "services.exe", "system", integrity="system"), gt(S, "lateral_movement"))
emit(L0 + timedelta(seconds=40), V, ADMIN_USER, "process_create",
     proc("psexec.exe", "psexec.exe \\\\10.10.2.31 -accepteula cmd.exe", "powershell.exe", ADMIN_USER), gt(S, "lateral_movement"))
emit(L0 + timedelta(seconds=45), V, ADMIN_USER, "process_create",
     proc("wmic.exe", "wmic.exe /node:10.10.2.21 process call create cmd.exe", "powershell.exe", ADMIN_USER), gt(S, "lateral_movement"))

C0 = T0 + timedelta(minutes=30)  # credential dumping 10:00:00Z on DB-01
emit(C0, "DB-01", ADMIN_USER, "process_create",
     proc("procdump.exe", "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp", "cmd.exe", ADMIN_USER, integrity="high"), gt(S, "credential_access"))
emit(C0 + timedelta(seconds=3), "DB-01", ADMIN_USER, "file_create",
     {"path": "C:\\Windows\\Temp\\lsass.dmp", "action": "create", "sha256": ""}, gt(S, "credential_access"))

EVENTS.sort(key=lambda e: (e["ts"], e["event_id"]))


# ----------------------------------------------------------------------- self-check (mirrors rules HC-001..HC-010)
def self_check() -> list[str]:
    errs: list[str] = []
    ev = EVENTS

    def get(e, path):
        cur = e
        for p in path.split("."):
            cur = cur.get(p) if isinstance(cur, dict) else None
            if cur is None:
                return None
        return cur

    def hosts_for(pred):
        return {e["host"] for e in ev if pred(e)}

    enc_re = re.compile(r"\s-(enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{8,}", re.I)
    hc1 = hosts_for(lambda e: get(e, "process.name") == "powershell.exe"
                    and get(e, "process.parent_name") in ("winword.exe", "excel.exe", "outlook.exe"))
    hc2 = hosts_for(lambda e: get(e, "process.name") == "powershell.exe"
                    and enc_re.search(get(e, "process.cmdline") or "")
                    and not (e["host"] == "WS-08" and e["user"] == ADMIN_USER))
    hc4 = hosts_for(lambda e: get(e, "process.name") in ("psexec.exe", "wmic.exe", "winrs.exe")
                    and re.search(r"(\\\\|/node:|-r:)", get(e, "process.cmdline") or "")
                    and not (e["host"] == "WS-08" and e["user"] == ADMIN_USER))
    hc6 = hosts_for(lambda e: get(e, "process.name") == "psexesvc.exe")
    hc7 = hosts_for(lambda e: re.search(r"(procdump.*lsass|comsvcs\.dll.*minidump)", get(e, "process.cmdline") or "", re.I))
    hc8 = hosts_for(lambda e: re.search(r"(reg(\.exe)?\s+save\s+hklm\\(sam|system)|ntdsutil)", get(e, "process.cmdline") or "", re.I))
    hc10 = hosts_for(lambda e: e["event_type"] == "file_create"
                     and re.search(r"\\AppData\\Roaming\\.*\.(exe|dll)$", get(e, "file.path") or "", re.I))
    # HC-005: >= 4 distinct internal dst_ip on 445/135/5985 within 600 s, per host
    hc5 = set()
    by_host: dict[str, list] = {}
    for e in ev:
        if e["event_type"] == "network_conn" and get(e, "net.direction") == "internal" and get(e, "net.dst_port") in (445, 135, 5985):
            by_host.setdefault(e["host"], []).append(e)
    for h, items in by_host.items():
        for i, a in enumerate(items):
            ta = datetime.fromisoformat(a["ts"].replace("Z", "+00:00"))
            win = [b for b in items[i:] if (datetime.fromisoformat(b["ts"].replace("Z", "+00:00")) - ta).total_seconds() <= 600]
            if len({b["net"]["dst_ip"] for b in win}) >= 4:
                hc5.add(h)
    # HC-009: >=15 outbound events per (host, dst_ip) in 7200 s with CV <= 0.25
    hc9 = set()
    grp: dict[tuple, list] = {}
    for e in ev:
        if e["event_type"] == "network_conn" and get(e, "net.direction") == "outbound":
            grp.setdefault((e["host"], e["net"]["dst_ip"]), []).append(e)
    for key, items in grp.items():
        if len(items) >= 15:
            hc9.add(key[0])

    def need(name, got, want):
        if want not in got:
            errs.append(f"{name} should fire on {want}, got {sorted(got)}")

    need("HC-001", hc1, "WS-03")
    need("HC-002", hc2, "WS-03")
    need("HC-004", hc4, "WS-03")
    need("HC-005", hc5, "WS-03")
    need("HC-006", hc6, "FILE-01")
    need("HC-006", hc6, "DB-01")
    need("HC-007", hc7, "DB-01")
    need("HC-010", hc10, "WS-03")
    if "WS-08" in hc2:
        errs.append("HC-002 must not fire on WS-08")
    if "WS-08" in hc4:
        errs.append("HC-004 must not fire on WS-08")
    if hc8:
        errs.append(f"HC-008 must not fire, got {hc8}")
    if hc9:
        errs.append(f"HC-009 must not fire, got {hc9}")
    return errs


def main() -> int:
    out = ROOT / "tests" / "fixtures"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "events_sample.jsonl", "w", encoding="utf-8") as fh:
        for e in EVENTS:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    (out / "assets.json").write_text(json.dumps(ASSETS, indent=2) + "\n", encoding="utf-8")
    expected = {
        "must_fire": [
            {"rule_id": "HC-001", "host": "WS-03"}, {"rule_id": "HC-002", "host": "WS-03"},
            {"rule_id": "HC-003", "host": "WS-03"}, {"rule_id": "HC-004", "host": "WS-03"},
            {"rule_id": "HC-005", "host": "WS-03"}, {"rule_id": "HC-006", "host": "FILE-01"},
            {"rule_id": "HC-006", "host": "DB-01"}, {"rule_id": "HC-007", "host": "DB-01"},
            {"rule_id": "HC-010", "host": "WS-03"},
        ],
        "must_not_fire": [
            {"rule_id": "HC-008"}, {"rule_id": "HC-009"},
            {"rule_id": "HC-002", "host": "WS-08"}, {"rule_id": "HC-004", "host": "WS-08"},
        ],
    }
    (out / "expected_alerts.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(EVENTS)} events to {out / 'events_sample.jsonl'}")
    if "--check" in sys.argv:
        errs = self_check()
        for e in errs:
            print("SELF-CHECK FAIL:", e)
        print("self-check:", "FAIL" if errs else "PASS")
        return 1 if errs else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
