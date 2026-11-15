"""Small synthetic telemetry generator used ONLY by the M3 tests (not the M1 generator).

It follows spec Sections 7.2 to 7.4 closely enough to exercise features, models and metrics.
Everything is synthetic: .test domains and reserved IP ranges only.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import numpy as np

from hc_common.constants import ASSETS, C2_DOMAIN, C2_IP, HOST_IP, HOST_USER, UPDATE_SERVER_IP

BASE = datetime(2026, 11, 12, 0, 0, 0, tzinfo=timezone.utc)
DOMAINS = [f"site{i}.corp.test" for i in range(40)] + ["mail.corp.test", "intranet.corp.test"]
BENIGN_PROCS = [("chrome.exe", "explorer.exe"), ("msedge.exe", "explorer.exe"), ("outlook.exe", "explorer.exe"),
                ("winword.exe", "explorer.exe"), ("excel.exe", "explorer.exe"), ("teams.exe", "explorer.exe"),
                ("svchost.exe", "services.exe"), ("explorer.exe", "userinit.exe")]


class Gen:
    def __init__(self, seed: int, train: bool) -> None:
        self.rng = np.random.RandomState(seed)
        self.train = train
        self.events: list[dict] = []
        self.n = 0

    def add(self, ts, host, etype, payload, mal=False, scenario="", stage="") -> None:
        self.n += 1
        user = HOST_USER.get(host, "svc_web")
        ev = {"schema_version": "1.0", "event_id": f"e{self.n:08d}", "ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "host": host, "host_ip": HOST_IP[host], "user": user, "event_type": etype,
              "process": None, "net": None, "auth": None, "file": None, "dns": None,
              "tags": ["train"] if self.train else [],
              "gt": {"is_malicious": mal, "scenario": scenario, "stage": stage}}
        ev[{"process_create": "process", "network_conn": "net", "auth": "auth", "file_create": "file",
            "dns_query": "dns"}[etype]] = payload
        self.events.append(ev)

    def proc(self, ts, host, name, parent, cmd=None, user=None, **kw) -> None:
        self.add(ts, host, "process_create", {"name": name, "pid": int(self.rng.randint(1000, 60000)),
                 "cmdline": cmd or name, "parent_name": parent, "parent_pid": 100,
                 "user": user or HOST_USER.get(host, "svc_web"), "integrity": "medium"}, **kw)

    def net(self, ts, host, dst_ip, port, direction="outbound", out=1000, dst_host="", **kw) -> None:
        self.add(ts, host, "network_conn", {"src_ip": HOST_IP[host], "src_port": 50000, "dst_ip": dst_ip,
                 "dst_port": port, "proto": "tcp", "bytes_out": out, "bytes_in": 500, "dst_host": dst_host,
                 "direction": direction}, **kw)

    def auth(self, ts, host, ltype, result="success", user="", src="", **kw) -> None:
        self.add(ts, host, "auth", {"logon_type": ltype, "result": result,
                 "target_user": user or HOST_USER.get(host, "svc_web"), "src_host": src, "src_ip": ""}, **kw)

    def dns(self, ts, host, q, **kw) -> None:
        self.add(ts, host, "dns_query", {"query": q, "qtype": "A", "answer": "198.51.100.10", "rcode": "NOERROR"}, **kw)

    def file(self, ts, host, path, **kw) -> None:
        self.add(ts, host, "file_create", {"path": path, "action": "create", "sha256": ""}, **kw)


def _times(g: Gen, rate_per_hour: float, hours: int = 24):
    """Event times with a diurnal curve: busy 08:00 to 18:00."""
    for h in range(hours):
        scale = 1.0 if 8 <= h < 18 else 0.08
        k = g.rng.poisson(rate_per_hour * scale)
        for s in g.rng.randint(0, 3600, size=k):
            yield BASE + timedelta(hours=h, seconds=int(s))


def benign(g: Gen, scale: float = 0.3, hours: int = 24) -> None:
    """Benign noise plus the five hard negatives. scale 1.0 is about 185 events per workstation peak hour."""
    for a in ASSETS:
        host, ws = a["host"], a["role"] == "workstation"
        user = HOST_USER.get(host, "svc_web")
        for t in _times(g, 60 * scale * (1 if ws else 0.4), hours):
            name, parent = BENIGN_PROCS[g.rng.randint(len(BENIGN_PROCS))]
            g.proc(t, host, name, parent)
        for t in _times(g, 80 * scale * (1 if ws else 0.6), hours):
            if ws and g.rng.rand() < 0.3:
                g.net(t, host, "10.10.2.21", 445, "internal", dst_host="FILE-01")
            else:
                g.net(t, host, f"198.51.100.{g.rng.randint(10, 60)}", 443, out=int(g.rng.randint(500, 3000)))
        for t in _times(g, 30 * scale, hours):
            z = min(int(g.rng.zipf(1.6)) - 1, len(DOMAINS) - 1)
            g.dns(t, host, DOMAINS[z])
        for t in _times(g, 5 * scale, hours):
            g.auth(t, host, 3 if g.rng.rand() < 0.6 else 2, user=user)
        for t in _times(g, 10 * scale, hours):
            g.file(t, host, f"C:\\Users\\{user}\\Documents\\doc_{g.rng.randint(999)}.docx")
        if ws:
            for s in range(0, hours * 3600, 300):  # updater beacon look-alike, 2 percent jitter
                t = BASE + timedelta(seconds=s + int(g.rng.randint(-6, 7)))
                g.net(t, host, UPDATE_SERVER_IP, 443, out=800)
    _hard_negatives(g, hours)


def _hard_negatives(g: Gen, hours: int) -> None:
    for i in range(3):  # adm_it encoded PowerShell on WS-08
        t = BASE + timedelta(hours=9 + 3 * i, minutes=5)
        enc = base64.b64encode(b"inventory-report").decode()
        g.proc(t, "WS-08", "powershell.exe", "cmd.exe", f"powershell.exe -enc {enc}", user="adm_it")
    g.proc(BASE + timedelta(hours=11), "WS-08", "psexec.exe", "cmd.exe", "psexec.exe \\\\10.10.2.21 hostname",
           user="adm_it")
    for k, target in enumerate(["FILE-01", "DB-01", "DC-01", "WEB-01", "WS-01", "WS-02"]):  # nightly backup fan-out
        g.net(BASE + timedelta(hours=2, seconds=k * 20), "FILE-01", HOST_IP[target], 445, "internal",
              dst_host=target)
    for t in _times(g, 6, hours):  # developer long command lines with base64 text
        g.proc(t, "WS-02", "python.exe", "cmd.exe", "python.exe build.py --blob " + "QUJDREVGR0hJSktMTU5PUA==" * 4)


def attack_apt(g: Gen, t0: datetime) -> None:
    """Compact apt_chain: phishing, C2, lateral movement, credential dumping, C2 on DB-01."""
    kw = dict(mal=True, scenario="apt_chain")
    enc = base64.b64encode(b"hunt-demo").decode()
    g.file(t0, "WS-03", "C:\\Users\\carol\\Downloads\\invoice_4471.docm", stage="initial_access", **kw)
    g.proc(t0 + timedelta(seconds=2), "WS-03", "winword.exe", "outlook.exe", "winword.exe invoice_4471.docm",
           stage="initial_access", **kw)
    g.proc(t0 + timedelta(seconds=8), "WS-03", "powershell.exe", "winword.exe",
           f"powershell.exe -nop -w hidden -enc {enc}", stage="execution", **kw)
    g.dns(t0 + timedelta(seconds=10), "WS-03", C2_DOMAIN, stage="c2", **kw)
    g.file(t0 + timedelta(seconds=20), "WS-03", "C:\\Users\\carol\\AppData\\Roaming\\update.exe",
           stage="initial_access", **kw)
    for host, start in (("WS-03", 5), ("DB-01", 35)):
        for i in range(120):
            t = t0 + timedelta(minutes=start, seconds=int(60 * i + g.rng.randint(-6, 7)))
            g.dns(t, host, C2_DOMAIN, stage="c2", **kw)
            g.net(t + timedelta(seconds=1), host, C2_IP, 443, out=int(g.rng.randint(300, 420)), stage="c2", **kw)
    lat = t0 + timedelta(minutes=15)
    for k in range(3):
        g.auth(lat + timedelta(seconds=k), "FILE-01", 3, "failure", "adm_it", "WS-03", stage="lateral_movement", **kw)
    for j, target in enumerate(["FILE-01", "DB-01", "WS-05", "WS-06"]):
        t = lat + timedelta(seconds=60 + 110 * j)
        for p in (445, 135, 5985):
            g.net(t, "WS-03", HOST_IP[target], p, "internal", dst_host=target, stage="lateral_movement", **kw)
        g.auth(t + timedelta(seconds=3), target, 3, "success", "adm_it", "WS-03", stage="lateral_movement", **kw)
        g.proc(t + timedelta(seconds=5), target, "psexesvc.exe", "services.exe", stage="lateral_movement", **kw)
    g.proc(lat + timedelta(seconds=30), "WS-03", "psexec.exe", "powershell.exe", "psexec.exe \\\\10.10.2.31 cmd",
           stage="lateral_movement", **kw)
    cred = t0 + timedelta(minutes=30)
    g.proc(cred, "DB-01", "procdump.exe", "cmd.exe", "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp",
           stage="credential_access", **kw)
    g.file(cred + timedelta(seconds=1), "DB-01", "C:\\Windows\\Temp\\lsass.dmp", stage="credential_access", **kw)
    g.proc(cred + timedelta(seconds=20), "DB-01", "reg.exe", "cmd.exe", "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save",
           stage="credential_access", **kw)
    g.proc(cred + timedelta(seconds=40), "DC-01", "ntdsutil.exe", "cmd.exe", "ntdsutil.exe ifm create full C:\\Windows\\Temp\\ntds",
           stage="credential_access", **kw)


def make_train(seed: int = 1001, scale: float = 0.3, hours: int = 24) -> list[dict]:
    g = Gen(seed, train=True)
    benign(g, scale, hours)
    return sorted(g.events, key=lambda e: (e["ts"], e["event_id"]))


def make_eval(seed: int = 2002, scale: float = 0.3, hours: int = 24, attack: bool = True) -> list[dict]:
    g = Gen(seed, train=False)
    benign(g, scale, hours)
    if attack:
        attack_apt(g, BASE + timedelta(hours=10, minutes=int(g.rng.randint(0, 120))))
    return sorted(g.events, key=lambda e: (e["ts"], e["event_id"]))
