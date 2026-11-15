"""Attack scenarios (spec 7.4). All content is harmless: base64 decodes to plain text, domains end in .test."""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Optional

from hc_common.constants import ADMIN_USER, C2_DOMAIN, C2_IP, HOST_IP

from . import builders as b
from .benign import b64

Event = dict

LATERAL_TARGETS = ["FILE-01", "DB-01", "WS-05", "WS-06"]
LATERAL_PORTS = [445, 135, 5985]
DEMO_TEXT = "hunt-demo"


def _t(base: datetime, seconds: float) -> datetime:
    return base + timedelta(seconds=seconds)


def _meta(scenario: str, component: str) -> dict:
    return {"scenario": scenario, "component": component}


def phishing(rng: random.Random, t0: datetime, label: str = "phishing", ps_pid: Optional[int] = None) -> list[Event]:
    """Victim WS-03 (carol): docm download, Word, encoded PowerShell, DNS, outbound C2 connection, dropped exe."""
    host, user, ip = "WS-03", "carol", HOST_IP["WS-03"]
    meta = _meta(label, "phishing")
    docm = "C:\\Users\\carol\\Downloads\\invoice_4471.docm"
    outlook_pid, word_pid = rng.randint(1000, 60000), rng.randint(1000, 60000)
    ps_pid = ps_pid or rng.randint(1000, 60000)
    ia, ex, c2 = (b.gt(True, label, s) for s in ("initial_access", "execution", "c2"))
    return [
        b.file_ev(_t(t0, 0), host, user, docm, truth=ia, meta=meta),
        b.proc(_t(t0, 2), host, user, "winword.exe", word_pid, f'winword.exe "{docm}"', "outlook.exe",
               outlook_pid, truth=ia, meta=meta),
        b.proc(_t(t0, 8), host, user, "powershell.exe", ps_pid,
               f"powershell.exe -nop -w hidden -enc {b64(DEMO_TEXT)}", "winword.exe", word_pid, truth=ex, meta=meta),
        b.dns(_t(t0, 10), host, user, C2_DOMAIN, C2_IP, truth=c2, meta=meta),
        b.net(_t(t0, 12), host, user, ip, C2_IP, 443, "outbound", rng.randint(4000, 4400), 800, rng, truth=c2,
              meta=meta),
        b.file_ev(_t(t0, 20), host, user, "C:\\Users\\carol\\AppData\\Roaming\\update.exe", truth=ia, meta=meta),
    ]


def lateral_movement(rng: random.Random, t0: datetime, label: str = "lateral_movement",
                     ps_pid: Optional[int] = None) -> list[Event]:
    """From WS-03 with the stolen adm_it account to FILE-01, DB-01, WS-05 and WS-06 over about 8 minutes."""
    src = "WS-03"
    truth = b.gt(True, label, "lateral_movement")
    meta = _meta(label, "lateral_movement")
    ps_pid = ps_pid or rng.randint(1000, 60000)
    out: list[Event] = []
    first = LATERAL_TARGETS[0]
    for k in range(3):
        out.append(b.auth(_t(t0, k * 2), first, ADMIN_USER, 3, "failure", src_host=src, truth=truth, meta=meta))
    for i, target in enumerate(LATERAL_TARGETS):
        base = _t(t0, 6 + i * 150)
        for j, port in enumerate(LATERAL_PORTS):
            out.append(b.net(_t(base, j * 2), src, ADMIN_USER, HOST_IP[src], HOST_IP[target], port, "internal",
                             rng.randint(900, 4000), rng.randint(900, 4000), rng, truth=truth, meta=meta))
        out.append(b.auth(_t(base, 8), target, ADMIN_USER, 3, "success", src_host=src, truth=truth, meta=meta))
        out.append(b.proc(_t(base, 12), target, "system", "psexesvc.exe", rng.randint(1000, 60000),
                          "C:\\Windows\\PSEXESVC.exe", "services.exe", rng.randint(500, 900), "system",
                          truth=truth, meta=meta))
    out.append(b.proc(_t(t0, 10), src, ADMIN_USER, "wmic.exe", rng.randint(1000, 60000),
                      f'wmic.exe /node:{HOST_IP["FILE-01"]} process call create "cmd.exe /c whoami"',
                      "powershell.exe", ps_pid, "high", truth=truth, meta=meta))
    out.append(b.proc(_t(t0, 160), src, ADMIN_USER, "psexec.exe", rng.randint(1000, 60000),
                      f'psexec.exe \\\\{HOST_IP["DB-01"]} -accepteula -s cmd.exe', "powershell.exe", ps_pid, "high",
                      truth=truth, meta=meta))
    return out


def credential_dumping(rng: random.Random, t0: datetime, label: str = "credential_dumping") -> list[Event]:
    """DB-01 (procdump, comsvcs MiniDump, reg save SAM) then DC-01 (ntdsutil)."""
    truth = b.gt(True, label, "credential_access")
    meta = _meta(label, "credential_dumping")
    user = ADMIN_USER
    cmd_pid = rng.randint(1000, 60000)
    return [
        b.proc(_t(t0, 0), "DB-01", user, "procdump.exe", rng.randint(1000, 60000),
               "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp", "cmd.exe", cmd_pid, "high",
               truth=truth, meta=meta),
        b.file_ev(_t(t0, 3), "DB-01", user, "C:\\Windows\\Temp\\lsass.dmp", truth=truth, meta=meta),
        b.proc(_t(t0, 40), "DB-01", user, "rundll32.exe", rng.randint(1000, 60000),
               "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 612 C:\\Windows\\Temp\\d.dmp full",
               "cmd.exe", cmd_pid, "high", truth=truth, meta=meta),
        b.proc(_t(t0, 80), "DB-01", user, "reg.exe", rng.randint(1000, 60000),
               "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save", "cmd.exe", cmd_pid, "high",
               truth=truth, meta=meta),
        b.proc(_t(t0, 200), "DC-01", user, "ntdsutil.exe", rng.randint(1000, 60000),
               'ntdsutil.exe "ac i ntds" ifm "create full C:\\Windows\\Temp\\ntds" q q', "cmd.exe",
               rng.randint(1000, 60000), "high", truth=truth, meta=meta),
    ]


def c2_beacon(rng: random.Random, t0: datetime, host: str, label: str = "c2", component: str = "c2",
              hours: float = 2.0) -> list[Event]:
    """Beacon every 60 s with 10 percent jitter for two hours: DNS query then outbound connection."""
    truth = b.gt(True, label, "c2")
    meta = _meta(label, component)
    user = b.user_of(host)
    ip = HOST_IP[host]
    out = [b.proc(t0, host, user, "rundll32.exe", rng.randint(1000, 60000),
                  "rundll32.exe C:\\ProgramData\\cache.dll,Start", "powershell.exe", rng.randint(1000, 60000),
                  "high" if host != "WS-03" else "medium", truth=truth, meta=meta)]
    t = t0 + timedelta(seconds=30)
    end = t0 + timedelta(hours=hours)
    while t < end:
        out.append(b.dns(t, host, user, C2_DOMAIN, C2_IP, truth=truth, meta=meta))
        out.append(b.net(t + timedelta(seconds=1), host, user, ip, C2_IP, 443, "outbound",
                         rng.randint(300, 420), rng.randint(200, 600), rng, truth=truth, meta=meta))
        t += timedelta(seconds=60 * (1 + rng.uniform(-0.1, 0.1)))
    return out


def standalone(name: str, rng: random.Random, t0: datetime) -> list[Event]:
    """One scenario on its own, starting at t0."""
    if name == "phishing":
        return phishing(rng, t0)
    if name == "lateral_movement":
        return lateral_movement(rng, t0)
    if name == "credential_dumping":
        return credential_dumping(rng, t0)
    if name == "c2":
        return c2_beacon(rng, t0, "WS-03") + c2_beacon(rng, t0, "DB-01")
    return apt_chain(rng, t0)


def apt_chain(rng: random.Random, t0: datetime) -> list[Event]:
    """Phishing at t0, C2 on WS-03 from t0+5 min, lateral at +15 min, credential dumping at +30, C2 on DB-01 at +35."""
    ps_pid = rng.randint(1000, 60000)
    out = phishing(rng, t0, "apt_chain", ps_pid)
    out += c2_beacon(rng, _t(t0, 300), "WS-03", "apt_chain", "c2_ws03")
    out += lateral_movement(rng, _t(t0, 900), "apt_chain", ps_pid)
    out += credential_dumping(rng, _t(t0, 1800), "apt_chain")
    out += c2_beacon(rng, _t(t0, 2100), "DB-01", "apt_chain", "c2_db01")
    return out
