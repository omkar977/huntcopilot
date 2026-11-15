"""Static catalogs for the generator: domains, process profiles, file templates, constants.

Everything here is synthetic. Domains end in .test, external IPs come from 198.51.100.0/24 and
203.0.113.0/24, internal IPs from 10.10.0.0/16.
"""
from __future__ import annotations

from hc_common.constants import C2_IP, UPDATE_SERVER_IP

SCENARIOS = ["phishing", "lateral_movement", "credential_dumping", "c2", "apt_chain"]
PROFILES = ["benign_train", "eval"]
DEFAULT_SEEDS = {"benign_train": 1001, "eval": 2002}
DEFAULT_START = {"benign_train": "2026-11-11T00:00:00Z", "eval": "2026-11-12T00:00:00Z"}

WORKSTATIONS = [f"WS-0{i}" for i in range(1, 9)]
SERVERS = ["FILE-01", "DB-01", "DC-01", "WEB-01"]

# Peak events per workstation-hour, tuned so the defaults (12 hosts, 24 h) give about 50 000 events.
DEFAULT_WS_PEAK = 366.0
SERVER_FACTOR = 0.4
# Event-type mix of one workstation-hour (spec 7.2: 60 process, 80 net, 30 dns, 5 auth, 10 file).
WS_MIX = {"process": 60, "net": 80, "dns": 30, "auth": 5, "file": 10}
SERVER_MIX = {"process": 40, "net": 40, "dns": 8, "auth": 0, "file": 12}

# About 40 benign domains. Internal ones resolve to WEB-01, external ones to 198.51.100.x.
INTERNAL_DOMAINS = [
    "mail.corp.test", "intranet.corp.test", "files.corp.test", "wiki.corp.test", "hr.corp.test",
    "vpn.corp.test", "ticket.corp.test", "print.corp.test",
]
EXTERNAL_DOMAINS = [
    "search.web.test", "news.daily.test", "video.stream.test", "cdn.static.test", "update.vendor.test",
    "maps.web.test", "docs.cloud.test", "chat.cloud.test", "ads.metrics.test", "social.feed.test",
    "shop.market.test", "weather.info.test", "music.stream.test", "code.host.test", "pkg.registry.test",
    "img.cdn.test", "fonts.cdn.test", "api.partner.test", "login.idp.test", "meet.cloud.test",
    "sport.news.test", "bank.portal.test", "mail.public.test", "wiki.public.test", "forum.tech.test",
    "stats.metrics.test", "dl.vendor.test", "ocsp.certs.test", "time.sync.test", "tools.dev.test",
    "blog.tech.test", "learn.edu.test", "jobs.board.test", "travel.book.test", "pay.gateway.test",
    "cloud.backup.test",
]
BENIGN_DOMAINS = INTERNAL_DOMAINS + EXTERNAL_DOMAINS
WEB_IP = "10.10.3.41"


def _external_pool() -> list[str]:
    reserved = {UPDATE_SERVER_IP.rsplit(".", 1)[1], C2_IP.rsplit(".", 1)[1]}
    return [f"198.51.100.{n}" for n in range(10, 70) if str(n) not in reserved]


EXTERNAL_POOL = _external_pool()


def domain_answer(index: int, domain: str) -> str:
    """Stable answer IP for a benign domain."""
    if domain.endswith(".corp.test"):
        return WEB_IP
    return EXTERNAL_POOL[index % len(EXTERNAL_POOL)]


DOMAIN_ANSWER = {d: domain_answer(i, d) for i, d in enumerate(BENIGN_DOMAINS)}
DOMAIN_WEIGHTS = [1.0 / (rank + 1) for rank in range(len(BENIGN_DOMAINS))]  # Zipf-like popularity

# Workstation processes: (name, parent_name, cmdline template, weight). {u} user, {doc} document name.
WS_PROCESSES = [
    ("chrome.exe", "explorer.exe", "chrome.exe --profile-directory=Default", 10),
    ("chrome.exe", "chrome.exe", "chrome.exe --type=renderer --lang=en-US", 14),
    ("msedge.exe", "explorer.exe", "msedge.exe --profile-directory=Default", 6),
    ("msedge.exe", "msedge.exe", "msedge.exe --type=utility --lang=en-US", 7),
    ("outlook.exe", "explorer.exe", "outlook.exe", 4),
    ("winword.exe", "explorer.exe", 'winword.exe "C:\\Users\\{u}\\Documents\\{doc}.docx"', 5),
    ("winword.exe", "outlook.exe", 'winword.exe "C:\\Users\\{u}\\AppData\\Local\\Temp\\{doc}.docx"', 2),
    ("excel.exe", "explorer.exe", 'excel.exe "C:\\Users\\{u}\\Documents\\{doc}.xlsx"', 5),
    ("teams.exe", "explorer.exe", "teams.exe --processStart Teams.exe", 6),
    ("notepad.exe", "explorer.exe", "notepad.exe", 3),
    ("calc.exe", "explorer.exe", "calc.exe", 1),
    ("svchost.exe", "services.exe", "svchost.exe -k netsvcs -p", 14),
    ("svchost.exe", "services.exe", "svchost.exe -k LocalService -p", 6),
    ("backgroundtaskhost.exe", "svchost.exe", "backgroundTaskHost.exe -ServerName:App.AppXabc.mca", 4),
    ("conhost.exe", "cmd.exe", "conhost.exe 0xffffffff -ForceV1", 2),
    ("cmd.exe", "explorer.exe", "cmd.exe /c dir", 1),
    ("powershell.exe", "explorer.exe", "powershell.exe -NoLogo -Command Get-Process", 1),
    ("onedrive.exe", "explorer.exe", "onedrive.exe /background", 3),
]

# Server processes: host -> list of (name, parent, cmdline, user, integrity, weight)
SERVER_PROCESSES = {
    "FILE-01": [
        ("svchost.exe", "services.exe", "svchost.exe -k netsvcs -p", "system", "system", 10),
        ("searchindexer.exe", "services.exe", "SearchIndexer.exe /Embedding", "system", "system", 4),
        ("vssvc.exe", "services.exe", "vssvc.exe", "system", "system", 2),
    ],
    "DB-01": [
        ("svchost.exe", "services.exe", "svchost.exe -k netsvcs -p", "system", "system", 8),
        ("sqlservr.exe", "services.exe", "sqlservr.exe -sMSSQLSERVER", "system", "system", 3),
        ("sqlagent.exe", "services.exe", "SQLAGENT.EXE -i MSSQLSERVER", "system", "system", 3),
    ],
    "DC-01": [
        ("svchost.exe", "services.exe", "svchost.exe -k netsvcs -p", "system", "system", 10),
        ("dns.exe", "services.exe", "dns.exe", "system", "system", 3),
        ("w32tm.exe", "svchost.exe", "w32tm.exe /query /status", "system", "system", 2),
    ],
    "WEB-01": [
        ("svchost.exe", "services.exe", "svchost.exe -k netsvcs -p", "system", "system", 8),
        ("w3wp.exe", "svchost.exe", "w3wp.exe -ap DefaultAppPool", "svc_web", "high", 6),
        ("inetmgr.exe", "services.exe", "inetmgr.exe", "svc_web", "high", 1),
    ],
}

WS_FILE_TEMPLATES = [
    "C:\\Users\\{u}\\Documents\\report_{n}.xlsx",
    "C:\\Users\\{u}\\Documents\\notes_{n}.docx",
    "C:\\Users\\{u}\\Downloads\\statement_{n}.pdf",
    "C:\\Users\\{u}\\Desktop\\todo_{n}.txt",
    "C:\\Users\\{u}\\AppData\\Local\\Temp\\tmp{n}.tmp",
    "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Edge\\cache_{n}.dat",
]
SERVER_FILE_TEMPLATES = {
    "FILE-01": ["D:\\Shares\\dept\\file_{n}.xlsx", "D:\\Shares\\dept\\doc_{n}.docx"],
    "DB-01": ["D:\\SQLData\\backup_{n}.bak", "D:\\SQLData\\log_{n}.ldf"],
    "DC-01": ["C:\\Windows\\System32\\LogFiles\\dns_{n}.log"],
    "WEB-01": ["C:\\inetpub\\logs\\LogFiles\\u_ex{n}.log"],
}

# Harmless scripts for the adm_it hard negative (base64 of plain ASCII text, never executed).
ADMIN_SCRIPTS = ["Get-Date", "Get-Process", "Get-Service", "Get-Host", "hostname"]
DEV_PROCESSES = [
    ("python.exe", "code.exe", "python.exe build_tools.py --input {b64} --out C:\\dev\\out"),
    ("node.exe", "code.exe", "node.exe C:\\dev\\app\\scripts\\fixture.js --data {b64} --verbose"),
    ("git.exe", "cmd.exe", 'git.exe commit -m "fixture {b64}"'),
    ("code.exe", "explorer.exe", "code.exe --folder-uri vscode-remote://{b64}"),
]
