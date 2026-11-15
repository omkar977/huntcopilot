"""Shared constants. Owner: Lead. Values are part of the contract (spec Sections 5, 7, 8)."""
from __future__ import annotations

STREAM_TELEMETRY = "hc:telemetry"
STREAM_ALERTS = "hc:alerts"
STREAM_DLQ = "hc:dlq"
GROUP_INGESTORS = "ingestors"
STREAM_MAXLEN = 200000

STAGES = ["initial_access", "execution", "credential_access", "lateral_movement", "c2"]

RULE_STAGE = {
    "HC-001": "execution",
    "HC-002": "execution",
    "HC-003": "c2",
    "HC-004": "lateral_movement",
    "HC-005": "lateral_movement",
    "HC-006": "lateral_movement",
    "HC-007": "credential_access",
    "HC-008": "credential_access",
    "HC-009": "c2",
    "HC-010": "initial_access",
}

ASSETS = [
    {"host": "WS-01", "ip": "10.10.1.11", "role": "workstation", "criticality": 2},
    {"host": "WS-02", "ip": "10.10.1.12", "role": "workstation", "criticality": 2},
    {"host": "WS-03", "ip": "10.10.1.13", "role": "workstation", "criticality": 2},
    {"host": "WS-04", "ip": "10.10.1.14", "role": "workstation", "criticality": 2},
    {"host": "WS-05", "ip": "10.10.1.15", "role": "workstation", "criticality": 2},
    {"host": "WS-06", "ip": "10.10.1.16", "role": "workstation", "criticality": 2},
    {"host": "WS-07", "ip": "10.10.1.17", "role": "workstation", "criticality": 2},
    {"host": "WS-08", "ip": "10.10.1.18", "role": "workstation", "criticality": 2},
    {"host": "FILE-01", "ip": "10.10.2.21", "role": "file server", "criticality": 3},
    {"host": "DB-01", "ip": "10.10.2.31", "role": "database", "criticality": 5},
    {"host": "DC-01", "ip": "10.10.2.5", "role": "domain controller", "criticality": 5},
    {"host": "WEB-01", "ip": "10.10.3.41", "role": "web server", "criticality": 4},
]

CRITICALITY = {a["host"]: a["criticality"] for a in ASSETS}
HOST_IP = {a["host"]: a["ip"] for a in ASSETS}
IP_HOST = {a["ip"]: a["host"] for a in ASSETS}

HOST_USER = {
    "WS-01": "alice",
    "WS-02": "bob",
    "WS-03": "carol",
    "WS-04": "dave",
    "WS-05": "erin",
    "WS-06": "frank",
    "WS-07": "grace",
    "WS-08": "heidi",
}
ADMIN_USER = "adm_it"
SERVICE_USERS = ["svc_backup", "svc_web"]

# Reserved, safe indicators used by the synthetic generator (never real).
C2_DOMAIN = "cdn-sync.badhost.test"
C2_IP = "203.0.113.50"
UPDATE_SERVER_IP = "198.51.100.77"

ALLOWED_FIELDS = [
    "ts",
    "host",
    "user",
    "event_type",
    "process.name",
    "process.cmdline",
    "process.parent_name",
    "net.dst_ip",
    "net.dst_port",
    "net.dst_host",
    "net.direction",
    "auth.logon_type",
    "auth.result",
    "auth.target_user",
    "dns.query",
    "file.path",
    "tags",
]

ACTIONS = ["isolate_host", "kill_process", "block_ip", "disable_account"]
