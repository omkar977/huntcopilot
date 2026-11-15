"""Index template hc-events-template (spec Appendix F)."""
from __future__ import annotations

from typing import Any

TEMPLATE_NAME = "hc-events-template"


def build_template(prefix: str = "hc-events") -> dict[str, Any]:
    """Return the composable index template body for indices named <prefix>-YYYY.MM.DD."""
    kw = {"type": "keyword"}
    return {
        "index_patterns": [f"{prefix}-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic": "false",
                "properties": {
                    "event_id": kw,
                    "schema_version": kw,
                    "ts": {"type": "date"},
                    "ingested_at": {"type": "date"},
                    "host": kw,
                    "host_ip": {"type": "ip"},
                    "user": kw,
                    "event_type": kw,
                    "tags": kw,
                    "process": {"properties": {
                        "name": kw,
                        "pid": {"type": "integer"},
                        "cmdline": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 512}}},
                        "parent_name": kw,
                        "parent_pid": {"type": "integer"},
                        "user": kw,
                        "integrity": kw,
                    }},
                    "net": {"properties": {
                        "src_ip": {"type": "ip"},
                        "src_port": {"type": "integer"},
                        "dst_ip": {"type": "ip"},
                        "dst_port": {"type": "integer"},
                        "proto": kw,
                        "bytes_out": {"type": "long"},
                        "bytes_in": {"type": "long"},
                        "dst_host": kw,
                        "direction": kw,
                    }},
                    "auth": {"properties": {
                        "logon_type": {"type": "integer"},
                        "result": kw,
                        "target_user": kw,
                        "src_host": kw,
                        "src_ip": kw,
                    }},
                    "file": {"properties": {
                        "path": {"type": "keyword", "fields": {"text": {"type": "text"}}},
                        "action": kw,
                        "sha256": kw,
                    }},
                    "dns": {"properties": {"query": kw, "qtype": kw, "answer": kw, "rcode": kw}},
                    "gt": {"properties": {"is_malicious": {"type": "boolean"}, "scenario": kw, "stage": kw}},
                },
            },
        },
    }
