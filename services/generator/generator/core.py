"""Generator core: configuration, event assembly, validation, JSONL serialisation, labels.json."""
from __future__ import annotations

import json
import random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterator, Optional

from hc_common.clients import iso, parse_ts
from hc_common.ids import uuid5_hex
from hc_common.schemas import Event

from .benign import generate_benign, generate_hard_negatives
from .catalog import DEFAULT_SEEDS, DEFAULT_START, DEFAULT_WS_PEAK, PROFILES, SCENARIOS
from .scenarios import standalone

LABELS_VERSION = "1.0"


@dataclass
class GenConfig:
    """Parameters of one generation run."""

    profile: str = "eval"
    scenarios: Optional[list[str]] = None
    seed: Optional[int] = None
    duration_hours: float = 24.0
    events_per_host_hour: Optional[float] = None
    start: Optional[str] = None
    resolved: dict[str, Any] = field(default_factory=dict, repr=False)

    def validate(self) -> "GenConfig":
        """Fill defaults and check values. Raises ValueError with a readable message."""
        if self.profile not in PROFILES:
            raise ValueError(f"profile must be one of {PROFILES}")
        names = self.scenarios
        if names is None:
            names = ["apt_chain"] if self.profile == "eval" else []
        names = list(dict.fromkeys(names))
        bad = [n for n in names if n not in SCENARIOS]
        if bad:
            raise ValueError(f"unknown scenarios {bad}; choose from {SCENARIOS}")
        if self.profile == "benign_train" and names:
            raise ValueError("profile benign_train contains no attacks, so scenarios must be empty")
        if not 0 < float(self.duration_hours) <= 168:
            raise ValueError("duration_hours must be between 0 and 168")
        if self.events_per_host_hour is not None and not 0 < float(self.events_per_host_hour) <= 5000:
            raise ValueError("events_per_host_hour must be between 0 and 5000")
        seed = DEFAULT_SEEDS[self.profile] if self.seed is None else int(self.seed)
        start = parse_ts(self.start or DEFAULT_START[self.profile])
        if start.minute or start.second or start.microsecond:
            raise ValueError("start must be on a whole hour, for example 2026-11-12T00:00:00Z")
        self.resolved = {"scenarios": names, "seed": seed, "start": start}
        return self


def _attack_t0(seed: int, name: str, start: datetime) -> datetime:
    """t0 is a random time between 10:00 and 15:00 on the first day (own random stream per scenario)."""
    r = random.Random(f"{seed}:t0:{name}")
    return start + timedelta(seconds=10 * 3600 + r.randrange(5 * 3600))


def build_events(cfg: GenConfig) -> tuple[list[dict], dict]:
    """Return (validated event dicts sorted by ts, labels). Deterministic for a given config."""
    cfg.validate()
    seed, start, names = cfg.resolved["seed"], cfg.resolved["start"], cfg.resolved["scenarios"]
    end = start + timedelta(hours=float(cfg.duration_hours))
    peak = float(cfg.events_per_host_hour or DEFAULT_WS_PEAK)
    raw = generate_benign(random.Random(f"{seed}:benign"), start, end, peak)
    raw += generate_hard_negatives(seed, start, end)
    t0s: dict[str, datetime] = {}
    for name in names:
        t0s[name] = _attack_t0(seed, name, start)
        raw += standalone(name, random.Random(f"{seed}:attack:{name}"), t0s[name])
    order = sorted(range(len(raw)), key=lambda i: (raw[i]["ts"], i))
    events: list[dict] = []
    train = cfg.profile == "benign_train"
    for counter, idx in enumerate(order):
        ev = raw[idx]
        meta = ev.pop("_meta")
        ev["event_id"] = uuid5_hex(seed, counter)
        ev["tags"] = ["train"] if train else []
        ev["_meta"] = meta
        events.append(ev)
    labels = _labels(cfg, events, t0s, seed, start)
    out = []
    for ev in events:
        ev.pop("_meta")
        out.append(Event.model_validate(ev).model_dump(mode="json"))
    return out, labels


def _labels(cfg: GenConfig, events: list[dict], t0s: dict[str, datetime], seed: int, start: datetime) -> dict:
    """labels.json content: event ids and hosts of each scenario and of each hard negative."""
    scen: dict[str, dict] = {}
    hard: dict[str, dict] = defaultdict(lambda: {"event_ids": [], "hosts": set()})
    malicious = 0
    for ev in events:
        meta = ev["_meta"]
        if "scenario" in meta:
            s = scen.setdefault(meta["scenario"], {"event_ids": [], "hosts": set(), "components": {}})
            s["event_ids"].append(ev["event_id"])
            s["hosts"].add(ev["host"])
            comp = s["components"].setdefault(meta["component"], {"event_ids": [], "hosts": set()})
            comp["event_ids"].append(ev["event_id"])
            comp["hosts"].add(ev["host"])
            malicious += 1
        elif "hard_negative" in meta:
            h = hard[meta["hard_negative"]]
            h["event_ids"].append(ev["event_id"])
            h["hosts"].add(ev["host"])

    def fin(d: dict) -> dict:
        d = dict(d)
        d["hosts"] = sorted(d["hosts"])
        d["event_count"] = len(d["event_ids"])
        if "components" in d:
            d["components"] = {k: fin(v) for k, v in d["components"].items()}
        return d

    scenarios = {}
    for name, d in scen.items():
        scenarios[name] = fin(d)
        scenarios[name]["t0"] = iso(t0s[name])
    return {
        "labels_version": LABELS_VERSION,
        "profile": cfg.profile,
        "seed": seed,
        "start": iso(start),
        "duration_hours": float(cfg.duration_hours),
        "event_count": len(events),
        "malicious_count": malicious,
        "scenarios": scenarios,
        "hard_negatives": {k: fin(v) for k, v in sorted(hard.items())},
    }


def to_line(event: dict) -> str:
    """One compact JSON line (key order follows the schema, so output is byte-stable)."""
    return json.dumps(event, separators=(",", ":"), ensure_ascii=True)


def iter_lines(events: list[dict]) -> Iterator[str]:
    for ev in events:
        yield to_line(ev)
