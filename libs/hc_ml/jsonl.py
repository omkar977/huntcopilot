"""JSONL helpers so training and evaluation run without OpenSearch."""
from __future__ import annotations

import json
from pathlib import Path


def read_jsonl(path: str) -> list[dict]:
    """Read one JSON object per line; blank lines are skipped."""
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def tag_train(events: list[dict]) -> list[dict]:
    """Return events with the train tag added (for files from the benign_train profile that lack it)."""
    for e in events:
        tags = list(e.get("tags") or [])
        if "train" not in tags:
            tags.append("train")
        e["tags"] = tags
    return events


def write_json(path: str, data: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")
