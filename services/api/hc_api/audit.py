"""Append-only, hash-chained audit log (spec Section 5.9)."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Optional

GENESIS = "0" * 64
FIELDS = ("seq", "ts", "actor", "action", "object_type", "object_id", "before", "after", "prev_hash")


def canonical(entry: dict) -> str:
    """Canonical JSON of an entry without the hash field (sorted keys, no spaces)."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, entry: dict) -> str:
    """sha256 hex of prev_hash concatenated with the canonical JSON of the entry."""
    return hashlib.sha256((prev_hash + canonical(entry)).encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_last_line(path: str) -> Optional[str]:
    """Return the last non-empty line of the file, or None if there is none."""
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        chunk = 65536
        while True:
            start = max(0, size - chunk)
            fh.seek(start)
            lines = [ln for ln in fh.read(size - start).split(b"\n") if ln.strip()]
            if len(lines) >= 2 or start == 0:
                return lines[-1].decode("utf-8", "replace") if lines else None
            chunk *= 4


class AuditLog:
    """Writes entries to HC_AUDIT_PATH. Thread-safe within one process."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()

    def append(self, actor: str, action: str, object_type: str, object_id: str,
               before: Any = None, after: Any = None) -> dict:
        """Append one entry and return it. before/after must be JSON-serialisable."""
        with self._lock:
            seq, prev = 1, GENESIS
            last = _read_last_line(self.path)
            if last is not None:
                try:
                    prev_entry = json.loads(last)
                    seq, prev = int(prev_entry["seq"]) + 1, str(prev_entry["hash"])
                except (ValueError, KeyError, TypeError):
                    # corrupt tail: keep writing so the service works; verify_chain reports the damage
                    seq = self._count_lines() + 1
                    prev = hashlib.sha256(last.encode("utf-8")).hexdigest()
            entry = {
                "seq": seq, "ts": _now_iso(), "actor": actor, "action": action,
                "object_type": object_type, "object_id": object_id,
                "before": before, "after": after, "prev_hash": prev,
            }
            entry["hash"] = compute_hash(prev, entry)
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def _count_lines(self) -> int:
        with open(self.path, "rb") as fh:
            return sum(1 for ln in fh if ln.strip())

    def read(self, limit: int = 100) -> tuple[list[dict], int]:
        """Return (the last `limit` entries in seq order, total entries). Corrupt lines are skipped."""
        entries = read_entries(self.path)
        return entries[-limit:] if limit > 0 else [], len(entries)

    def verify(self) -> tuple[bool, Optional[int]]:
        return verify_chain(self.path)


def read_entries(path: str) -> list[dict]:
    """All parseable entries of the file, in file order."""
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def verify_chain(path: str) -> tuple[bool, Optional[int]]:
    """Check the hash chain. Returns (ok, first_bad_seq); first_bad_seq is None when ok."""
    if not os.path.exists(path):
        return True, None
    prev = GENESIS
    expected = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            expected += 1
            try:
                entry = json.loads(line)
                seq = entry["seq"]
                good = (
                    isinstance(entry, dict)
                    and all(k in entry for k in FIELDS + ("hash",))
                    and seq == expected
                    and entry["prev_hash"] == prev
                    and entry["hash"] == compute_hash(prev, entry)
                )
            except (ValueError, KeyError, TypeError):
                return False, expected
            if not good:
                return False, expected
            prev = entry["hash"]
    return True, None
