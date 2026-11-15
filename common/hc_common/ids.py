"""Deterministic id helpers. Owner: Lead."""
from __future__ import annotations

import hashlib
import uuid

NAMESPACE = uuid.UUID("7d1b6b0e-0d6d-4f6a-9c5e-2f6f4f6c0a11")


def uuid5_hex(seed: int, counter: int) -> str:
    """Reproducible 32-char hex id for generated events."""
    return uuid.uuid5(NAMESPACE, f"{seed}:{counter}").hex


def sha1_hex(*parts: str) -> str:
    """sha1 hex of the parts joined with the pipe character."""
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
