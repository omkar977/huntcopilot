"""Resolve the hunt library: M2's hc_hunt when importable, local stand-ins otherwise (spec Section 12.4)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from . import hunt_local
from .errors import ApiError


def mock_ml_enabled() -> bool:
    """HC_MOCK_ML=1 makes the api use canned ScoredWindow and confidence responses."""
    return os.getenv("HC_MOCK_ML") == "1"


def mock_hunt_enabled() -> bool:
    """HC_MOCK_HUNT=1 makes the api use a canned run_plan result built from the fixtures."""
    return os.getenv("HC_MOCK_HUNT") == "1"


@dataclass
class HuntLib:
    validate_plan: Callable
    run_plan: Callable
    build_chain: Callable
    chain_to_dot: Callable
    source: str  # "hc_hunt" or "local"
    run_source: str  # "hc_hunt", "mock" or "missing"


def _missing_run_plan(*_args, **_kwargs):
    raise ApiError("internal", "hc_hunt library is not installed; set HC_MOCK_HUNT=1 for the canned hunt", status=503)


def load_hunt_lib(mock_hunt: bool) -> HuntLib:
    """Prefer hc_hunt for every function. run_plan is replaced by the canned mock when mock_hunt is true."""
    try:
        import hc_hunt  # type: ignore
        real = (hc_hunt.validate_plan, hc_hunt.run_plan, hc_hunt.build_chain, hc_hunt.chain_to_dot)
        source = "hc_hunt"
    except (ImportError, AttributeError):
        real = (hunt_local.validate_plan, None, hunt_local.build_chain, hunt_local.chain_to_dot)
        source = "local"
    validate, run, chain, dot = real
    if mock_hunt:
        from .mocks import mock_run_plan
        return HuntLib(validate, mock_run_plan, chain, dot, source, "mock")
    if run is None:
        return HuntLib(validate, _missing_run_plan, chain, dot, source, "missing")
    return HuntLib(validate, run, chain, dot, source, "hc_hunt")
