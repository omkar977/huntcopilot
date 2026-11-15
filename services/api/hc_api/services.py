"""Wires the service objects together from Settings (with optional overrides for tests)."""
from dataclasses import dataclass
from typing import Any, Optional

from agent.llm import LLMClient
from agent.pipeline import PlanGenerator
from hc_common.logging import get_logger

from .approvals import ProposalService
from .audit import AuditLog
from .backends import HttpMlClient, OpenSearchBackend
from .export import CaseExporter
from .hunt_lib import load_hunt_lib, mock_hunt_enabled, mock_ml_enabled
from .hunts import HuntService
from .mocks import FixtureBackend, MockMl
from .store import Store

log = get_logger("api")


@dataclass
class Services:
    settings: Any
    store: Store
    audit: AuditLog
    backend: Any
    ml: Any
    lib: Any
    llm: LLMClient
    proposals: ProposalService
    hunts: HuntService
    exporter: CaseExporter
    mock_hunt: bool
    mock_ml: bool


def build_services(settings: Any, *, backend: Optional[Any] = None, ml: Optional[Any] = None,
                   lib: Optional[Any] = None, llm: Optional[LLMClient] = None) -> Services:
    """Create all services. Mocks follow HC_MOCK_ML and HC_MOCK_HUNT unless an override is given."""
    mock_hunt, mock_ml = mock_hunt_enabled(), mock_ml_enabled()
    lib = lib or load_hunt_lib(mock_hunt)
    if backend is None:
        if mock_hunt:
            backend = FixtureBackend()
        else:
            from hc_common.clients import get_opensearch
            backend = OpenSearchBackend(get_opensearch(), settings)
    if ml is None:
        ml = MockMl() if mock_ml else HttpMlClient(settings.hc_ml_url, settings.hc_api_key)
    llm = llm or LLMClient.from_settings(settings)
    store, audit = Store(settings.hc_db_url), AuditLog(settings.hc_audit_path)
    proposals = ProposalService(store, audit)
    generator = PlanGenerator(llm, lib.validate_plan)
    if mock_hunt or mock_ml or lib.source != "hc_hunt":
        log.warning("running with stand-ins", extra={"mock_hunt": mock_hunt, "mock_ml": mock_ml,
                                                     "hunt_lib": lib.source})
    return Services(settings, store, audit, backend, ml, lib, llm, proposals,
                    HuntService(store, backend, ml, lib, generator, proposals),
                    CaseExporter(store, settings.hc_audit_path, backend, lib), mock_hunt, mock_ml)
