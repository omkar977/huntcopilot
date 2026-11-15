"""Shared fixtures for the M4 tests."""
import pytest

from hc_api.approvals import ProposalService
from hc_api.audit import AuditLog
from hc_api.store import Store


@pytest.fixture()
def store():
    s = Store("sqlite://")
    yield s
    s.close()


@pytest.fixture()
def audit(tmp_path):
    return AuditLog(str(tmp_path / "audit.jsonl"))


@pytest.fixture()
def svc(store, audit):
    return ProposalService(store, audit)
