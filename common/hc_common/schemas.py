"""Data contracts (spec Section 5). Owner: Lead. Never change without a Lead-approved CHANGE_REQUEST.

All models forbid unknown fields so that contract drift is caught early.
Timestamps must be timezone-aware (UTC). Wire format is JSON; datetimes serialise as ISO 8601 with Z.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "1.0"


class HCModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- 5.1 Event
class EventType(str, Enum):
    process_create = "process_create"
    network_conn = "network_conn"
    auth = "auth"
    file_create = "file_create"
    dns_query = "dns_query"


class Process(HCModel):
    name: str  # lower-case image name, e.g. powershell.exe
    pid: int
    cmdline: str = ""
    parent_name: str = ""
    parent_pid: int = 0
    user: str = ""
    integrity: Literal["low", "medium", "high", "system"] = "medium"

    @field_validator("name", "parent_name")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class Net(HCModel):
    src_ip: str
    src_port: int = 0
    dst_ip: str
    dst_port: int
    proto: Literal["tcp", "udp"] = "tcp"
    bytes_out: int = 0
    bytes_in: int = 0
    dst_host: str = ""  # asset name if dst_ip belongs to an asset, else empty
    direction: Literal["outbound", "inbound", "internal"] = "outbound"


class Auth(HCModel):
    logon_type: int  # 2 interactive, 3 network, 10 remote interactive
    result: Literal["success", "failure"]
    target_user: str
    src_host: str = ""
    src_ip: str = ""


class FileInfo(HCModel):
    path: str
    action: Literal["create", "modify", "delete"] = "create"
    sha256: str = ""


class Dns(HCModel):
    query: str
    qtype: str = "A"
    answer: str = ""
    rcode: str = "NOERROR"


class GroundTruth(HCModel):
    """Evaluation only. NEVER use as a feature, a query filter or LLM input."""

    is_malicious: bool = False
    scenario: str = ""  # phishing, lateral_movement, credential_dumping, c2, apt_chain or empty
    stage: str = ""  # initial_access, execution, credential_access, lateral_movement, c2


_PAYLOAD_FIELD = {
    EventType.process_create: "process",
    EventType.network_conn: "net",
    EventType.auth: "auth",
    EventType.file_create: "file",
    EventType.dns_query: "dns",
}


class Event(HCModel):
    schema_version: str = SCHEMA_VERSION
    event_id: str
    ts: datetime
    host: str
    host_ip: str
    user: str = ""
    event_type: EventType
    process: Optional[Process] = None
    net: Optional[Net] = None
    auth: Optional[Auth] = None
    file: Optional[FileInfo] = None
    dns: Optional[Dns] = None
    tags: List[str] = Field(default_factory=list)
    gt: Optional[GroundTruth] = None
    ingested_at: Optional[datetime] = None  # set by the ingestor only

    @field_validator("ts", "ingested_at")
    @classmethod
    def _aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware (UTC)")
        return v

    @model_validator(mode="after")
    def _payload_matches_type(self) -> "Event":
        want = _PAYLOAD_FIELD[self.event_type]
        present = [n for n in ("process", "net", "auth", "file", "dns") if getattr(self, n) is not None]
        if present != [want]:
            raise ValueError(f"event_type {self.event_type.value} needs exactly the field '{want}', got {present}")
        return self


# ---------------------------------------------------------------- 5.5 Alert
class Alert(HCModel):
    alert_id: str  # sha1 hex of rule_id | group key | ts_first
    rule_id: str  # HC-001 ... HC-010
    rule_name: str
    severity: int = Field(ge=1, le=5)
    technique_ids: List[str]
    tactics: List[str]
    host: str
    user: str = ""
    ts_first: datetime
    ts_last: datetime
    event_ids: List[str]
    summary: str
    status: Literal["new", "triaged", "closed"] = "new"
    created_at: datetime


# ---------------------------------------------------------------- 5.7 Hunt plan
class Cond(HCModel):
    field: str
    op: Literal["eq", "neq", "in", "contains", "startswith", "gt", "gte", "lt", "lte"]
    value: Union[str, int, float, List[Union[str, int]]]  # may be a variable such as ${s1.hosts}


class Query(HCModel):
    filters: List[Cond]
    group_by: Optional[str] = None
    size: int = Field(default=200, ge=1, le=500)


class HuntStep(HCModel):
    step_id: str  # s1, s2, ...
    description: str
    query: Query
    depends_on: List[str] = Field(default_factory=list)
    expected_evidence: str = ""
    stage: str = ""  # one of STAGES, used for coverage


class TimeRange(HCModel):
    start: datetime
    end: datetime


class ValidationResult(HCModel):
    ok: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class HuntPlan(HCModel):
    plan_id: str
    intent_text: str
    hypothesis: str
    source: Literal["llm", "fallback"]
    template: str = ""
    time_range: TimeRange
    steps: List[HuntStep]
    expected_stages: List[str]
    created_at: datetime
    validation: ValidationResult


# ---------------------------------------------------------------- 5.8 Findings
class ScoreBreakdown(HCModel):
    anomaly_if: float = Field(ge=0, le=1)
    anomaly_seq: float = Field(ge=0, le=1)
    anomaly: float = Field(ge=0, le=1)  # A
    coverage: float = Field(ge=0, le=1)  # V
    criticality: float = Field(ge=0, le=1)  # K
    uncertainty: float = Field(ge=0, le=1)  # U
    confidence: float = Field(ge=0, le=100)


class FeatureContribution(HCModel):
    name: str
    value: float
    z: float


class Node(HCModel):
    id: str
    type: Literal["host", "process", "ip", "user", "domain"]
    label: str
    risk: float = Field(default=0.0, ge=0, le=1)


class Edge(HCModel):
    src: str
    dst: str
    kind: Literal["spawned", "connected", "authenticated", "dropped", "queried"]
    ts: datetime
    event_id: str


class AttackChain(HCModel):
    nodes: List[Node]
    edges: List[Edge]


class ProposedAction(HCModel):
    action: Literal["isolate_host", "kill_process", "block_ip", "disable_account"]
    target: str
    rationale: str


class Finding(HCModel):
    finding_id: str
    run_id: str
    hosts: List[str]
    users: List[str]
    ts_first: datetime
    ts_last: datetime
    event_ids: List[str]
    alert_ids: List[str]
    technique_ids: List[str]
    stages_found: List[str]
    scores: ScoreBreakdown
    cluster_id: Optional[int] = None
    top_features: List[FeatureContribution]
    rationale: str
    chain: AttackChain
    recommended_actions: List[ProposedAction]
    created_at: datetime


class StepResult(HCModel):
    step_id: str
    event_count: int
    hosts: List[str]
    users: List[str]
    dst_ips: List[str]
    duration_ms: int


class HuntRun(HCModel):
    run_id: str
    plan_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: Literal["running", "completed", "failed"]
    error: str = ""
    step_results: List[StepResult]
    findings: List[Finding]


class ScoredWindow(HCModel):  # returned by the ml service
    window_id: str  # sha1 hex of host + window start
    host: str
    ts_first: datetime
    ts_last: datetime
    event_ids: List[str]
    anomaly_if: float = Field(ge=0, le=1)
    anomaly_seq: float = Field(ge=0, le=1)
    anomaly: float = Field(ge=0, le=1)
    uncertainty: float = Field(ge=0, le=1)
    top_features: List[FeatureContribution]
    cluster_id: Optional[int] = None


# ---------------------------------------------------------------- 5.9 Proposal
class Proposal(HCModel):
    proposal_id: str
    finding_id: str
    action: Literal["isolate_host", "kill_process", "block_ip", "disable_account"]
    target: str
    justification: str
    disruptive: bool = True
    status: Literal["pending", "approved", "rejected", "executed", "failed"] = "pending"
    requested_by: str = "system"
    requested_at: datetime
    decided_by: str = ""
    decided_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    result: str = ""
