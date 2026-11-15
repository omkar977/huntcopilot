"""Request bodies of the API (responses reuse hc_common.schemas)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from hc_common.schemas import TimeRange


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HuntCreate(_Body):
    intent: str = Field(min_length=3, max_length=500)
    time_range: Optional[TimeRange] = None


class ProposalCreate(_Body):
    finding_id: str = Field(min_length=1, max_length=64)
    action: Literal["isolate_host", "kill_process", "block_ip", "disable_account"]
    target: str = Field(min_length=1, max_length=200)
    justification: str = Field(min_length=1, max_length=2000)


class ApproveBody(_Body):
    approver: str = Field(min_length=3, max_length=100)
    confirm: bool


class RejectBody(_Body):
    approver: str = Field(min_length=3, max_length=100)
    reason: str = Field(default="", max_length=1000)
