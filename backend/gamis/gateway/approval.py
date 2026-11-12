"""Approval contract for protected ACTION requests.

The provider is a trusted identity-verified human approval channel. Workers cannot supply these records.
"""
from __future__ import annotations

from typing import Protocol

from pydantic import model_validator

from gamis.schemas.assignment import AgentAssignment
from gamis.schemas.common import Identifier, Sha256Hex, StrictModel, UtcDatetime
from gamis.schemas.mission import MissionGrant
from gamis.schemas.tools import ToolRequest


class HumanApproval(StrictModel):
    approval_id: Identifier
    approver_id: Identifier
    approver_role: Identifier
    request_digest: Sha256Hex
    approved_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def check_window(self) -> "HumanApproval":
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expiry must follow its approval time")
        return self


class HumanApprovalProvider(Protocol):
    """Return records from an independently authenticated human approval system."""

    def approvals_for(self, request: ToolRequest, assignment: AgentAssignment, grant: MissionGrant,
                      requirements: tuple) -> tuple[HumanApproval, ...]: ...
