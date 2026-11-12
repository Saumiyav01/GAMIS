"""Supporting models: policy version, limits, approvals, stopping conditions, permissions."""
from __future__ import annotations

from typing import Annotated, ClassVar, Self

from pydantic import Field, model_validator

from gamis.schemas.common import (ApprovalType, Count, Flag, Identifier, PermissionClass, Sha256Hex, ShortText,
                                  SemVer, SourceType, StoppingConditionType, StrictModel, require_unique)


class PolicyVersion(StrictModel):
    policy_id: Identifier
    version: SemVer
    policy_digest: Sha256Hex | None = None


class ResourceLimits(StrictModel):
    """Hard ceilings. Every dimension is required: there is no implicit 'unlimited'."""

    ADDITIVE: ClassVar[tuple[str, ...]] = ("max_tool_calls", "max_tokens", "max_cost_units", "max_evidence_bytes")

    max_tool_calls: Annotated[int, Field(strict=True, ge=0, le=100_000)]
    max_wall_clock_seconds: Annotated[int, Field(strict=True, ge=1, le=604_800)]
    max_tokens: Annotated[int, Field(strict=True, ge=0, le=1_000_000_000)]
    max_cost_units: Annotated[int, Field(strict=True, ge=0, le=1_000_000_000)]
    max_evidence_bytes: Annotated[int, Field(strict=True, ge=0, le=10_000_000_000)]

    def exceeded_dimensions(self, ceiling: "ResourceLimits") -> tuple[str, ...]:
        return tuple(name for name in type(self).model_fields if getattr(self, name) > getattr(ceiling, name))


class ToolPermission(StrictModel):
    """The atomic unit of authority: one operation of one tool, at one permission class."""

    tool_id: Identifier
    operation_id: Identifier
    permission_class: PermissionClass

    @property
    def key(self) -> tuple[str, str]:
        return (self.tool_id, self.operation_id)

    @property
    def qualified_name(self) -> str:
        return f"{self.tool_id}:{self.operation_id}"


class ToolCallLimit(StrictModel):
    tool_id: Identifier
    max_calls: Annotated[int, Field(strict=True, ge=0, le=100_000)]


class ApprovalRequirement(StrictModel):
    requirement_id: Identifier
    approval_type: ApprovalType
    applies_to: PermissionClass
    tool_id: Identifier | None = None
    operation_id: Identifier | None = None
    approver_roles: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=32)]
    minimum_approvals: Annotated[int, Field(strict=True, ge=1, le=10)]
    description: ShortText

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.approver_roles, "approver role")
        if self.operation_id is not None and self.tool_id is None:
            raise ValueError("operation_id requires tool_id")
        if self.approval_type is ApprovalType.DUAL_CONTROL and self.minimum_approvals < 2:
            raise ValueError("DUAL_CONTROL requires minimum_approvals >= 2")
        return self


class StoppingCondition(StrictModel):
    condition_id: Identifier
    condition_type: StoppingConditionType
    threshold: Annotated[int, Field(strict=True, ge=0, le=1_000_000_000)] | None = None
    description: ShortText

    @model_validator(mode="after")
    def _check(self) -> Self:
        needs = (StoppingConditionType.CONSECUTIVE_FAILURES, StoppingConditionType.CONFIDENCE_REACHED)
        if self.condition_type in needs and self.threshold is None:
            raise ValueError(f"{self.condition_type.value} requires a threshold")
        if self.condition_type is StoppingConditionType.CONFIDENCE_REACHED and self.threshold > 100:
            raise ValueError("CONFIDENCE_REACHED threshold is a percentage (0-100)")
        return self


class EvidenceRequirement(StrictModel):
    requirement_id: Identifier
    description: ShortText
    minimum_items: Count
    require_tool_receipts: Flag
    accepted_source_types: Annotated[tuple[SourceType, ...], Field(min_length=1)]
    applies_to_roles: tuple[Identifier, ...] = ()  # empty = every role

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.accepted_source_types, "accepted source type")
        require_unique(self.applies_to_roles, "role")
        return self

    def applies_to(self, role: str) -> bool:
        return not self.applies_to_roles or role in self.applies_to_roles
