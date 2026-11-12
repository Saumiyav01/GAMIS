"""MissionGrant (immutable, signed) and MissionStatus (mutable runtime state, never signed)."""
from __future__ import annotations

from datetime import timedelta
from typing import Annotated, ClassVar, Self

from pydantic import ConfigDict, Field, model_validator

from gamis.schemas.common import (Identifier, LongText, MissionState, PermissionClass, Principal, PrincipalType,
                                  ShortText, StrictModel, UtcDatetime, require_unique)
from gamis.schemas.policy import (ApprovalRequirement, EvidenceRequirement, PolicyVersion, ResourceLimits,
                                  ToolPermission)
from gamis.schemas.signature import SignableModel, SignedObjectType

MAX_GRANT_LIFETIME = timedelta(days=366)


class ScopeEntry(StrictModel):
    """Domain-neutral scope selector, e.g. resource_type='dataset', selector='synthetic-logs'."""

    resource_type: Identifier
    selector: ShortText


class MissionGrant(SignableModel):
    """The maximum authority available to a mission. Nothing is permitted unless listed here."""

    OBJECT_TYPE: ClassVar[SignedObjectType] = SignedObjectType.MISSION_GRANT

    mission_id: Identifier
    grant_id: Identifier
    mission_objective: LongText
    authorized_scope: Annotated[tuple[ScopeEntry, ...], Field(min_length=1, max_length=256)]
    permitted_roles: Annotated[tuple[Identifier, ...], Field(max_length=64)]
    permitted_tools: Annotated[tuple[Identifier, ...], Field(max_length=256)]
    permitted_operations: Annotated[tuple[ToolPermission, ...], Field(max_length=1024)]
    permitted_permission_classes: Annotated[tuple[PermissionClass, ...], Field(max_length=2)]
    maximum_worker_count: Annotated[int, Field(strict=True, ge=0, le=1000)]
    global_resource_limits: ResourceLimits
    approval_requirements: Annotated[tuple[ApprovalRequirement, ...], Field(max_length=64)]
    evidence_requirements: Annotated[tuple[EvidenceRequirement, ...], Field(max_length=64)]
    policy_version: PolicyVersion
    issued_at: UtcDatetime
    expires_at: UtcDatetime
    issuer_identity: Principal
    revocation_reference: Identifier

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.permitted_roles, "permitted role")
        require_unique(self.permitted_tools, "permitted tool")
        require_unique(self.permitted_operations, "permitted operation", key=lambda p: p.key)
        require_unique(self.permitted_permission_classes, "permission class")
        require_unique(self.approval_requirements, "approval requirement", key=lambda r: r.requirement_id)
        require_unique(self.evidence_requirements, "evidence requirement", key=lambda r: r.requirement_id)
        tools_with_ops = set()
        for perm in self.permitted_operations:
            if perm.tool_id not in self.permitted_tools:
                raise ValueError(f"operation {perm.qualified_name} references a tool that is not permitted")
            if perm.permission_class not in self.permitted_permission_classes:
                raise ValueError(f"operation {perm.qualified_name} is {perm.permission_class.value} "
                                 "but that permission class is not granted")
            tools_with_ops.add(perm.tool_id)
        missing = [t for t in self.permitted_tools if t not in tools_with_ops]
        if missing:
            raise ValueError(f"permitted tools without any permitted operation: {missing}")
        if PermissionClass.ACTION in self.permitted_permission_classes and not any(
                r.applies_to is PermissionClass.ACTION for r in self.approval_requirements):
            raise ValueError("granting ACTION requires at least one ACTION approval requirement")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.expires_at - self.issued_at > MAX_GRANT_LIFETIME:
            raise ValueError("grant lifetime exceeds the maximum of 366 days")
        if self.issuer_identity.principal_type is not PrincipalType.MISSION_ISSUER:
            raise ValueError("issuer_identity must be a MISSION_ISSUER principal")
        return self

    def permission_for(self, tool_id: str, operation_id: str) -> ToolPermission | None:
        return next((p for p in self.permitted_operations if p.key == (tool_id, operation_id)), None)


class MissionStatus(StrictModel):
    """Mutable runtime state of a mission/grant. Deliberately separate from the signed grant."""

    model_config = ConfigDict(extra="forbid", frozen=False, validate_assignment=True, validate_default=True)

    mission_id: Identifier
    grant_id: Identifier
    revocation_reference: Identifier
    state: MissionState
    reason: ShortText | None = None
    updated_at: UtcDatetime

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.state in (MissionState.REVOKED, MissionState.SUSPENDED) and self.reason is None:
            raise ValueError(f"{self.state.value} requires a reason")
        return self

    @property
    def permits_new_assignments(self) -> bool:
        return self.state is MissionState.ACTIVE
