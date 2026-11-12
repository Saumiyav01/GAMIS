"""WorkerIdentity and AgentAssignment."""
from __future__ import annotations

from typing import Annotated, ClassVar, Self

from pydantic import Field, model_validator

from gamis.schemas.common import (Flag, Identifier, LongText, PermissionClass, ShortText, StrictModel, UtcDatetime,
                                  require_unique)
from gamis.schemas.mission import ScopeEntry
from gamis.schemas.policy import (EvidenceRequirement, PolicyVersion, ResourceLimits, StoppingCondition,
                                  ToolCallLimit, ToolPermission)
from gamis.schemas.signature import SignableModel, SignedObjectType


class WorkerIdentity(StrictModel):
    worker_id: Identifier
    worker_role: Identifier
    display_name: ShortText
    enabled: Flag
    registered_at: UtcDatetime


class AgentAssignment(SignableModel):
    """A bounded task for one worker. Unsigned = proposal; only the Authority Service signs it.

    ``permission_class`` is a ceiling and has no default: a READ assignment can only hold READ
    operations; an ACTION assignment must hold at least one ACTION operation (and may hold READ ones),
    each individually granted.
    """

    OBJECT_TYPE: ClassVar[SignedObjectType] = SignedObjectType.AGENT_ASSIGNMENT

    assignment_id: Identifier
    mission_id: Identifier
    grant_id: Identifier
    worker_id: Identifier
    worker_role: Identifier
    task_objective: ShortText
    task_description: LongText
    success_criteria: Annotated[tuple[ShortText, ...], Field(min_length=1, max_length=32)]
    authorized_scope: Annotated[tuple[ScopeEntry, ...], Field(max_length=256)] = ()
    permitted_tools: Annotated[tuple[Identifier, ...], Field(max_length=256)]
    permitted_operations: Annotated[tuple[ToolPermission, ...], Field(max_length=1024)]
    forbidden_actions: Annotated[tuple[ShortText, ...], Field(max_length=256)]
    permission_class: PermissionClass
    resource_limits: ResourceLimits
    tool_call_limits: Annotated[tuple[ToolCallLimit, ...], Field(max_length=256)]
    required_evidence: Annotated[tuple[EvidenceRequirement, ...], Field(max_length=64)]
    stopping_conditions: Annotated[tuple[StoppingCondition, ...], Field(min_length=1, max_length=32)]
    issued_at: UtcDatetime
    expires_at: UtcDatetime
    policy_version: PolicyVersion

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.permitted_tools, "permitted tool")
        require_unique(self.permitted_operations, "permitted operation", key=lambda p: p.key)
        require_unique(self.tool_call_limits, "tool call limit", key=lambda l: l.tool_id)
        require_unique(self.required_evidence, "evidence requirement", key=lambda r: r.requirement_id)
        require_unique(self.stopping_conditions, "stopping condition", key=lambda c: c.condition_id)
        require_unique(self.forbidden_actions, "forbidden action")
        tools_with_ops = set()
        for perm in self.permitted_operations:
            if perm.tool_id not in self.permitted_tools:
                raise ValueError(f"operation {perm.qualified_name} references a tool that is not permitted")
            if self.permission_class is PermissionClass.READ and perm.permission_class is not PermissionClass.READ:
                raise ValueError(f"READ assignment cannot hold {perm.permission_class.value} "
                                 f"operation {perm.qualified_name}")
            if perm.qualified_name in self.forbidden_actions or perm.tool_id in self.forbidden_actions:
                raise ValueError(f"operation {perm.qualified_name} is both permitted and forbidden")
            tools_with_ops.add(perm.tool_id)
        if self.permission_class is PermissionClass.ACTION and not any(
                p.permission_class is PermissionClass.ACTION for p in self.permitted_operations):
            raise ValueError("an ACTION assignment must hold at least one ACTION operation; use READ otherwise")
        missing = [t for t in self.permitted_tools if t not in tools_with_ops]
        if missing:
            raise ValueError(f"permitted tools without any permitted operation: {missing}")
        limits = {l.tool_id: l for l in self.tool_call_limits}
        if set(limits) != set(self.permitted_tools):
            raise ValueError("tool_call_limits must list exactly the permitted tools")
        for limit in self.tool_call_limits:
            if limit.max_calls > self.resource_limits.max_tool_calls:
                raise ValueError(f"tool call limit for {limit.tool_id} exceeds resource_limits.max_tool_calls")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    def permission_for(self, tool_id: str, operation_id: str) -> ToolPermission | None:
        return next((p for p in self.permitted_operations if p.key == (tool_id, operation_id)), None)
