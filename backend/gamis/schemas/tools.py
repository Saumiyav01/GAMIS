"""Tool definitions, registry snapshot, tool requests and execution receipts."""
from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, ClassVar, Mapping, Self

from pydantic import Field, model_validator

from gamis.schemas.common import (Count, ExecutionStatus, Flag, Identifier, JsonObject, PermissionClass, Principal,
                                  PrincipalType, RiskLevel, SemVer, Sha256Hex, ShortText, LongText, StrictModel,
                                  UtcDatetime, require_unique, semver_tuple)
from gamis.schemas.policy import ApprovalRequirement, PolicyVersion
from gamis.schemas.signature import SignableModel, SignedObjectType
from gamis.security.digest import canonical_digest


class ArgumentType(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"


class ArgumentSpec(StrictModel):
    name: Identifier
    type: ArgumentType
    required: Flag
    description: ShortText
    enum: Annotated[tuple[ShortText, ...], Field(min_length=1, max_length=256)] | None = None
    minimum: Annotated[int, Field(strict=True, ge=-(2**53) + 1, le=2**53 - 1)] | None = None
    maximum: Annotated[int, Field(strict=True, ge=-(2**53) + 1, le=2**53 - 1)] | None = None
    max_length: Annotated[int, Field(strict=True, ge=1, le=65_536)] | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        numeric = self.type in (ArgumentType.INTEGER, ArgumentType.NUMBER)
        if (self.enum is not None or self.max_length is not None) and self.type is not ArgumentType.STRING:
            raise ValueError("enum and max_length apply only to string arguments")
        if (self.minimum is not None or self.maximum is not None) and not numeric:
            raise ValueError("minimum and maximum apply only to numeric arguments")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum must not exceed maximum")
        return self

    def problems(self, value: Any) -> list[str]:
        if self.type is ArgumentType.STRING:
            if not isinstance(value, str):
                return [f"{self.name}: expected string"]
            out = []
            if self.max_length is not None and len(value) > self.max_length:
                out.append(f"{self.name}: longer than {self.max_length}")
            if self.enum is not None and value not in self.enum:
                out.append(f"{self.name}: not an allowed value")
            return out
        if self.type is ArgumentType.BOOLEAN:
            return [] if isinstance(value, bool) else [f"{self.name}: expected boolean"]
        ok = isinstance(value, int) if self.type is ArgumentType.INTEGER else isinstance(value, (int, float))
        if isinstance(value, bool) or not ok:
            return [f"{self.name}: expected {self.type.value}"]
        out = []
        if self.minimum is not None and value < self.minimum:
            out.append(f"{self.name}: below minimum {self.minimum}")
        if self.maximum is not None and value > self.maximum:
            out.append(f"{self.name}: above maximum {self.maximum}")
        return out


class OperationArgumentSchema(StrictModel):
    """Closed argument schema for one operation: unknown arguments are always rejected."""

    operation_id: Identifier
    arguments: Annotated[tuple[ArgumentSpec, ...], Field(max_length=64)]

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.arguments, "argument", key=lambda a: a.name)
        return self

    def validate_arguments(self, arguments: Mapping[str, Any]) -> tuple[str, ...]:
        specs = {a.name: a for a in self.arguments}
        problems = [f"{name}: unknown argument" for name in arguments if name not in specs]
        for spec in self.arguments:
            if spec.name not in arguments:
                if spec.required:
                    problems.append(f"{spec.name}: missing required argument")
            else:
                problems.extend(spec.problems(arguments[spec.name]))
        return tuple(problems)


class ToolOperation(StrictModel):
    operation_id: Identifier
    description: ShortText
    permission_class: PermissionClass


class ToolDefinition(StrictModel):
    tool_id: Identifier
    name: ShortText
    description: LongText
    version: SemVer
    permission_class: PermissionClass  # ceiling for the tool's operations
    supported_operations: Annotated[tuple[ToolOperation, ...], Field(min_length=1, max_length=64)]
    argument_schemas: Annotated[tuple[OperationArgumentSchema, ...], Field(min_length=1, max_length=64)]
    risk_classification: RiskLevel
    approval_requirements: Annotated[tuple[ApprovalRequirement, ...], Field(max_length=16)]
    enabled_status: Flag
    policy_version: PolicyVersion

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.supported_operations, "operation", key=lambda o: o.operation_id)
        require_unique(self.argument_schemas, "argument schema", key=lambda s: s.operation_id)
        require_unique(self.approval_requirements, "approval requirement", key=lambda r: r.requirement_id)
        op_ids = {o.operation_id for o in self.supported_operations}
        if {s.operation_id for s in self.argument_schemas} != op_ids:
            raise ValueError("argument_schemas must define exactly one schema per supported operation")
        classes = {o.permission_class for o in self.supported_operations}
        if self.permission_class is PermissionClass.READ and PermissionClass.ACTION in classes:
            raise ValueError("a READ tool cannot expose ACTION operations")
        if self.permission_class is PermissionClass.ACTION:
            if PermissionClass.ACTION not in classes:
                raise ValueError("an ACTION tool must expose at least one ACTION operation")
            if not any(r.applies_to is PermissionClass.ACTION for r in self.approval_requirements):
                raise ValueError("an ACTION tool requires at least one ACTION approval requirement")
        for req in self.approval_requirements:
            if req.tool_id not in (None, self.tool_id):
                raise ValueError("approval requirement references a different tool")
            if req.operation_id is not None and req.operation_id not in op_ids:
                raise ValueError("approval requirement references an unsupported operation")
        return self

    @property
    def version_tuple(self) -> tuple[int, int, int]:
        return semver_tuple(self.version)

    def operation(self, operation_id: str) -> ToolOperation | None:
        return next((o for o in self.supported_operations if o.operation_id == operation_id), None)

    def schema_for(self, operation_id: str) -> OperationArgumentSchema | None:
        return next((s for s in self.argument_schemas if s.operation_id == operation_id), None)


class RegistrySnapshot(SignableModel):
    """Signed, complete state of a tool registry at one revision."""

    OBJECT_TYPE: ClassVar[SignedObjectType] = SignedObjectType.TOOL_REGISTRY

    registry_id: Identifier
    registry_version: Annotated[int, Field(strict=True, ge=1, le=1_000_000_000)]
    policy_version: PolicyVersion
    definitions: Annotated[tuple[ToolDefinition, ...], Field(max_length=4096)]
    sealed_at: UtcDatetime

    @model_validator(mode="after")
    def _check(self) -> Self:
        keys = [(d.tool_id, d.version_tuple) for d in self.definitions]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate tool definition in snapshot")
        if keys != sorted(keys):
            raise ValueError("snapshot definitions must be sorted by (tool_id, version)")
        return self


class ToolRequest(StrictModel):
    request_id: Identifier
    mission_id: Identifier
    assignment_id: Identifier
    worker_id: Identifier
    tool_id: Identifier
    operation_id: Identifier
    arguments: JsonObject
    requested_at: UtcDatetime
    correlation_id: Identifier
    sequence_number: Count
    idempotency_key: Identifier | None = None

    def arguments_digest(self) -> str:
        return canonical_digest(self.arguments)

    def request_digest(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


class ToolReceipt(SignableModel):
    """Gateway-signed record that an execution happened and what it returned (by digest).

    A receipt proves execution provenance and integrity, never the truth of an interpretation.
    """

    OBJECT_TYPE: ClassVar[SignedObjectType] = SignedObjectType.TOOL_RECEIPT

    receipt_id: Identifier
    request_id: Identifier
    request_digest: Sha256Hex
    mission_id: Identifier
    assignment_id: Identifier
    worker_id: Identifier
    tool_id: Identifier
    tool_version: SemVer
    operation_id: Identifier
    permission_class: PermissionClass
    arguments_digest: Sha256Hex
    result_digest: Sha256Hex | None
    execution_status: ExecutionStatus
    error_code: Identifier | None = None
    started_at: UtcDatetime
    completed_at: UtcDatetime
    correlation_id: Identifier
    gateway_identity: Principal
    policy_version: PolicyVersion

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.gateway_identity.principal_type is not PrincipalType.TOOL_GATEWAY:
            raise ValueError("gateway_identity must be a TOOL_GATEWAY principal")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not be before started_at")
        if self.execution_status is ExecutionStatus.SUCCEEDED:
            if self.result_digest is None:
                raise ValueError("a SUCCEEDED receipt requires result_digest")
            if self.error_code is not None:
                raise ValueError("a SUCCEEDED receipt must not carry error_code")
        elif self.error_code is None:
            raise ValueError(f"a {self.execution_status.value} receipt requires error_code")
        if self.execution_status in (ExecutionStatus.TIMEOUT, ExecutionStatus.REJECTED) and self.result_digest:
            raise ValueError(f"a {self.execution_status.value} receipt cannot carry result_digest")
        return self
