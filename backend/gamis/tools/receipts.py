"""Receipt primitives (P1): check a ToolRequest against a ToolDefinition and build a signed ToolReceipt.

These are building blocks for the P4 Secure Tool Gateway. They perform NO authorization: nothing here
checks assignments, budgets or approvals.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from gamis.schemas.common import ExecutionStatus
from gamis.schemas.policy import PolicyVersion
from gamis.schemas.tools import ToolDefinition, ToolReceipt, ToolRequest
from gamis.security.digest import canonical_digest
from gamis.security.keys import Signer
from gamis.security.signing import sign_object


def request_problems(request: ToolRequest, definition: ToolDefinition) -> tuple[str, ...]:
    """Structural problems of a request against the registered definition (empty = well-formed)."""
    if request.tool_id != definition.tool_id:
        return (f"request is for {request.tool_id}, definition is {definition.tool_id}",)
    schema = definition.schema_for(request.operation_id)
    if definition.operation(request.operation_id) is None or schema is None:
        return (f"{request.operation_id}: unsupported operation",)
    return schema.validate_arguments(request.arguments)


def issue_receipt(request: ToolRequest, definition: ToolDefinition, *, receipt_id: str, status: ExecutionStatus,
                  result: Any = None, error_code: str | None = None, started_at: datetime, completed_at: datetime,
                  policy_version: PolicyVersion, signer: Signer) -> ToolReceipt:
    """Build and sign a receipt. ``result`` is bound by digest only; the receipt never stores it."""
    operation = definition.operation(request.operation_id)
    if operation is None:
        raise ValueError(f"{request.operation_id} is not an operation of {definition.tool_id}")
    receipt = ToolReceipt(
        receipt_id=receipt_id, request_id=request.request_id, request_digest=request.request_digest(),
        mission_id=request.mission_id, assignment_id=request.assignment_id, worker_id=request.worker_id,
        tool_id=definition.tool_id, tool_version=definition.version, operation_id=operation.operation_id,
        permission_class=operation.permission_class, arguments_digest=request.arguments_digest(),
        result_digest=None if result is None else canonical_digest(result), execution_status=status,
        error_code=error_code, started_at=started_at, completed_at=completed_at,
        correlation_id=request.correlation_id, gateway_identity=signer.principal, policy_version=policy_version)
    return receipt.with_signature(sign_object(receipt, signer, now=completed_at))
