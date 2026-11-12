"""Bridge between P0 (tool doubles, evaluation harness) and the P1 schemas / signing primitives.

``call_double_with_receipt`` is a TEST AID: it runs a P0 tool double and records the outcome as a signed
ToolReceipt. It authorizes nothing and is not the Secure Tool Gateway (P4).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from gamis.evaluation.harness import SystemOutput
from gamis.schemas.common import ExecutionStatus
from gamis.schemas.evidence import EvidenceBundle
from gamis.schemas.policy import PolicyVersion
from gamis.schemas.tools import ToolDefinition, ToolReceipt, ToolRequest
from gamis.security.keys import Signer
from gamis.tools.mock_tools import ActionDisabledError, ToolExecutionError, ToolTimeoutError
from gamis.tools.receipts import issue_receipt, request_problems

_ERRORS = {ToolTimeoutError: (ExecutionStatus.TIMEOUT, "tool-timeout"),
           ToolExecutionError: (ExecutionStatus.FAILED, "tool-error"),
           ActionDisabledError: (ExecutionStatus.REJECTED, "action-disabled")}


def call_double_with_receipt(tool: Callable[[dict[str, Any]], Any], request: ToolRequest,
                             definition: ToolDefinition, *, receipt_id: str, signer: Signer,
                             policy_version: PolicyVersion, clock: Callable[[], datetime]
                             ) -> tuple[Any, ToolReceipt]:
    """Run a P0 double for ``request``; return (result or None, signed receipt)."""
    started = clock()
    common = dict(receipt_id=receipt_id, started_at=started, policy_version=policy_version, signer=signer)
    if request_problems(request, definition):
        return None, issue_receipt(request, definition, status=ExecutionStatus.REJECTED,
                                   error_code="invalid-request", completed_at=clock(), **common)
    try:
        result = tool(_thaw(request.arguments))
    except tuple(_ERRORS) as exc:
        status, code = _ERRORS[type(exc)]
        return None, issue_receipt(request, definition, status=status, error_code=code, completed_at=clock(),
                                   **common)
    if not isinstance(result, dict):  # P0 failure injection returns a non-object for 'malformed'
        return None, issue_receipt(request, definition, status=ExecutionStatus.MALFORMED_RESULT,
                                   error_code="malformed-result", result=result, completed_at=clock(), **common)
    return result, issue_receipt(request, definition, status=ExecutionStatus.SUCCEEDED, result=result,
                                 completed_at=clock(), **common)


def _thaw(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value


def bundle_to_system_output(bundle: EvidenceBundle) -> SystemOutput:
    """Convert a P1 EvidenceBundle into the P0 harness's SystemOutput so the harness can score it."""
    records = {e.evidence_id: e.source_record_id or e.evidence_id for e in bundle.evidence_items}
    claims = [{"statement": c.statement, "evidence_ids": [records[i] for i in c.supporting_evidence_ids],
               "disputed": c.disputed} for c in bundle.claims]
    status = bundle.completion_status.value
    return SystemOutput(status="stopped" if status == "failed" else status, claims=claims)
