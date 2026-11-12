"""Pure containment rules: an assignment must never exceed its parent MissionGrant.

No keys, clocks or I/O here, so the Authority Service and any later verifier (e.g. the Secure Tool
Gateway) apply exactly the same rules.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from gamis.schemas.assignment import AgentAssignment
from gamis.schemas.common import PermissionClass
from gamis.schemas.mission import MissionGrant


class ViolationCode(StrEnum):
    MALFORMED_PROPOSAL = "MALFORMED_PROPOSAL"
    PROPOSAL_ALREADY_SIGNED = "PROPOSAL_ALREADY_SIGNED"
    GRANT_SIGNATURE_INVALID = "GRANT_SIGNATURE_INVALID"
    GRANT_NOT_YET_VALID = "GRANT_NOT_YET_VALID"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    GRANT_NOT_ACTIVE = "GRANT_NOT_ACTIVE"
    GRANT_REVOKED = "GRANT_REVOKED"
    GRANT_MISMATCH = "GRANT_MISMATCH"
    POLICY_VERSION_MISMATCH = "POLICY_VERSION_MISMATCH"
    UNKNOWN_WORKER = "UNKNOWN_WORKER"
    WORKER_DISABLED = "WORKER_DISABLED"
    WORKER_ROLE_MISMATCH = "WORKER_ROLE_MISMATCH"
    ROLE_NOT_PERMITTED = "ROLE_NOT_PERMITTED"
    SCOPE_NOT_AUTHORIZED = "SCOPE_NOT_AUTHORIZED"
    TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"
    PERMISSION_CLASS_NOT_GRANTED = "PERMISSION_CLASS_NOT_GRANTED"
    PERMISSION_CLASS_ESCALATION = "PERMISSION_CLASS_ESCALATION"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    WORKER_COUNT_EXCEEDED = "WORKER_COUNT_EXCEEDED"
    DUPLICATE_ASSIGNMENT = "DUPLICATE_ASSIGNMENT"
    ASSIGNMENT_EXPIRED = "ASSIGNMENT_EXPIRED"
    ASSIGNMENT_NOT_YET_VALID = "ASSIGNMENT_NOT_YET_VALID"
    ASSIGNMENT_OUTLIVES_GRANT = "ASSIGNMENT_OUTLIVES_GRANT"
    EVIDENCE_REQUIREMENT_WEAKENED = "EVIDENCE_REQUIREMENT_WEAKENED"
    REGISTRY_INTEGRITY = "REGISTRY_INTEGRITY"
    TOOL_NOT_REGISTERED = "TOOL_NOT_REGISTERED"
    TOOL_DISABLED = "TOOL_DISABLED"
    OPERATION_NOT_SUPPORTED = "OPERATION_NOT_SUPPORTED"
    ASSIGNMENT_SIGNATURE_INVALID = "ASSIGNMENT_SIGNATURE_INVALID"


@dataclass(frozen=True)
class Violation:
    code: ViolationCode
    message: str


def check_assignment_within_grant(assignment: AgentAssignment, grant: MissionGrant) -> list[Violation]:
    """Return every way ``assignment`` exceeds ``grant``. Empty list = contained."""
    V, C = Violation, ViolationCode
    out: list[Violation] = []
    if assignment.mission_id != grant.mission_id or assignment.grant_id != grant.grant_id:
        out.append(V(C.GRANT_MISMATCH, "assignment does not reference this mission grant"))
    if assignment.policy_version != grant.policy_version:
        out.append(V(C.POLICY_VERSION_MISMATCH, "assignment policy version differs from the grant"))
    if assignment.worker_role not in grant.permitted_roles:
        out.append(V(C.ROLE_NOT_PERMITTED, f"role {assignment.worker_role} is not permitted by the grant"))
    if any(scope not in grant.authorized_scope for scope in assignment.authorized_scope):
        out.append(V(C.SCOPE_NOT_AUTHORIZED, "assignment scope exceeds the mission grant"))

    # READ and ACTION are validated independently of each other.
    if assignment.permission_class not in grant.permitted_permission_classes:
        out.append(V(C.PERMISSION_CLASS_NOT_GRANTED,
                     f"grant does not permit {assignment.permission_class.value} assignments"))
    for tool_id in assignment.permitted_tools:
        if tool_id not in grant.permitted_tools:
            out.append(V(C.TOOL_NOT_PERMITTED, f"tool {tool_id} is not permitted by the grant"))
    for perm in assignment.permitted_operations:
        granted = grant.permission_for(perm.tool_id, perm.operation_id)
        if granted is None:
            out.append(V(C.OPERATION_NOT_PERMITTED, f"operation {perm.qualified_name} is not permitted by the grant"))
        elif granted.permission_class is not perm.permission_class:
            out.append(V(C.PERMISSION_CLASS_ESCALATION,
                         f"operation {perm.qualified_name} is granted as {granted.permission_class.value}, "
                         f"requested as {perm.permission_class.value}"))
        if perm.permission_class not in grant.permitted_permission_classes:
            out.append(V(C.PERMISSION_CLASS_NOT_GRANTED,
                         f"{perm.permission_class.value} is not granted ({perm.qualified_name})"))
        if perm.permission_class is PermissionClass.ACTION and assignment.permission_class is PermissionClass.READ:
            out.append(V(C.PERMISSION_CLASS_ESCALATION,
                         f"READ assignment requests ACTION operation {perm.qualified_name}"))

    for dimension in assignment.resource_limits.exceeded_dimensions(grant.global_resource_limits):
        out.append(V(C.RESOURCE_LIMIT_EXCEEDED, f"{dimension} exceeds the grant ceiling"))
    for limit in assignment.tool_call_limits:
        if limit.max_calls > grant.global_resource_limits.max_tool_calls:
            out.append(V(C.RESOURCE_LIMIT_EXCEEDED, f"tool call limit for {limit.tool_id} exceeds the grant ceiling"))

    if assignment.issued_at < grant.issued_at:
        out.append(V(C.ASSIGNMENT_NOT_YET_VALID, "assignment is issued before its grant"))
    if assignment.expires_at > grant.expires_at:
        out.append(V(C.ASSIGNMENT_OUTLIVES_GRANT, "assignment expires after its grant"))

    held = {r.requirement_id: r for r in assignment.required_evidence}
    for required in grant.evidence_requirements:
        if not required.applies_to(assignment.worker_role):
            continue
        mine = held.get(required.requirement_id)
        if (mine is None or mine.minimum_items < required.minimum_items
                or (required.require_tool_receipts and not mine.require_tool_receipts)
                or not set(mine.accepted_source_types) <= set(required.accepted_source_types)):
            out.append(V(C.EVIDENCE_REQUIREMENT_WEAKENED,
                         f"evidence requirement {required.requirement_id} is missing or weakened"))
    return out
