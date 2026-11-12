"""SAMPLE tool registrations built from the P0 mock tool doubles.

These exist for tests and demos only. GAMIS does not depend on them: any domain registers its own
ToolDefinitions through ToolRegistry.register in exactly the same way.
"""
from __future__ import annotations

from gamis.schemas.common import ApprovalType, PermissionClass, Principal, RiskLevel
from gamis.schemas.policy import ApprovalRequirement, PolicyVersion
from gamis.schemas.tools import (ArgumentSpec, ArgumentType, OperationArgumentSchema, ToolDefinition, ToolOperation)
from gamis.tools.mock_tools import MockCaseAction, MockIntelLookup, MockLogSearch
from gamis.tools.registry import ToolRegistry

SAMPLE_OPERATIONS = {MockLogSearch.name: "search", MockIntelLookup.name: "lookup", MockCaseAction.name: "execute"}


def _text(name: str, required: bool, description: str) -> ArgumentSpec:
    return ArgumentSpec(name=name, type=ArgumentType.STRING, required=required, description=description,
                        max_length=256)


def sample_tool_definitions(policy_version: PolicyVersion) -> tuple[ToolDefinition, ...]:
    log_search = ToolDefinition(
        tool_id=MockLogSearch.name, name="Log search (synthetic)", version="1.0.0",
        description="Exact-match search over the synthetic P0 log events.",
        permission_class=PermissionClass(MockLogSearch.kind),
        supported_operations=(ToolOperation(operation_id="search", description="Search events",
                                            permission_class=PermissionClass.READ),),
        argument_schemas=(OperationArgumentSchema(operation_id="search", arguments=(
            *(_text(f, False, f"Exact match on {f}") for f in MockLogSearch._EXACT),
            _text("contains", False, "Case-insensitive substring of the message"),
            ArgumentSpec(name="limit", type=ArgumentType.INTEGER, required=False, description="Maximum results",
                         minimum=1, maximum=1000))),),
        risk_classification=RiskLevel.LOW, approval_requirements=(), enabled_status=True,
        policy_version=policy_version)
    intel_lookup = ToolDefinition(
        tool_id=MockIntelLookup.name, name="Intel lookup (synthetic)", version="1.0.0",
        description="Look up an indicator in the synthetic P0 intel records.",
        permission_class=PermissionClass(MockIntelLookup.kind),
        supported_operations=(ToolOperation(operation_id="lookup", description="Look up one indicator",
                                            permission_class=PermissionClass.READ),),
        argument_schemas=(OperationArgumentSchema(operation_id="lookup", arguments=(
            _text("indicator", True, "Indicator to look up"),)),),
        risk_classification=RiskLevel.LOW, approval_requirements=(), enabled_status=True,
        policy_version=policy_version)
    case_action = ToolDefinition(
        tool_id=MockCaseAction.name, name="Case action (synthetic)", version="1.0.0",
        description="State-changing action double. Disabled by default, as in P0.",
        permission_class=PermissionClass(MockCaseAction.kind),
        supported_operations=(ToolOperation(operation_id="execute", description="Execute an action",
                                            permission_class=PermissionClass.ACTION),),
        argument_schemas=(OperationArgumentSchema(operation_id="execute", arguments=(
            _text("action", True, "Action verb"), _text("target", True, "Action target"))),),
        risk_classification=RiskLevel.HIGH,
        approval_requirements=(ApprovalRequirement(
            requirement_id="case-action-human-approval", approval_type=ApprovalType.HUMAN_APPROVAL,
            applies_to=PermissionClass.ACTION, tool_id=MockCaseAction.name, approver_roles=("mission-owner",),
            minimum_approvals=1, description="Every action requires human approval"),),
        enabled_status=False, policy_version=policy_version)
    return (log_search, intel_lookup, case_action)


def build_sample_registry(policy_version: PolicyVersion, admin: Principal,
                          registry_id: str = "sample-registry", recorder=None) -> ToolRegistry:
    registry = ToolRegistry(registry_id, policy_version, recorder=recorder)
    for definition in sample_tool_definitions(policy_version):
        registry.register(definition, actor=admin)
    return registry
