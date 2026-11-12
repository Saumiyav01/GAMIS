"""P1 signed tool registry tests."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from gamis.schemas import PermissionClass, Principal, PrincipalType, RegistrySnapshot, RiskLevel, ToolDefinition
from gamis.security import signing
from gamis.tools.mock_tools import MockCaseAction, MockIntelLookup, MockLogSearch
from gamis.tools.registry import (ReadOnlyToolRegistry, RegistryError, RegistryIntegrityError,
                                  RegistryPermissionError, ToolRegistry)
from gamis.tools.sample_registry import build_sample_registry, sample_tool_definitions
from tests.p1_support import NOW, POLICY, REGISTRY_ADMIN, SUPERVISOR, build_trust_world

WORKER = Principal(principal_id="worker-reader-1", principal_type=PrincipalType.WORKER)


def definition(**overrides) -> dict:
    data = sample_tool_definitions(POLICY)[0].model_dump(mode="json")
    data.update(overrides)
    return data


def test_valid_registration_and_p0_sample_tools():
    registry = build_sample_registry(POLICY, REGISTRY_ADMIN)
    assert [d.tool_id for d in registry.list()] == ["case_action", "intel_lookup", "log_search"]
    for double in (MockLogSearch, MockIntelLookup, MockCaseAction):
        d = registry.get(double.name)
        assert d.permission_class is PermissionClass(double.kind) and d.policy_version == POLICY
        assert {s.operation_id for s in d.argument_schemas} == {o.operation_id for o in d.supported_operations}
    action = registry.get("case_action")
    assert action.enabled_status is False and action.risk_classification is RiskLevel.HIGH
    assert action.approval_requirements and registry.get("log_search").enabled_status is True
    assert registry.get("missing") is None and registry.get("log_search", "9.9.9") is None


def test_registry_is_extensible_with_domain_specific_tools():
    registry = build_sample_registry(POLICY, REGISTRY_ADMIN)
    custom = definition(tool_id="document_store", name="Document store", supported_operations=[
        {"operation_id": "fetch", "description": "Fetch a document", "permission_class": "READ"},
        {"operation_id": "list", "description": "List documents", "permission_class": "READ"}],
        argument_schemas=[
            {"operation_id": "fetch", "arguments": [{"name": "document_id", "type": "string", "required": True,
                                                     "description": "Document id", "max_length": 64}]},
            {"operation_id": "list", "arguments": [{"name": "page", "type": "integer", "required": False,
                                                    "description": "Page", "minimum": 1, "maximum": 100}]}])
    registry.register(ToolDefinition.model_validate(custom), actor=REGISTRY_ADMIN)
    stored = registry.get("document_store")
    assert stored.operation("fetch") is not None and stored.operation("purge") is None
    assert stored.schema_for("list").validate_arguments({"page": 0}) == ("page: below minimum 1",)


@pytest.mark.parametrize("overrides,match", [
    ({"permission_class": "read"}, None), ({"permission_class": "WRITE"}, None), ({"permission_class": None}, None),
    ({"supported_operations": [{"operation_id": "search", "description": "d", "permission_class": "EXECUTE"}]}, None),
    ({"supported_operations": [{"operation_id": "search", "description": "d", "permission_class": "ACTION"}]},
     "READ tool cannot expose ACTION"),
    ({"permission_class": "ACTION"}, "must expose at least one ACTION operation"),
    ({"permission_class": "ACTION",
      "supported_operations": [{"operation_id": "search", "description": "d", "permission_class": "ACTION"}]},
     "requires at least one ACTION approval"),
    ({"risk_classification": "EXTREME"}, None), ({"enabled_status": "yes"}, None), ({"enabled_status": 1}, None),
    ({"hidden_flag": True}, "Extra inputs"),
])
def test_invalid_permission_class_and_fields(overrides, match):
    with pytest.raises(ValidationError, match=match):
        ToolDefinition.model_validate(definition(**overrides))
    data = definition()
    del data["permission_class"]
    with pytest.raises(ValidationError, match="Field required"):
        ToolDefinition.model_validate(data)


def test_unsupported_operations_are_rejected():
    extra_schema = definition()["argument_schemas"] + [{"operation_id": "delete", "arguments": []}]
    with pytest.raises(ValidationError, match="exactly one schema per supported operation"):
        ToolDefinition.model_validate(definition(argument_schemas=extra_schema))
    with pytest.raises(ValidationError, match="exactly one schema per supported operation"):
        ToolDefinition.model_validate(definition(supported_operations=definition()["supported_operations"] + [
            {"operation_id": "export", "description": "d", "permission_class": "READ"}]))
    with pytest.raises(ValidationError, match="duplicate operation"):
        ToolDefinition.model_validate(definition(supported_operations=definition()["supported_operations"] * 2))
    with pytest.raises(ValidationError):
        ToolDefinition.model_validate(definition(supported_operations=[]))
    approval = {"requirement_id": "r", "approval_type": "HUMAN_APPROVAL", "applies_to": "READ",
                "tool_id": "log_search", "operation_id": "purge", "approver_roles": ["owner"],
                "minimum_approvals": 1, "description": "d"}
    with pytest.raises(ValidationError, match="unsupported operation"):
        ToolDefinition.model_validate(definition(approval_requirements=[approval]))
    with pytest.raises(ValidationError, match="apply only to string"):
        ToolDefinition.model_validate(definition(argument_schemas=[{"operation_id": "search", "arguments": [
            {"name": "n", "type": "integer", "required": True, "description": "d", "max_length": 5}]}]))
    log_search = sample_tool_definitions(POLICY)[0]
    assert log_search.operation("delete") is None and log_search.schema_for("delete") is None


def test_version_validation():
    registry = build_sample_registry(POLICY, REGISTRY_ADMIN)
    for bad in ("1.0", "v1.0.0", "1.0.0-beta", "01.0.0", "1.0.0.0", "", 1):
        with pytest.raises(ValidationError):
            ToolDefinition.model_validate(definition(version=bad))
    with pytest.raises(RegistryError, match="already registered"):
        registry.register(ToolDefinition.model_validate(definition()), actor=REGISTRY_ADMIN)
    with pytest.raises(RegistryError, match="already registered"):       # same version, different content
        registry.register(ToolDefinition.model_validate(definition(description="silently changed")),
                          actor=REGISTRY_ADMIN)
    registry.register(ToolDefinition.model_validate(definition(version="1.2.0")), actor=REGISTRY_ADMIN)
    with pytest.raises(RegistryError, match="must be greater"):
        registry.register(ToolDefinition.model_validate(definition(version="1.1.9")), actor=REGISTRY_ADMIN)
    registry.register(ToolDefinition.model_validate(definition(version="1.10.0")), actor=REGISTRY_ADMIN)
    assert registry.get("log_search").version == "1.10.0"                # numeric, not lexical, ordering
    assert registry.get("log_search", "1.0.0").version == "1.0.0"
    other_policy = {"policy_id": "another-policy", "version": "1.0.0"}
    with pytest.raises(RegistryError, match="different policy"):
        registry.register(ToolDefinition.model_validate(definition(tool_id="t2", policy_version=other_policy)),
                          actor=REGISTRY_ADMIN)


def test_worker_modification_is_rejected():
    world = build_trust_world()
    registry = world.registry
    new_tool = ToolDefinition.model_validate(definition(tool_id="worker_tool"))
    for actor in (WORKER, SUPERVISOR, None, "registry-admin-1"):
        with pytest.raises(RegistryPermissionError):
            registry.register(new_tool, actor=actor)
        with pytest.raises(RegistryPermissionError):
            registry.set_enabled("case_action", "1.0.0", True, actor=actor)
    assert registry.get("worker_tool") is None and registry.get("case_action").enabled_status is False

    view = registry.read_only()                                   # what a worker is handed
    assert isinstance(view, ReadOnlyToolRegistry)
    assert sorted(n for n in dir(view) if not n.startswith("_")) == ["get", "list", "verify_integrity"]
    held = view.get("case_action")
    with pytest.raises(ValidationError, match="frozen"):
        held.enabled_status = True
    with pytest.raises(ValidationError, match="frozen"):
        held.supported_operations[0].permission_class = PermissionClass.READ
    with pytest.raises((TypeError, AttributeError)):
        held.supported_operations.append(None)
    object.__setattr__(held, "enabled_status", True)              # forcing the worker's own copy ...
    assert view.get("case_action").enabled_status is False        # ... does not touch the registry
    view.verify_integrity(world.trust_store, NOW)
    # a worker cannot seal: its key type may not sign registries
    with pytest.raises(signing.KeyNotAuthorizedError):
        registry.seal(world.worker_signer, NOW)
    registry.verify_integrity(world.trust_store, NOW)


def test_registry_tampering_is_detected():
    world = build_trust_world()
    registry, store = world.registry, world.trust_store
    snapshot = registry.verify_integrity(store, NOW)
    assert snapshot.registry_version == 3 and len(snapshot.definitions) == 3

    # 1. in-memory tampering that bypasses the admin API
    internal = registry._definitions["case_action"][(1, 0, 0)]
    registry._definitions["case_action"][(1, 0, 0)] = internal.model_copy(update={"enabled_status": True})
    with pytest.raises(RegistryIntegrityError, match="differ from the signed snapshot"):
        registry.verify_integrity(store, NOW)
    registry._definitions["case_action"][(1, 0, 0)] = internal
    registry.verify_integrity(store, NOW)
    object.__setattr__(internal, "permission_class", PermissionClass.READ)      # mutate the stored object itself
    with pytest.raises(RegistryIntegrityError):
        registry.verify_integrity(store, NOW)

    # 2. a legitimate change invalidates the seal until an admin key re-signs
    world = build_trust_world()
    world.registry.set_enabled("case_action", "1.0.0", True, actor=REGISTRY_ADMIN)
    with pytest.raises(RegistryIntegrityError, match="not sealed"):
        world.registry.verify_integrity(world.trust_store, NOW)
    assert world.registry.seal(world.registry_signer, NOW).registry_version == 4
    world.registry.verify_integrity(world.trust_store, NOW)

    # 3. a seal made by an untrusted key
    other = build_trust_world()
    world.registry.seal(other.registry_signer, NOW)
    with pytest.raises(RegistryIntegrityError, match="seal invalid"):
        world.registry.verify_integrity(world.trust_store, NOW)
    with pytest.raises(RegistryError, match="empty"):
        ToolRegistry("empty", POLICY).seal(world.registry_signer, NOW)


def test_snapshot_export_import_and_tampering():
    world = build_trust_world()
    exported = world.registry.snapshot.model_dump_json()
    restored = ToolRegistry.from_snapshot(RegistrySnapshot.model_validate_json(exported), world.trust_store, NOW)
    assert [d.model_dump() for d in restored.list()] == [d.model_dump() for d in world.registry.list()]
    restored.verify_integrity(world.trust_store, NOW)

    data = json.loads(exported)
    case_action = next(d for d in data["definitions"] if d["tool_id"] == "case_action")
    case_action["enabled_status"] = True
    with pytest.raises(RegistryIntegrityError, match="PayloadTamperedError"):
        ToolRegistry.from_snapshot(RegistrySnapshot.model_validate(data), world.trust_store, NOW)
    data = json.loads(exported)
    data["definitions"] = data["definitions"][1:]                 # silently drop a tool
    with pytest.raises(RegistryIntegrityError):
        ToolRegistry.from_snapshot(RegistrySnapshot.model_validate(data), world.trust_store, NOW)
    data = json.loads(exported)
    data["signature_metadata"] = None
    with pytest.raises(RegistryIntegrityError, match="MissingSignatureError"):
        ToolRegistry.from_snapshot(RegistrySnapshot.model_validate(data), world.trust_store, NOW)
    data = json.loads(exported)
    data["definitions"] = list(reversed(data["definitions"]))
    with pytest.raises(ValidationError, match="sorted"):
        RegistrySnapshot.model_validate(data)
