"""Signed tool registry (P1).

Definitions are immutable models. Only a REGISTRY_ADMIN principal may change the registry, every change
invalidates the seal, and consumers trust the registry only through a signed RegistrySnapshot. The
in-process actor check is a guard rail; the signature is the actual integrity control.
Execution enforcement belongs to the Secure Tool Gateway (P4).
"""
from __future__ import annotations

import threading
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from gamis.schemas.common import Principal, PrincipalType
from gamis.schemas.policy import PolicyVersion
from gamis.schemas.tools import RegistrySnapshot, ToolDefinition
from gamis.security.digest import canonical_digest
from gamis.security.keys import Signer, TrustStore
from gamis.security.signing import SignatureVerificationError, sign_object, verify_object

if TYPE_CHECKING:
    from gamis.audit.recorder import AuditRecorder


class RegistryError(Exception):
    pass


class RegistryPermissionError(RegistryError):
    pass


class RegistryIntegrityError(RegistryError):
    pass


class RegistryReader(Protocol):
    """Read-only surface used by the Authority Service and, later, the gateway."""

    def get(self, tool_id: str, version: str | None = None) -> ToolDefinition | None: ...
    def list(self) -> tuple[ToolDefinition, ...]: ...
    def verify_integrity(self, trust_store: TrustStore, now: datetime) -> RegistrySnapshot: ...


def _require_admin(actor: Principal) -> None:
    if not isinstance(actor, Principal) or actor.principal_type is not PrincipalType.REGISTRY_ADMIN:
        raise RegistryPermissionError("only a REGISTRY_ADMIN principal may modify the tool registry")


class ToolRegistry:
    def __init__(self, registry_id: str, policy_version: PolicyVersion, recorder: "AuditRecorder | None" = None):
        self._recorder = recorder   # P2: changes are audited before they take effect
        self.registry_id = registry_id
        self.policy_version = policy_version
        self._definitions: dict[str, dict[tuple[int, int, int], ToolDefinition]] = {}
        self._revision = 0
        self._snapshot: RegistrySnapshot | None = None
        self._lock = threading.Lock()

    # -- mutation (admin only) ------------------------------------------------------------------
    def register(self, definition: ToolDefinition, *, actor: Principal) -> ToolDefinition:
        _require_admin(actor)
        definition = ToolDefinition.model_validate(definition.model_dump(mode="json"))
        if definition.policy_version.policy_id != self.policy_version.policy_id:
            raise RegistryError("tool definition belongs to a different policy")
        with self._lock:
            versions = self._definitions.setdefault(definition.tool_id, {})
            if definition.version_tuple in versions:
                raise RegistryError(f"{definition.tool_id} {definition.version} is already registered; "
                                    "definitions are immutable - register a new version")
            if versions and definition.version_tuple <= max(versions):
                raise RegistryError(f"{definition.tool_id} version must be greater than "
                                    f"{'.'.join(map(str, max(versions)))}")
            if self._recorder is not None:
                self._recorder.tool_registered(self.registry_id, self._revision + 1, definition, actor)
            versions[definition.version_tuple] = definition
            self._changed()
        return definition

    def set_enabled(self, tool_id: str, version: str, enabled: bool, *, actor: Principal) -> ToolDefinition:
        _require_admin(actor)
        with self._lock:
            current = self._lookup(tool_id, version)
            if current is None:
                raise RegistryError(f"{tool_id} {version} is not registered")
            updated = ToolDefinition.model_validate({**current.model_dump(mode="json"), "enabled_status": enabled})
            if self._recorder is not None:
                self._recorder.tool_status_changed(self.registry_id, self._revision + 1, updated, actor)
            self._definitions[tool_id][updated.version_tuple] = updated
            self._changed()
        return updated

    def seal(self, signer: Signer, now: datetime) -> RegistrySnapshot:
        """Sign the current state. Must be repeated after every change."""
        with self._lock:
            if self._revision == 0:
                raise RegistryError("cannot seal an empty registry")
            snapshot = RegistrySnapshot(registry_id=self.registry_id, registry_version=self._revision,
                                        policy_version=self.policy_version, definitions=self._sorted(),
                                        sealed_at=now)
            sealed = snapshot.with_signature(sign_object(snapshot, signer, now=now))
            if self._recorder is not None:
                self._recorder.registry_sealed(sealed)
            self._snapshot = sealed
            return self._snapshot

    def _changed(self) -> None:
        self._revision += 1
        self._snapshot = None

    # -- reads ----------------------------------------------------------------------------------
    def _sorted(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._definitions[t][v] for t in sorted(self._definitions) for v in sorted(self._definitions[t]))

    def _lookup(self, tool_id: str, version: str | None) -> ToolDefinition | None:
        versions = self._definitions.get(tool_id)
        if not versions:
            return None
        if version is None:
            return versions[max(versions)]
        return next((d for d in versions.values() if d.version == version), None)

    def get(self, tool_id: str, version: str | None = None) -> ToolDefinition | None:
        found = self._lookup(tool_id, version)
        return None if found is None else found.model_copy(deep=True)  # callers never hold our instance

    def list(self) -> tuple[ToolDefinition, ...]:
        return tuple(d.model_copy(deep=True) for d in self._sorted())

    @property
    def snapshot(self) -> RegistrySnapshot | None:
        return self._snapshot

    def verify_integrity(self, trust_store: TrustStore, now: datetime) -> RegistrySnapshot:
        """Check the seal's signature and that live definitions still equal the sealed ones."""
        snapshot = self._snapshot
        if snapshot is None:
            raise RegistryIntegrityError("registry is not sealed (unsigned or changed since last seal)")
        try:
            verify_object(snapshot, trust_store, now=now)
        except SignatureVerificationError as exc:
            raise RegistryIntegrityError(f"registry seal invalid: {type(exc).__name__}: {exc}") from exc
        live = [d.model_dump(mode="json", warnings=False) for d in self._sorted()]
        sealed = [d.model_dump(mode="json") for d in snapshot.definitions]
        if (snapshot.registry_id != self.registry_id or snapshot.registry_version != self._revision
                or snapshot.policy_version != self.policy_version
                or canonical_digest(live) != canonical_digest(sealed)):
            raise RegistryIntegrityError("registry contents differ from the signed snapshot")
        return snapshot

    def read_only(self) -> "ReadOnlyToolRegistry":
        return ReadOnlyToolRegistry(self)

    @classmethod
    def from_snapshot(cls, snapshot: RegistrySnapshot, trust_store: TrustStore, now: datetime) -> "ToolRegistry":
        """Rebuild a registry from a signed snapshot (e.g. in another process). Verifies before loading."""
        try:
            verify_object(snapshot, trust_store, now=now)
        except SignatureVerificationError as exc:
            raise RegistryIntegrityError(f"snapshot rejected: {type(exc).__name__}: {exc}") from exc
        registry = cls(snapshot.registry_id, snapshot.policy_version)
        for definition in snapshot.definitions:
            registry._definitions.setdefault(definition.tool_id, {})[definition.version_tuple] = definition
        registry._revision = snapshot.registry_version
        registry._snapshot = snapshot
        return registry


class ReadOnlyToolRegistry:
    """What workers receive: lookups only, no mutation methods at all."""

    __slots__ = ("__registry",)

    def __init__(self, registry: ToolRegistry):
        self.__registry = registry

    def get(self, tool_id: str, version: str | None = None) -> ToolDefinition | None:
        return self.__registry.get(tool_id, version)

    def list(self) -> tuple[ToolDefinition, ...]:
        return self.__registry.list()

    def verify_integrity(self, trust_store: TrustStore, now: datetime) -> RegistrySnapshot:
        return self.__registry.verify_integrity(trust_store, now)
