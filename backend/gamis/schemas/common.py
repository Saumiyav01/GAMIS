"""Shared building blocks for GAMIS typed schemas (P1).

Conventions used by every model:
- unknown fields are rejected and models are frozen;
- scalars are strict (no "5" -> 5, no 1 -> True); enums accept only their exact values;
- collections are tuples and free-form JSON is deep-frozen;
- timestamps must be timezone-aware and are normalised to UTC.
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Callable, Hashable, Iterable, Mapping, Self

from pydantic import (AfterValidator, AwareDatetime, BaseModel, BeforeValidator, ConfigDict, Field,
                      PlainSerializer, StringConstraints, field_validator)

MAX_SAFE_INTEGER = 2**53 - 1
_MAX_JSON_DEPTH = 32


def _no_bytes(value: Any, _depth: int = 0) -> None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("binary values are not accepted")
    if _depth < 8:
        if isinstance(value, Mapping):
            for item in value.values():
                _no_bytes(item, _depth + 1)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                _no_bytes(item, _depth + 1)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, allow_inf_nan=False)

    @field_validator("*", mode="before")
    @classmethod
    def _reject_bytes(cls, value: Any) -> Any:
        """Binary input is never coerced into text, enums or identifiers."""
        _no_bytes(value)
        return value

    def revalidate(self) -> Self:
        """Re-run full validation. Catches objects built via model_construct / model_copy(update=...)."""
        return type(self).model_validate(self.model_dump(mode="json", warnings=False))


# --- enums -------------------------------------------------------------------------------------

class PermissionClass(StrEnum):
    READ = "READ"
    ACTION = "ACTION"


class PrincipalType(StrEnum):
    MISSION_ISSUER = "MISSION_ISSUER"
    AUTHORITY_SERVICE = "AUTHORITY_SERVICE"
    TOOL_GATEWAY = "TOOL_GATEWAY"
    REGISTRY_ADMIN = "REGISTRY_ADMIN"
    SUPERVISOR = "SUPERVISOR"
    WORKER = "WORKER"
    AUDIT_SERVICE = "AUDIT_SERVICE"        # P2: signs audit checkpoints
    EVIDENCE_SERVICE = "EVIDENCE_SERVICE"  # P2: evidence storage actor (never signs authority)


class MissionState(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    COMPLETED = "COMPLETED"
    REVOKED = "REVOKED"


class CompletionStatus(StrEnum):  # values match the P0 harness statuses
    COMPLETE = "complete"
    PARTIAL = "partial"
    STOPPED = "stopped"
    FAILED = "failed"


class ExecutionStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    REJECTED = "REJECTED"
    MALFORMED_RESULT = "MALFORMED_RESULT"


class SourceType(StrEnum):
    TOOL_RESULT = "TOOL_RESULT"
    DOCUMENT = "DOCUMENT"
    HUMAN_INPUT = "HUMAN_INPUT"
    EXTERNAL_FEED = "EXTERNAL_FEED"
    DERIVED = "DERIVED"
    WORKER_ANALYSIS = "WORKER_ANALYSIS"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalType(StrEnum):
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    DUAL_CONTROL = "DUAL_CONTROL"
    POLICY_AUTOMATED = "POLICY_AUTOMATED"


class StoppingConditionType(StrEnum):
    OBJECTIVE_MET = "OBJECTIVE_MET"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    DEADLINE_REACHED = "DEADLINE_REACHED"
    CONSECUTIVE_FAILURES = "CONSECUTIVE_FAILURES"
    CONFIDENCE_REACHED = "CONFIDENCE_REACHED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    MANUAL_STOP = "MANUAL_STOP"


# --- scalar types ------------------------------------------------------------------------------

Identifier = Annotated[str, StringConstraints(strict=True, max_length=128,
                                              pattern=r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")]
ShortText = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=256, pattern=r"\S")]
LongText = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=4000, pattern=r"\S")]
Sha256Hex = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
SemVer = Annotated[str, StringConstraints(
    strict=True, pattern=r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$")]
Flag = Annotated[bool, Field(strict=True)]
Confidence = Annotated[float, Field(strict=True, ge=0.0, le=1.0, allow_inf_nan=False)]
Count = Annotated[int, Field(strict=True, ge=0, le=1_000_000)]

_ISO_8601 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$")


def _timestamp_input(value: Any) -> Any:
    if isinstance(value, datetime) or (isinstance(value, str) and _ISO_8601.match(value)):
        return value
    raise ValueError("timestamp must be a timezone-aware datetime or ISO-8601 string with an explicit offset")


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


UtcDatetime = Annotated[
    AwareDatetime,
    BeforeValidator(_timestamp_input),
    AfterValidator(lambda d: d.astimezone(timezone.utc)),
    PlainSerializer(format_timestamp, return_type=str, when_used="json"),
]


def semver_tuple(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


# --- immutable free-form JSON -------------------------------------------------------------------

class FrozenDict(dict):
    """A dict whose mutators raise. Values are frozen by ``freeze_json`` so it is deeply immutable."""

    __slots__ = ()

    def _blocked(self, *args: Any, **kwargs: Any) -> Any:
        raise TypeError("this JSON content is immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _blocked  # type: ignore[assignment]

    def __copy__(self) -> "FrozenDict":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenDict":
        return self

    def __reduce__(self) -> tuple[Any, ...]:
        return (FrozenDict, (dict(self),))


def freeze_json(value: Any, _depth: int = 0) -> Any:
    """Validate that ``value`` is plain JSON data and return a deeply immutable copy."""
    if _depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON content is nested too deeply")
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("integers must be within the IEEE-754 safe range")
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN and Infinity are not allowed")
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("JSON object keys must be strings")
        return FrozenDict({k: freeze_json(v, _depth + 1) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(v, _depth + 1) for v in value)
    raise ValueError(f"{type(value).__name__} is not JSON data")


def _freeze_object(value: Any) -> Any:
    if not isinstance(value, Mapping):
        raise ValueError("must be a JSON object")
    return freeze_json(value)


FrozenJson = Annotated[Any, AfterValidator(freeze_json)]
JsonObject = Annotated[Any, AfterValidator(_freeze_object)]


def require_unique(items: Iterable[Any], what: str, key: Callable[[Any], Hashable] = lambda x: x) -> None:
    seen: set[Hashable] = set()
    for item in items:
        k = key(item)
        if k in seen:
            raise ValueError(f"duplicate {what}: {k}")
        seen.add(k)


class Principal(StrictModel):
    """An identified actor. The type decides which object types it may ever sign."""

    principal_id: Identifier
    principal_type: PrincipalType
