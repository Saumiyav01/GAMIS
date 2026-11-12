"""RFC 8785 JSON Canonicalization Scheme (JCS).

Input must already be plain JSON data (dict / list / tuple / str / int / float / bool / None).
Numbers follow ECMAScript Number serialization; object keys are sorted by UTF-16 code units.
Integers outside the IEEE-754 safe range are rejected instead of silently losing precision.
"""
from __future__ import annotations

import math
from decimal import Decimal
from typing import Any, Mapping

MAX_SAFE_INTEGER = 2**53 - 1
_MAX_DEPTH = 64
_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented as canonical JSON."""


def _string(value: str) -> str:
    out = ['"']
    for ch in value:
        cp = ord(ch)
        if cp in _ESCAPES:
            out.append(_ESCAPES[cp])
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        elif 0xD800 <= cp <= 0xDFFF:
            raise CanonicalizationError("lone surrogate code points are not valid in canonical JSON")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _float(value: float) -> str:
    """ECMAScript Number::toString for a finite double."""
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN and Infinity are not valid in canonical JSON")
    if value == 0:
        return "0"  # covers -0.0
    sign = "-" if value < 0 else ""
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(map(str, digit_tuple)).lstrip("0")
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = k + exponent
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _utf16_key(key: str) -> bytes:
    try:
        return key.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("object key contains a lone surrogate") from exc


def _serialize(value: Any, depth: int) -> str:
    if depth > _MAX_DEPTH:
        raise CanonicalizationError("maximum nesting depth exceeded")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer outside the IEEE-754 safe range; encode it as a string")
        return str(value)
    if isinstance(value, float):
        return _float(value)
    if isinstance(value, Mapping):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"object keys must be strings, got {type(key).__name__}")
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(f"{_string(k)}:{_serialize(v, depth + 1)}" for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v, depth + 1) for v in value) + "]"
    raise CanonicalizationError(f"type {type(value).__name__} is not JSON data")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value``."""
    return _serialize(value, 0).encode("utf-8")
