"""SHA-256 content digests over canonical JSON."""
from __future__ import annotations

import hashlib
from typing import Any

from gamis.security.canonical import canonicalize


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: Any) -> str:
    """Lower-case hex SHA-256 of the RFC 8785 canonical form of ``value``."""
    return sha256_hex(canonicalize(value))


def domain_digest(domain: str, value: Any) -> str:
    """Digest bound to a domain tag, so equal content in different domains hashes differently."""
    return sha256_hex(b"GAMIS-DIGEST-V1\x00" + domain.encode("ascii") + b"\x00" + canonicalize(value))
