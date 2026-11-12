"""Filesystem content-addressed store (P2). Object id = lower-case hex SHA-256 of the exact bytes.

Writes are atomic (temp file + fsync + rename + directory fsync). Reads always re-hash. A corrupted or
missing object is reported, never repaired or silently replaced.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Iterator

CAS_REFERENCE_PREFIX = "gamis-cas:sha256:"
DEFAULT_MAX_OBJECT_BYTES = 64 * 1024 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ContentStoreError(Exception):
    pass


class ContentMissingError(ContentStoreError):
    pass


class ContentCorruptedError(ContentStoreError):
    pass


class ObjectStatus(StrEnum):
    OK = "OK"
    MISSING = "MISSING"
    CORRUPTED = "CORRUPTED"


@dataclass(frozen=True)
class PutResult:
    digest: str
    size: int
    deduplicated: bool

    @property
    def reference(self) -> str:
        return cas_reference(self.digest)


def cas_reference(digest: str) -> str:
    _check_digest(digest)
    return CAS_REFERENCE_PREFIX + digest


def parse_cas_reference(reference: str) -> str | None:
    if not reference.startswith(CAS_REFERENCE_PREFIX):
        return None
    digest = reference[len(CAS_REFERENCE_PREFIX):]
    return digest if _DIGEST.match(digest) else None


def _check_digest(digest: str) -> None:
    if not isinstance(digest, str) or not _DIGEST.match(digest):
        raise ContentStoreError("content id must be a lower-case hex SHA-256 digest")


class ContentStore:
    def __init__(self, root: str | Path, *, read_only: bool = False,
                 max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES):
        self.root = Path(root).resolve()
        self.read_only, self.max_object_bytes = read_only, max_object_bytes
        self._objects = self.root / "objects"
        if read_only:
            if not self._objects.is_dir():
                raise ContentStoreError(f"no content store at {self.root}")
        else:
            (self.root / "tmp").mkdir(parents=True, exist_ok=True)
            self._objects.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        _check_digest(digest)
        return self._objects / digest[:2] / digest[2:]

    def put(self, data: bytes) -> PutResult:
        if self.read_only:
            raise ContentStoreError("content store was opened read-only")
        if not isinstance(data, (bytes, bytearray)):
            raise ContentStoreError("content must be bytes")
        if len(data) > self.max_object_bytes:
            raise ContentStoreError(f"object exceeds {self.max_object_bytes} bytes")
        digest = hashlib.sha256(data).hexdigest()
        target = self.path_for(digest)
        if target.exists():
            self.get(digest)  # raises if the existing object is corrupted: never overwrite silently
            return PutResult(digest, len(data), True)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.root / "tmp", prefix="put-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o444)
            os.replace(tmp, target)
            _fsync_dir(target.parent)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return PutResult(digest, len(data), False)

    def get(self, digest: str) -> bytes:
        path = self.path_for(digest)
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            raise ContentMissingError(f"content object {digest} is missing") from None
        if hashlib.sha256(data).hexdigest() != digest:
            raise ContentCorruptedError(f"content object {digest} does not match its digest")
        return data

    def status(self, digest: str) -> ObjectStatus:
        try:
            self.get(digest)
            return ObjectStatus.OK
        except ContentMissingError:
            return ObjectStatus.MISSING
        except ContentCorruptedError:
            return ObjectStatus.CORRUPTED

    def exists(self, digest: str) -> bool:
        return self.path_for(digest).exists()

    def iter_digests(self) -> Iterator[str]:
        for shard in sorted(self._objects.iterdir()) if self._objects.is_dir() else ():
            for obj in sorted(shard.iterdir()):
                digest = shard.name + obj.name
                if _DIGEST.match(digest):
                    yield digest


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
