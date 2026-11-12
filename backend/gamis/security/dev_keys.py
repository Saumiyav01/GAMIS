"""Development key storage: Ed25519 keys as PEM files in a directory OUTSIDE the source tree.

This is deliberately the only module that writes private keys to disk. It refuses to run unless
GAMIS_ENV is 'development' or 'test', and refuses directories inside the repository. Production key
protection (HSM / TPM / KMS) must be a separate ``Signer`` / ``KeyRotator`` implementation.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gamis.security.keys import (Ed25519Signer, KeyManagementError, KeyStatus, SoftwareKeyManager, TrustedKey,
                                 TrustStore)

ALLOWED_ENVIRONMENTS = ("development", "test")
ENV_VAR_ENVIRONMENT = "GAMIS_ENV"
ENV_VAR_KEY_DIR = "GAMIS_DEV_KEY_DIR"
_REPO_ROOT = Path(__file__).resolve().parents[3]


class DevKeyStore(SoftwareKeyManager):
    def __init__(self, directory: Path | str | None = None, environ: Mapping[str, str] | None = None):
        environ = os.environ if environ is None else environ
        env = environ.get(ENV_VAR_ENVIRONMENT, "")
        if env not in ALLOWED_ENVIRONMENTS:
            raise KeyManagementError(f"DevKeyStore requires {ENV_VAR_ENVIRONMENT} in {ALLOWED_ENVIRONMENTS}, "
                                     f"got {env!r}")
        directory = directory or environ.get(ENV_VAR_KEY_DIR)
        if not directory:
            raise KeyManagementError(f"set {ENV_VAR_KEY_DIR} or pass a directory")
        self.directory = Path(directory).resolve()
        if self.directory == _REPO_ROOT or _REPO_ROOT in self.directory.parents:
            raise KeyManagementError("development keys must be stored outside the source tree")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        super().__init__(TrustStore())
        self._load()

    def _paths(self, record: TrustedKey) -> tuple[Path, Path]:
        stem = f"{record.key_name}.v{record.key_version}"
        return self.directory / f"{stem}.key.pem", self.directory / f"{stem}.pub.json"

    def _key_created(self, record: TrustedKey, private_key: Ed25519PrivateKey) -> None:
        key_path, _ = self._paths(record)
        pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        self._record_changed(record)

    def _record_changed(self, record: TrustedKey) -> None:
        _, pub_path = self._paths(record)
        pub_path.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8")

    def _load(self) -> None:
        records = sorted((TrustedKey.model_validate_json(p.read_text(encoding="utf-8"))
                          for p in self.directory.glob("*.pub.json")), key=lambda r: (r.key_name, r.key_version))
        for record in records:
            self.trust_store.add(record)
        for record in records:
            if record.status is not KeyStatus.ACTIVE:
                continue
            key_path, _ = self._paths(record)
            private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            signer = Ed25519Signer(private_key, key_name=record.key_name, key_version=record.key_version,
                                   principal=record.principal)
            if signer.key_id != record.key_id:
                raise KeyManagementError(f"private key file does not match public record for {record.key_name}")
            self._signers[record.key_name] = signer
