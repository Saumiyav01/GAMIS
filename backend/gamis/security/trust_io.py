"""Public trust-store files (P2): JSON lists of TrustedKey records for independent verifiers.

Contains public keys only. Loading validates every record (key id derived from the public key, allowed
signer types per object type) exactly as P1 TrustStore.add() does.
"""
from __future__ import annotations

import json
from pathlib import Path

from gamis.security.keys import TrustedKey, TrustStore

FORMAT = "gamis.trust_store.v1"


def save_trust_store(store: TrustStore, path: str | Path) -> None:
    data = {"format": FORMAT, "keys": [k.model_dump(mode="json") for k in store.all()]}
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_trust_store(path: str | Path) -> TrustStore:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("keys"), list):
        raise ValueError(f"{path} is not a {FORMAT} file")
    return TrustStore(tuple(TrustedKey.model_validate(k) for k in data["keys"]))
