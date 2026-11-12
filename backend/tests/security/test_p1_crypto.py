"""P1 cryptographic tests: RFC 8785 canonical JSON, SHA-256 digests, Ed25519 signing, keys, rotation."""
from __future__ import annotations

import hashlib
import json
import os
import pickle
import stat
import struct
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from gamis.schemas import (AgentAssignment, MissionGrant, Principal, PrincipalType, SignatureMetadata,
                           SignedObjectType, ToolReceipt)
from gamis.security import signing
from gamis.security.canonical import CanonicalizationError, canonicalize
from gamis.security.dev_keys import DevKeyStore
from gamis.security.digest import canonical_digest, domain_digest, sha256_hex
from gamis.security.keys import (Ed25519Signer, KeyManagementError, KeyStatus, SoftwareKeyManager, TrustStore,
                                 b64url_decode, b64url_encode, compute_key_id, trusted_key_for, verify_ed25519)
from gamis.security.signing import sign_object, verify_object
from tests.p1_support import AUTHORITY, GATEWAY, NOW, SUPERVISOR, build_trust_world, receipt_dict

REPO_ROOT = Path(__file__).resolve().parents[3]


# --- RFC 8785 canonicalization ------------------------------------------------------------------

RFC8785_NUMBER_VECTORS = [  # RFC 8785 Appendix B (IEEE-754 bits -> expected serialization)
    ("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"), ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"), ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"), ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"), ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"), ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("bits,expected", RFC8785_NUMBER_VECTORS)
def test_rfc8785_number_serialization(bits, expected):
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    assert canonicalize(value) == expected.encode()


def test_rfc8785_sample_object():
    # RFC 8785 section 3.2.2/3.2.3 sample; characters built with chr() so the source file stays ASCII.
    text = chr(0x20AC) + "$" + chr(0x0F) + chr(0x0A) + "A'B" + chr(0x22) + chr(0x5C) + chr(0x5C) + chr(0x22) + "/"
    source = {"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
              "string": text, "literals": [None, True, False]}
    expected_string = (chr(0x22) + chr(0x20AC) + "$" + chr(0x5C) + "u000f" + chr(0x5C) + "nA'B" + chr(0x5C) + chr(0x22)
                       + chr(0x5C) * 4 + chr(0x5C) + chr(0x22) + "/" + chr(0x22))
    expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":'
                + expected_string + "}")
    assert canonicalize(source) == expected.encode("utf-8")
    assert json.loads(canonicalize(source)) == source


def test_rfc8785_keys_sort_by_utf16_code_units():
    euro, cr, dalet, grin, ctrl, o_uml = chr(0x20AC), chr(0x0D), chr(0xFB33), chr(0x1F600), chr(0x80), chr(0xF6)
    source = {euro: "Euro Sign", cr: "Carriage Return", dalet: "Hebrew Letter Dalet With Dagesh", "1": "One",
              grin: "Emoji: Grinning Face", ctrl: "Control", o_uml: "Latin Small Letter O With Diaeresis"}
    order = [k for k, _ in json.loads(canonicalize(source).decode("utf-8"), object_pairs_hook=list)]
    assert order == [cr, "1", ctrl, o_uml, euro, grin, dalet]   # code-point order would put dalet before grin
    assert sorted(source) != order


def test_canonical_serialization_is_deterministic():
    a = {"b": [1, 2, {"z": None, "a": True}], "a": "x", "c": 1.0}
    b = {"c": 1, "a": "x", "b": (1, 2, {"a": True, "z": None})}   # other key order, tuple, int vs float
    assert canonicalize(a) == canonicalize(b) == b'{"a":"x","b":[1,2,{"a":true,"z":null}],"c":1}'
    assert all(canonicalize(a) == canonicalize(a) for _ in range(20))
    assert canonical_digest(a) == canonical_digest(b) == sha256_hex(canonicalize(a))
    assert canonical_digest({}) == hashlib.sha256(b"{}").hexdigest()
    assert canonical_digest(a) != canonical_digest({**a, "a": "y"})
    assert domain_digest("type.a", a) != domain_digest("type.b", a) != canonical_digest(a)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 2**53, -(2**53), {1: "x"}, {"x": b"bytes"},
                                   {"x": {1, 2}}, chr(0xD800), {chr(0xD800): 1}, object()])
def test_canonicalization_rejects_non_json(value):
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


def test_model_canonical_form_is_stable_across_input_order():
    data = receipt_dict()
    one = ToolReceipt.model_validate(data)
    two = ToolReceipt.model_validate(dict(reversed(list(data.items()))))
    assert canonicalize(one.signed_payload()) == canonicalize(two.signed_payload())
    assert signing.payload_digest(SignedObjectType.TOOL_RECEIPT, one.signed_payload()) == \
        signing.payload_digest(SignedObjectType.TOOL_RECEIPT, two.signed_payload())


# --- Ed25519 primitives --------------------------------------------------------------------------

def test_ed25519_matches_rfc8032_test_vector():
    # RFC 8032 section 7.1 TEST 1: a published test vector, not a GAMIS key.
    secret = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    expected = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
                             "1cf9b46bd25bf5f0595bbe24655141438e7a100b")
    signer = Ed25519Signer(Ed25519PrivateKey.from_private_bytes(secret), key_name="rfc8032", key_version=1,
                           principal=AUTHORITY)
    assert signer.public_key_raw() == public and signer.sign(b"") == expected
    assert len(expected) == 64 and verify_ed25519(public, expected, b"")
    assert not verify_ed25519(public, expected, b"x")
    assert signer.key_id == compute_key_id(public) and signer.key_id.startswith("gk-")


def test_signer_never_exposes_private_key():
    world = build_trust_world()
    signer = world.gateway_signer
    assert "private" not in repr(signer).lower() and signer.key_id in repr(signer)
    assert not [n for n in dir(signer) if not n.startswith("_") and "private" in n]
    with pytest.raises(KeyManagementError):
        pickle.dumps(signer)
    record = world.trust_store.get(signer.key_id)
    assert set(record.model_dump()) == {"key_id", "key_name", "key_version", "algorithm", "public_key", "principal",
                                        "allowed_object_types", "status", "not_before", "not_after"}


def test_base64url_must_be_canonical():
    raw = bytes(range(64))
    text = b64url_encode(raw)
    assert b64url_decode(text) == raw and len(text) == 86
    with pytest.raises(ValueError):
        b64url_decode(text[:-1] + "B")   # same bytes, different trailing bits


# --- signing and verification --------------------------------------------------------------------

def test_valid_signature_verifies_and_is_deterministic():
    world = build_trust_world()
    assignment = world.issue()
    meta = assignment.signature_metadata
    verified = verify_object(assignment, world.trust_store, now=NOW)
    assert verified.object_type is SignedObjectType.AGENT_ASSIGNMENT and verified.key.principal == AUTHORITY
    assert meta.algorithm.value == "Ed25519" and meta.canonicalization == "RFC8785" and meta.key_version == 1
    assert meta.payload_digest == signing.payload_digest(SignedObjectType.AGENT_ASSIGNMENT,
                                                         assignment.signed_payload())
    assert len(b64url_decode(meta.signature)) == 64
    # round-trip through JSON keeps the signature valid
    restored = AgentAssignment.model_validate_json(assignment.model_dump_json())
    assert verify_object(restored, world.trust_store, now=NOW).metadata == meta
    # Ed25519 is deterministic: signing the same grant again yields the same signature
    again = sign_object(world.grant, world.issuer_signer, now=world.grant.signature_metadata.signed_at)
    assert again == world.grant.signature_metadata


@pytest.mark.parametrize("update", [
    {"permission_class": "ACTION"}, {"worker_id": "worker-intel-1"}, {"permitted_tools": ("log_search", "case_action")},
    {"task_objective": "Collect log evidence."}, {"assignment_id": "ASG-002"},
])
def test_modified_assignment_is_detected(update):
    world = build_trust_world()
    tampered = world.issue().model_copy(update=update)
    with pytest.raises((signing.PayloadTamperedError, signing.MalformedSignedObjectError)):
        verify_object(tampered, world.trust_store, now=NOW)


def test_modified_nested_fields_are_detected():
    world = build_trust_world()
    assignment = world.issue()
    bigger = assignment.resource_limits.model_copy(update={"max_tool_calls": 99_999})
    later = assignment.expires_at + timedelta(days=30)
    for update in ({"resource_limits": bigger}, {"expires_at": later}):
        with pytest.raises(signing.PayloadTamperedError):
            verify_object(assignment.model_copy(update=update), world.trust_store, now=NOW)
    data = json.loads(assignment.model_dump_json())
    data["tool_call_limits"][0]["max_calls"] = 19
    with pytest.raises(signing.PayloadTamperedError):
        verify_object(AgentAssignment.model_validate(data), world.trust_store, now=NOW)


def test_tampered_payload_is_rejected_for_every_signed_type():
    world = build_trust_world()
    receipt = ToolReceipt.model_validate(receipt_dict())
    receipt = receipt.with_signature(sign_object(receipt, world.gateway_signer, now=NOW))
    verify_object(receipt, world.trust_store, now=NOW)
    verify_object(world.registry.snapshot, world.trust_store, now=NOW)
    cases = [receipt.model_copy(update={"result_digest": "b" * 64}),
             receipt.model_copy(update={"execution_status": "FAILED", "error_code": "x", "result_digest": None}),
             world.grant.model_copy(update={"maximum_worker_count": 500}),
             world.registry.snapshot.model_copy(update={"registry_version": 2})]
    for tampered in cases:
        with pytest.raises((signing.PayloadTamperedError, signing.MalformedSignedObjectError)):
            verify_object(tampered, world.trust_store, now=NOW)


def test_tampered_signature_and_metadata_are_rejected():
    world = build_trust_world()
    assignment = world.issue()
    meta = assignment.signature_metadata
    flipped = meta.signature[:10] + ("A" if meta.signature[10] != "A" else "B") + meta.signature[11:]
    for update, error in [({"signature": flipped}, signing.InvalidSignatureError),
                          ({"signed_at": meta.signed_at - timedelta(seconds=1)}, signing.InvalidSignatureError),
                          ({"payload_digest": "0" * 64}, signing.PayloadTamperedError)]:
        forged = assignment.with_signature(meta.model_copy(update=update))
        with pytest.raises(error):
            verify_object(forged, world.trust_store, now=NOW)


def test_missing_signature_is_rejected():
    world = build_trust_world()
    unsigned = world.issue().without_signature()
    with pytest.raises(signing.MissingSignatureError):
        verify_object(unsigned, world.trust_store, now=NOW)
    with pytest.raises(signing.MissingSignatureError):
        verify_object(MissionGrant.model_validate(world.grant.signed_payload()), world.trust_store, now=NOW)
    with pytest.raises(signing.MalformedSignedObjectError):
        verify_object({"not": "a model"}, world.trust_store, now=NOW)


def test_wrong_public_key_is_rejected():
    world, other = build_trust_world(), build_trust_world()       # two independent key sets
    assignment = world.issue()
    with pytest.raises(signing.UnknownKeyError):                  # verifier that does not trust the signing key
        verify_object(assignment, other.trust_store, now=NOW)
    with pytest.raises(signing.UnknownKeyError):
        verify_object(assignment, TrustStore(), now=NOW)
    # attacker signs with their own key but claims the trusted key's id
    forged_payload = assignment.without_signature().model_copy(update={"assignment_id": "ASG-EVIL"})
    attacker = Ed25519Signer(Ed25519PrivateKey.generate(), key_name="authority-assignment", key_version=1,
                             principal=AUTHORITY)
    attacker_meta = sign_object(forged_payload, attacker, now=NOW)
    forged = forged_payload.with_signature(attacker_meta.model_copy(update={"key_id": assignment.signature_metadata.key_id}))
    with pytest.raises(signing.InvalidSignatureError):
        verify_object(forged, world.trust_store, now=NOW)
    real_key = world.trust_store.get(assignment.signature_metadata.key_id).public_key_raw()
    message = signing.signing_input(SignedObjectType.AGENT_ASSIGNMENT, assignment.signature_metadata.protected_header())
    signature = b64url_decode(assignment.signature_metadata.signature)
    assert verify_ed25519(real_key, signature, message)
    assert not verify_ed25519(attacker.public_key_raw(), signature, message)


def test_domain_separation_between_object_types():
    header = {"key_id": "k", "payload_digest": "0" * 64}
    inputs = {signing.signing_input(t, header) for t in SignedObjectType}
    digests = {signing.payload_digest(t, {"same": "payload"}) for t in SignedObjectType}
    assert len(inputs) == len(digests) == len(SignedObjectType)
    # a raw signature over one type's signing input does not verify for another type
    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(key, key_name="k", key_version=1, principal=GATEWAY)
    signature = signer.sign(signing.signing_input(SignedObjectType.TOOL_RECEIPT, header))
    assert verify_ed25519(signer.public_key_raw(), signature, signing.signing_input(SignedObjectType.TOOL_RECEIPT, header))
    for other in set(SignedObjectType) - {SignedObjectType.TOOL_RECEIPT}:
        assert not verify_ed25519(signer.public_key_raw(), signature, signing.signing_input(other, header))
    assert {m.OBJECT_TYPE for m in (MissionGrant, AgentAssignment, ToolReceipt)} == {
        SignedObjectType.MISSION_GRANT, SignedObjectType.AGENT_ASSIGNMENT, SignedObjectType.TOOL_RECEIPT}


def test_cross_object_signature_misuse_is_rejected():
    world = build_trust_world()
    assignment = world.issue()
    receipt = ToolReceipt.model_validate(receipt_dict())
    receipt = receipt.with_signature(sign_object(receipt, world.gateway_signer, now=NOW))
    # 1. reuse a valid signature block from one object type on another
    for victim, donor in [(world.grant, assignment), (assignment, world.grant), (assignment, receipt),
                          (receipt, assignment)]:
        with pytest.raises(signing.DomainMismatchError):
            verify_object(victim.with_signature(donor.signature_metadata), world.trust_store, now=NOW)
    # 2. relabel the donor signature as the victim's type
    relabelled = receipt.signature_metadata.model_copy(update={"object_type": SignedObjectType.AGENT_ASSIGNMENT})
    with pytest.raises(signing.KeyNotAuthorizedError):
        verify_object(assignment.with_signature(relabelled), world.trust_store, now=NOW)
    # 3. a gateway key genuinely signing assignment-shaped content is refused at signing and at verification
    with pytest.raises(signing.KeyNotAuthorizedError):
        sign_object(assignment.without_signature(), world.gateway_signer, now=NOW)
    with pytest.raises(signing.KeyNotAuthorizedError):
        sign_object(world.grant.without_signature(), world.authority._AuthorityService__signer, now=NOW)


def test_trust_store_refuses_wrong_principal_for_object_type():
    signer = Ed25519Signer(Ed25519PrivateKey.generate(), key_name="sup", key_version=1, principal=SUPERVISOR)
    worker = Principal(principal_id="worker-reader-1", principal_type=PrincipalType.WORKER)
    for principal, types in [(SUPERVISOR, (SignedObjectType.AGENT_ASSIGNMENT,)),
                             (worker, (SignedObjectType.AGENT_ASSIGNMENT,)),
                             (GATEWAY, (SignedObjectType.TOOL_RECEIPT, SignedObjectType.AGENT_ASSIGNMENT)),
                             (AUTHORITY, (SignedObjectType.MISSION_GRANT,))]:
        s = Ed25519Signer(Ed25519PrivateKey.generate(), key_name="k", key_version=1, principal=principal)
        with pytest.raises(ValidationError, match="may not sign"):
            trusted_key_for(s, types, NOW)
    record = trusted_key_for(Ed25519Signer(Ed25519PrivateKey.generate(), key_name="a", key_version=1,
                                           principal=AUTHORITY), (SignedObjectType.AGENT_ASSIGNMENT,), NOW)
    with pytest.raises(ValidationError, match="key_id does not match"):
        type(record).model_validate({**record.model_dump(mode="json"), "public_key": b64url_encode(signer.public_key_raw())})


# --- key versions and rotation -------------------------------------------------------------------

def test_key_version_handling_and_rotation():
    world = build_trust_world()
    old_assignment = world.issue()
    old_meta = old_assignment.signature_metadata
    with pytest.raises(signing.KeyVersionMismatchError):
        verify_object(old_assignment.with_signature(old_meta.model_copy(update={"key_version": 2})),
                      world.trust_store, now=NOW)

    world.clock.advance(minutes=5)
    rotated_at = world.clock.now
    new_signer = world.keys.rotate("authority-assignment", rotated_at)
    assert new_signer.key_version == 2 and new_signer.key_id != old_meta.key_id
    assert world.keys.current("authority-assignment") is new_signer
    versions = world.trust_store.versions("authority-assignment")
    assert [(k.key_version, k.status) for k in versions] == [(1, KeyStatus.RETIRED), (2, KeyStatus.ACTIVE)]
    assert versions[0].not_after == rotated_at

    # signatures made before rotation stay valid; the new key signs as version 2
    verify_object(old_assignment, world.trust_store, now=world.clock.now)
    fresh = old_assignment.without_signature().model_copy(update={"assignment_id": "ASG-AFTER-ROTATION"})
    fresh = fresh.with_signature(sign_object(fresh, new_signer, now=world.clock.now))
    assert verify_object(fresh, world.trust_store, now=world.clock.now).metadata.key_version == 2

    # the retired key cannot authenticate anything dated after its retirement
    world.clock.advance(minutes=5)
    late = fresh.without_signature()
    stale = world.authority._AuthorityService__signer   # service still holds v1 until reconfigured
    assert stale.key_version == 1
    late = late.with_signature(sign_object(late, stale, now=world.clock.now))
    with pytest.raises(signing.KeyValidityError):
        verify_object(late, world.trust_store, now=world.clock.now)

    # revocation invalidates everything signed by that key, including old signatures
    world.trust_store.revoke(old_meta.key_id)
    with pytest.raises(signing.KeyRevokedError):
        verify_object(old_assignment, world.trust_store, now=world.clock.now)
    verify_object(fresh, world.trust_store, now=world.clock.now)


def test_key_manager_rules():
    keys = SoftwareKeyManager()
    keys.create_key("gw", GATEWAY, (SignedObjectType.TOOL_RECEIPT,), NOW)
    with pytest.raises(KeyManagementError, match="use rotate"):
        keys.create_key("gw", GATEWAY, (SignedObjectType.TOOL_RECEIPT,), NOW)
    with pytest.raises(KeyManagementError):
        keys.current("missing")
    with pytest.raises(KeyManagementError):
        keys.rotate("missing", NOW)
    with pytest.raises(KeyManagementError, match="already trusted"):
        keys.trust_store.add(keys.trust_store.all()[0])
    with pytest.raises(signing.KeyValidityError):   # signature dated before the key existed
        receipt = ToolReceipt.model_validate(receipt_dict())
        early = receipt.with_signature(sign_object(receipt, keys.current("gw"), now=NOW - timedelta(days=1)))
        verify_object(early, keys.trust_store, now=NOW)
    with pytest.raises(signing.KeyValidityError):   # signature dated in the future
        receipt = ToolReceipt.model_validate(receipt_dict())
        future = receipt.with_signature(sign_object(receipt, keys.current("gw"), now=NOW + timedelta(hours=1)))
        verify_object(future, keys.trust_store, now=NOW)


# --- development key storage ---------------------------------------------------------------------

def test_dev_key_store_requires_dev_environment_and_external_directory(tmp_path):
    for env in ({}, {"GAMIS_ENV": "production"}, {"GAMIS_ENV": "staging"}):
        with pytest.raises(KeyManagementError, match="GAMIS_ENV"):
            DevKeyStore(tmp_path / "keys", environ=env)
    with pytest.raises(KeyManagementError, match="GAMIS_DEV_KEY_DIR"):
        DevKeyStore(environ={"GAMIS_ENV": "development"})
    with pytest.raises(KeyManagementError, match="outside the source tree"):
        DevKeyStore(REPO_ROOT / "backend" / "dev-keys", environ={"GAMIS_ENV": "development"})
    assert not (REPO_ROOT / "backend" / "dev-keys").exists()


def test_dev_key_store_persists_and_rotates(tmp_path):
    env = {"GAMIS_ENV": "test", "GAMIS_DEV_KEY_DIR": str(tmp_path / "keys")}
    store = DevKeyStore(environ=env)
    signer = store.create_key("tool-gateway", GATEWAY, (SignedObjectType.TOOL_RECEIPT,), NOW)
    key_file = tmp_path / "keys" / "tool-gateway.v1.key.pem"
    if os.name != "nt":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    public_text = (tmp_path / "keys" / "tool-gateway.v1.pub.json").read_text()
    assert "PRIVATE" not in public_text and signer.key_id in public_text

    receipt = ToolReceipt.model_validate(receipt_dict())
    signed = receipt.with_signature(sign_object(receipt, signer, now=NOW))

    reopened = DevKeyStore(environ=env)                           # a new process would see the same keys
    assert reopened.current("tool-gateway").key_id == signer.key_id
    verify_object(signed, reopened.trust_store, now=NOW)
    assert reopened.current("tool-gateway").sign(b"m") == signer.sign(b"m")

    v2 = reopened.rotate("tool-gateway", NOW + timedelta(minutes=1))
    third = DevKeyStore(environ=env)
    assert third.current("tool-gateway").key_id == v2.key_id and v2.key_version == 2
    assert [k.status for k in third.trust_store.versions("tool-gateway")] == [KeyStatus.RETIRED, KeyStatus.ACTIVE]
    verify_object(signed, third.trust_store, now=NOW + timedelta(minutes=2))


def test_no_private_keys_or_secrets_in_repository():
    needles = ["-----BEGIN " + kind + "PRIVATE KEY-----" for kind in ("", "EC ", "RSA ", "OPENSSH ", "ENCRYPTED ")]
    offenders = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or {".git", ".venv", "venv", "env", "node_modules", "__pycache__",
                                  ".pytest_cache"} & set(path.parts):
            continue
        if path.suffix in (".pem", ".key"):
            offenders.append(str(path))
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(n in text for n in needles):
            offenders.append(str(path))
    assert offenders == []
    env_example = (REPO_ROOT / "backend" / ".env.example").read_text()
    assert "GAMIS_SIGNING_KEY" not in env_example and "GAMIS_DEV_KEY_DIR=" in env_example


def test_signature_metadata_validation():
    world = build_trust_world()
    good = world.grant.signature_metadata.model_dump(mode="json")
    SignatureMetadata.model_validate(good)
    for bad in ({"algorithm": "HS256"}, {"algorithm": "ed25519"}, {"canonicalization": "none"},
                {"signature_version": 2}, {"key_version": 0}, {"key_version": "1"}, {"signature": "short"},
                {"signature": good["signature"] + "="}, {"payload_digest": "xyz"}, {"object_type": "gamis.other.v1"},
                {"signed_at": "2026-01-10T08:00:00"}, {"signer_identity": "authority"}, {"extra": 1}):
        with pytest.raises(ValidationError):
            SignatureMetadata.model_validate({**good, **bad})
    for field in good:
        with pytest.raises(ValidationError, match="Field required"):
            SignatureMetadata.model_validate({k: v for k, v in good.items() if k != field})
