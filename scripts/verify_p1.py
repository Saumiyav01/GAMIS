"""P1 verification script: exercises the trust foundation end to end on the P0 sample tools.

Usage (from repo root): python scripts/verify_p1.py
Exits non-zero if any check fails. Generates throwaway keys in memory / a temp directory only.
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from gamis.authority.service import AssignmentRejected  # noqa: E402
from gamis.authority.verification import AssignmentVerificationError  # noqa: E402
from gamis.evaluation.bridge import call_double_with_receipt  # noqa: E402
from gamis.evaluation.harness import build_scenarios, build_toolbox  # noqa: E402
from gamis.evaluation.trust_fixture import ACTION_OP, GATEWAY, NOW, POLICY, build_trust_world  # noqa: E402
from gamis.schemas import SignedObjectType, ToolRequest  # noqa: E402
from gamis.security.canonical import canonicalize  # noqa: E402
from gamis.security.dev_keys import DevKeyStore  # noqa: E402
from gamis.security.signing import SignatureVerificationError, sign_object, verify_object  # noqa: E402
from gamis.tools.registry import RegistryIntegrityError  # noqa: E402

failures = 0


def check(name, fn):
    global failures
    try:
        ok = fn() is not False
    except Exception as exc:  # noqa: BLE001
        ok, name = False, f"{name} ({type(exc).__name__}: {exc})"
    failures += 0 if ok else 1
    print(("PASS  " if ok else "FAIL  ") + name)


def raises(error, fn):
    try:
        fn()
    except error:
        return True
    return False


world = build_trust_world()
signed = world.issue()
check("canonical JSON is key-order independent", lambda: canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}')
check("mission grant signature verifies", lambda: world.verifier.verify_grant(world.grant))
check("authority signs a valid assignment; verifier accepts it", lambda: world.verifier.verify(signed, world.grant))
check("modified assignment is rejected", lambda: raises(
    AssignmentVerificationError, lambda: world.verifier.verify(signed.model_copy(update={"permission_class": "ACTION"}))))
check("READ assignment requesting an ACTION operation is rejected", lambda: raises(
    AssignmentRejected, lambda: world.issue(assignment_id="ASG-X", permitted_tools=["case_action"],
                                            permitted_operations=[ACTION_OP], forbidden_actions=[],
                                            tool_call_limits=[{"tool_id": "case_action", "max_calls": 1}])))
check("assignment signature is not valid for a grant (domain separation)", lambda: raises(
    SignatureVerificationError,
    lambda: verify_object(world.grant.with_signature(signed.signature_metadata), world.trust_store, now=NOW)))
check("gateway key cannot sign assignments", lambda: raises(
    SignatureVerificationError, lambda: sign_object(signed.without_signature(), world.gateway_signer, now=NOW)))
check("signed registry verifies", lambda: world.registry.verify_integrity(world.trust_store, NOW))


def registry_tamper():
    entry = world.registry._definitions["case_action"][(1, 0, 0)]
    world.registry._definitions["case_action"][(1, 0, 0)] = entry.model_copy(update={"enabled_status": True})
    try:
        return raises(RegistryIntegrityError, lambda: world.registry.verify_integrity(world.trust_store, NOW))
    finally:
        world.registry._definitions["case_action"][(1, 0, 0)] = entry


check("registry tampering is detected", registry_tamper)


def receipt_on_p0_double():
    scenario = build_scenarios()[0]
    tools = build_toolbox(scenario)
    request = ToolRequest(request_id="REQ-1", mission_id=signed.mission_id, assignment_id=signed.assignment_id,
                          worker_id=signed.worker_id, tool_id="log_search", operation_id="search",
                          arguments={"host": scenario.investigation["scope"]["host"]}, requested_at=NOW,
                          correlation_id="CORR-1", sequence_number=0)
    result, receipt = call_double_with_receipt(tools.log_search, request, world.registry.get("log_search"),
                                               receipt_id="RCPT-1", signer=world.gateway_signer,
                                               policy_version=POLICY, clock=world.clock)
    verify_object(receipt, world.trust_store, now=NOW)
    return bool(result["results"]) and len(tools.case_action.attempt_log) == 0


check("P0 tool double call produces a verifiable signed receipt", receipt_on_p0_double)


def dev_keys_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        env = {"GAMIS_ENV": "development", "GAMIS_DEV_KEY_DIR": tmp}
        key_id = DevKeyStore(environ=env).create_key("tool-gateway", GATEWAY, (SignedObjectType.TOOL_RECEIPT,), NOW).key_id
        return DevKeyStore(environ=env).current("tool-gateway").key_id == key_id


check("development key store persists keys outside the repo", dev_keys_roundtrip)
check("development key store refuses a production environment", lambda: raises(
    Exception, lambda: DevKeyStore("/tmp/gamis-should-not-exist", environ={"GAMIS_ENV": "production"})))

print(f"\n{'ALL P1 CHECKS PASSED' if not failures else f'{failures} P1 CHECK(S) FAILED'}")
sys.exit(1 if failures else 0)
