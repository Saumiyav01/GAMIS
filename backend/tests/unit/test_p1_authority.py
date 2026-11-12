"""P1 Authority Service tests: containment, signing boundary, independent verification."""
from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from gamis.authority.containment import ViolationCode as C, check_assignment_within_grant
from gamis.authority.service import AssignmentProposalPort, AssignmentRejected, AuthorityService
from gamis.authority.verification import AssignmentVerificationError, AssignmentVerifier
from gamis.schemas import AgentAssignment, MissionGrant, MissionState, PolicyVersion, SignedObjectType
from gamis.security import signing
from gamis.security.keys import Ed25519Signer, KeyManagementError, Signer, TrustStore, trusted_key_for
from gamis.security.signing import sign_object, verify_object
from tests.p1_support import (ACTION_OP, AUTHORITY, EVIDENCE_REQUIREMENT, NOW, POLICY, READ_OPS, REGISTRY_ADMIN,
                              SUPERVISOR, action_assignment, assignment_dict, build_trust_world, grant_dict,
                              iso)


def rejected_codes(world, grant=None, **overrides) -> set[C]:
    with pytest.raises(AssignmentRejected) as info:
        world.authority.issue_assignment(assignment_dict(world.clock.now, **overrides), grant or world.grant)
    assert not info.value.decision.approved
    return info.value.decision.codes


INTEL = dict(assignment_id="ASG-002", worker_id="worker-intel-1", worker_role="intel-analyst",
             permitted_tools=["intel_lookup"], permitted_operations=[READ_OPS[1]],
             tool_call_limits=[{"tool_id": "intel_lookup", "max_calls": 5}])


# --- happy path ---------------------------------------------------------------------------------

def test_valid_assignment_is_signed_by_the_authority():
    world = build_trust_world()
    assert world.authority.evaluate(assignment_dict(), world.grant).approved
    signed = world.issue()
    meta = signed.signature_metadata
    assert meta.signer_identity == AUTHORITY and meta.object_type is SignedObjectType.AGENT_ASSIGNMENT
    assert meta.signed_at == NOW
    assert signed.signed_payload() == AgentAssignment.model_validate(assignment_dict()).signed_payload()
    assert world.verifier.verify(signed, world.grant).key.key_name == "authority-assignment"
    assert world.ledger.issued("GRANT-001") == (signed,)


def test_evaluate_does_not_sign_or_record():
    world = build_trust_world()
    decision = world.authority.evaluate(assignment_dict(), world.grant)
    assert decision.approved and decision.violations == () and world.ledger.issued("GRANT-001") == ()


def test_multiple_independent_worker_assignments():
    world = build_trust_world(enable_action_tool=True)
    reader, intel = world.issue(), world.issue(**INTEL)
    responder = world.issue(**action_assignment())
    assert {a.worker_id for a in (reader, intel, responder)} == {"worker-reader-1", "worker-intel-1",
                                                                  "worker-responder-1"}
    for a in (reader, intel, responder):
        world.verifier.verify(a, world.grant)
    assert reader.permission_for("intel_lookup", "lookup") is None      # authority is per assignment
    assert intel.permission_for("log_search", "search") is None
    assert responder.permission_class.value == "ACTION" and reader.permission_class.value == "READ"
    assert len({a.signature_metadata.signature for a in (reader, intel, responder)}) == 3


# --- rejections ---------------------------------------------------------------------------------

def test_unauthorized_worker_rejected():
    world = build_trust_world()
    assert rejected_codes(world, worker_id="worker-unknown-9") == {C.UNKNOWN_WORKER}
    assert rejected_codes(world, worker_id="worker-disabled-1") == {C.WORKER_DISABLED}
    assert world.ledger.issued("GRANT-001") == ()


def test_unauthorized_role_rejected():
    world = build_trust_world()
    # the worker's registered role is not the one claimed
    assert rejected_codes(world, worker_role="intel-analyst") == {C.WORKER_ROLE_MISMATCH}
    # a role the grant does not permit, even for a worker that really holds it
    grant = world.sign_grant(permitted_roles=["intel-analyst", "responder"])
    assert rejected_codes(world, grant=grant) == {C.ROLE_NOT_PERMITTED}
    assert C.ROLE_NOT_PERMITTED in rejected_codes(world, worker_role="mission-admin")


def test_unauthorized_tool_rejected():
    world = build_trust_world()
    grant = world.sign_grant(permitted_tools=["intel_lookup", "case_action"],
                             permitted_operations=[READ_OPS[1], ACTION_OP])
    assert rejected_codes(world, grant=grant) == {C.TOOL_NOT_PERMITTED, C.OPERATION_NOT_PERMITTED}
    # a tool the registry has never heard of
    op = {"tool_id": "shell", "operation_id": "run", "permission_class": "READ"}
    codes = rejected_codes(world, permitted_tools=["shell"], permitted_operations=[op],
                           tool_call_limits=[{"tool_id": "shell", "max_calls": 1}])
    assert codes == {C.TOOL_NOT_PERMITTED, C.OPERATION_NOT_PERMITTED, C.TOOL_NOT_REGISTERED}
    # registered and granted, but disabled in the registry (case_action is disabled by default, as in P0)
    assert rejected_codes(world, **action_assignment()) == {C.TOOL_DISABLED}


def test_unauthorized_operation_rejected():
    world = build_trust_world()
    op = {"tool_id": "log_search", "operation_id": "delete", "permission_class": "READ"}
    assert rejected_codes(world, permitted_operations=[op]) == {C.OPERATION_NOT_PERMITTED, C.OPERATION_NOT_SUPPORTED}
    # granted by a (careless) grant but not a registered operation of the tool
    grant = world.sign_grant(permitted_operations=[*READ_OPS, ACTION_OP, op])
    assert rejected_codes(world, grant=grant, permitted_operations=[op]) == {C.OPERATION_NOT_SUPPORTED}


def test_read_cannot_become_action():
    world = build_trust_world(enable_action_tool=True)
    act = dict(permitted_tools=["case_action"], permitted_operations=[ACTION_OP],
               tool_call_limits=[{"tool_id": "case_action", "max_calls": 1}], forbidden_actions=[])
    # 1. READ assignment listing an ACTION operation: rejected as malformed before any signing
    assert rejected_codes(world, **act) == {C.MALFORMED_PROPOSAL}
    # 2. ACTION operation relabelled as READ to slip under a READ assignment
    relabelled = {**ACTION_OP, "permission_class": "READ"}
    assert rejected_codes(world, **{**act, "permitted_operations": [relabelled]}) == {C.PERMISSION_CLASS_ESCALATION}
    # 3. even if the grant itself mislabels the operation as READ, the registry's classification wins
    grant = world.sign_grant(permitted_operations=[*READ_OPS, relabelled])
    assert rejected_codes(world, grant=grant, **{**act, "permitted_operations": [relabelled]}) == {
        C.PERMISSION_CLASS_ESCALATION}
    # 4. READ-only grant: ACTION assignments are refused, READ ones still work (validated independently)
    read_grant = world.sign_grant(permitted_tools=["log_search", "intel_lookup"], permitted_operations=READ_OPS,
                                  permitted_permission_classes=["READ"], approval_requirements=[])
    codes = rejected_codes(world, grant=read_grant, **action_assignment())
    assert {C.PERMISSION_CLASS_NOT_GRANTED, C.TOOL_NOT_PERMITTED, C.OPERATION_NOT_PERMITTED} <= codes
    # raising only the ceiling of a READ assignment is itself malformed
    assert rejected_codes(world, grant=read_grant, permission_class="ACTION") == {C.MALFORMED_PROPOSAL}
    assert rejected_codes(world, permission_class="ACTION") == {C.MALFORMED_PROPOSAL}
    assert world.authority.issue_assignment(assignment_dict(), read_grant).permission_class.value == "READ"
    # 5. malformed permission input never falls back to a default
    for bad in ("read", None, ["READ", "ACTION"], 1):
        assert rejected_codes(world, assignment_id="ASG-X", permission_class=bad) == {C.MALFORMED_PROPOSAL}
    proposal = assignment_dict(assignment_id="ASG-X")
    del proposal["permission_class"]
    with pytest.raises(AssignmentRejected) as info:
        world.authority.issue_assignment(proposal, world.grant)
    assert info.value.decision.codes == {C.MALFORMED_PROPOSAL}
    # 6. a signed READ assignment edited to ACTION afterwards no longer verifies
    signed = world.issue(assignment_id="ASG-READ")
    with pytest.raises(AssignmentVerificationError) as err:
        world.verifier.verify(signed.model_copy(update={"permission_class": "ACTION"}))
    assert err.value.codes == {C.ASSIGNMENT_SIGNATURE_INVALID}


@pytest.mark.parametrize("dimension,value", [("max_tool_calls", 101), ("max_wall_clock_seconds", 3601),
                                             ("max_tokens", 100_001), ("max_cost_units", 1001),
                                             ("max_evidence_bytes", 1_000_001)])
def test_resource_ceiling_violation_rejected(dimension, value):
    world = build_trust_world()
    limits = {**assignment_dict()["resource_limits"], dimension: value}
    assert rejected_codes(world, resource_limits=limits) == {C.RESOURCE_LIMIT_EXCEEDED}
    at_ceiling = {**assignment_dict()["resource_limits"], dimension: value - 1}
    assert world.issue(resource_limits=at_ceiling).resource_limits.model_dump()[dimension] == value - 1


def test_cumulative_budget_and_worker_count_are_bounded_by_the_grant():
    world = build_trust_world()
    big = {**assignment_dict()["resource_limits"], "max_tool_calls": 60}
    limit = [{"tool_id": "log_search", "max_calls": 20}]
    world.issue(resource_limits=big, tool_call_limits=limit)
    # 60 + 60 tool calls > grant ceiling of 100
    intel_limits = [{"tool_id": "intel_lookup", "max_calls": 5}]
    assert rejected_codes(world, **{**INTEL, "resource_limits": big, "tool_call_limits": intel_limits}) == {
        C.RESOURCE_LIMIT_EXCEEDED}
    assert rejected_codes(world) == {C.DUPLICATE_ASSIGNMENT}       # same assignment_id again
    world.issue(**INTEL)
    world.issue(assignment_id="ASG-002b", worker_id="worker-intel-1", worker_role="intel-analyst")  # same worker: ok
    grant2 = world.sign_grant(grant_id="GRANT-002", maximum_worker_count=1,
                              revocation_reference="REVOCATION-GRANT-002")
    world.status.activate(grant2, world.clock.now)
    world.authority.issue_assignment(assignment_dict(grant_id="GRANT-002"), grant2)
    with pytest.raises(AssignmentRejected) as info:
        world.authority.issue_assignment(assignment_dict(**{**INTEL, "grant_id": "GRANT-002"}), grant2)
    assert info.value.decision.codes == {C.WORKER_COUNT_EXCEEDED}


def test_expired_assignment_rejected():
    world = build_trust_world()
    past = dict(issued_at=iso(NOW - timedelta(minutes=30)), expires_at=iso(NOW - timedelta(minutes=1)))
    assert rejected_codes(world, **past) == {C.ASSIGNMENT_EXPIRED}
    assert rejected_codes(world, expires_at=iso(NOW + timedelta(hours=9))) == {C.ASSIGNMENT_OUTLIVES_GRANT}
    future = dict(issued_at=iso(NOW + timedelta(minutes=10)), expires_at=iso(NOW + timedelta(minutes=20)))
    assert rejected_codes(world, **future) == {C.ASSIGNMENT_NOT_YET_VALID}
    before_grant = dict(issued_at=iso(NOW - timedelta(hours=2)))
    assert rejected_codes(world, **before_grant) == {C.ASSIGNMENT_NOT_YET_VALID}
    # a validly signed assignment stops verifying once it expires
    signed = world.issue()
    world.verifier.verify(signed)
    world.clock.advance(hours=1)
    with pytest.raises(AssignmentVerificationError) as err:
        world.verifier.verify(signed)
    assert err.value.codes == {C.ASSIGNMENT_EXPIRED}


def test_expired_revoked_or_inactive_grant_rejected():
    world = build_trust_world()
    world.clock.advance(hours=9)                                   # past grant expiry
    late = dict(issued_at=iso(NOW), expires_at=iso(NOW + timedelta(hours=1)))
    assert C.GRANT_EXPIRED in rejected_codes(world, **late)
    with pytest.raises(AssignmentVerificationError) as err:
        world.verifier.verify_grant(world.grant)
    assert err.value.codes == {C.GRANT_EXPIRED}

    world = build_trust_world()
    world.status.revoke("GRANT-001", NOW, "operator revoked the mission")
    assert rejected_codes(world) == {C.GRANT_REVOKED}
    assert world.grant.signature_metadata is not None              # the signed grant itself is untouched
    world.status.set_state("GRANT-001", MissionState.SUSPENDED, NOW, "paused")
    assert rejected_codes(world) == {C.GRANT_NOT_ACTIVE}

    world = build_trust_world()
    unknown = world.sign_grant(grant_id="GRANT-UNTRACKED")         # no runtime status recorded: deny by default
    assert C.GRANT_NOT_ACTIVE in rejected_codes(world, grant=unknown, grant_id="GRANT-UNTRACKED")
    post_dated = MissionGrant.model_validate(grant_dict(issued_at=iso(NOW + timedelta(hours=1)),
                                                        expires_at=iso(NOW + timedelta(hours=5))))
    post_dated = post_dated.with_signature(sign_object(post_dated, world.issuer_signer, now=NOW))
    assert C.GRANT_NOT_YET_VALID in rejected_codes(world, grant=post_dated)


def test_grant_authenticity_is_verified():
    world, other = build_trust_world(), build_trust_world()
    assert rejected_codes(world, grant=world.grant.without_signature()) == {C.GRANT_SIGNATURE_INVALID}
    assert rejected_codes(world, grant=other.grant) == {C.GRANT_SIGNATURE_INVALID}    # unknown issuer key
    widened = world.grant.model_copy(update={"maximum_worker_count": 999})
    assert rejected_codes(world, grant=widened) == {C.GRANT_SIGNATURE_INVALID}
    # the authority's own key cannot be used to mint grants
    with pytest.raises(signing.KeyNotAuthorizedError):
        sign_object(world.grant.without_signature(), world.authority._AuthorityService__signer, now=NOW)
    # a grant naming a different issuer than the key that signed it
    impostor = {"principal_id": "mission-issuer-2", "principal_type": "MISSION_ISSUER"}
    assert rejected_codes(world, grant=world.sign_grant(issuer_identity=impostor)) == {C.GRANT_SIGNATURE_INVALID}


def test_policy_version_is_validated():
    world = build_trust_world()
    other = {"policy_id": POLICY.policy_id, "version": "2.0.0"}
    assert rejected_codes(world, policy_version=other) == {C.POLICY_VERSION_MISMATCH}
    assert C.POLICY_VERSION_MISMATCH in rejected_codes(world, grant=world.sign_grant(policy_version=other))
    assert rejected_codes(world, grant=world.sign_grant(policy_version=other), policy_version=other) == {
        C.POLICY_VERSION_MISMATCH}                                 # consistent with each other, but not active


def test_evidence_requirements_cannot_be_dropped_or_weakened():
    world = build_trust_world()
    assert rejected_codes(world, required_evidence=[]) == {C.EVIDENCE_REQUIREMENT_WEAKENED}
    weaker = {**EVIDENCE_REQUIREMENT, "require_tool_receipts": False}
    assert rejected_codes(world, required_evidence=[weaker]) == {C.EVIDENCE_REQUIREMENT_WEAKENED}
    wider = {**EVIDENCE_REQUIREMENT, "accepted_source_types": ["TOOL_RESULT", "HUMAN_INPUT"]}
    assert rejected_codes(world, required_evidence=[wider]) == {C.EVIDENCE_REQUIREMENT_WEAKENED}
    stricter = {**EVIDENCE_REQUIREMENT, "minimum_items": 3}
    assert world.issue(required_evidence=[stricter]).required_evidence[0].minimum_items == 3


def test_mismatched_grant_reference_and_malformed_proposals_rejected():
    world = build_trust_world()
    assert rejected_codes(world, mission_id="MIS-999") == {C.GRANT_MISMATCH}
    assert rejected_codes(world, grant_id="GRANT-999") == {C.GRANT_MISMATCH}
    for bad in ("not a mapping", None, 42, {"assignment_id": "only-this"}):
        with pytest.raises(AssignmentRejected) as info:
            world.authority.issue_assignment(bad, world.grant)
        assert info.value.decision.codes == {C.MALFORMED_PROPOSAL}
    assert rejected_codes(world, is_admin=True) == {C.MALFORMED_PROPOSAL}
    assert world.ledger.issued("GRANT-001") == ()


def test_all_violations_are_reported_together():
    world = build_trust_world()
    limits = {**assignment_dict()["resource_limits"], "max_tokens": 10**6}
    codes = rejected_codes(world, worker_id="worker-unknown-9", resource_limits=limits,
                           expires_at=iso(NOW + timedelta(hours=20)), required_evidence=[])
    assert codes == {C.UNKNOWN_WORKER, C.RESOURCE_LIMIT_EXCEEDED, C.ASSIGNMENT_OUTLIVES_GRANT,
                     C.EVIDENCE_REQUIREMENT_WEAKENED}


def test_registry_integrity_is_required():
    world = build_trust_world()
    world.registry.set_enabled("intel_lookup", "1.0.0", False, actor=REGISTRY_ADMIN)   # change without re-sealing
    assert rejected_codes(world) == {C.REGISTRY_INTEGRITY}
    world.registry.seal(world.registry_signer, NOW)
    assert world.issue().is_signed


# --- signing boundary ---------------------------------------------------------------------------

def test_modified_assignment_rejected():
    world = build_trust_world()
    signed = world.issue()
    edits = [{"permitted_tools": ("log_search", "intel_lookup")}, {"worker_id": "worker-intel-1"},
             {"expires_at": signed.expires_at + timedelta(hours=5)},
             {"resource_limits": signed.resource_limits.model_copy(update={"max_tool_calls": 100})},
             {"forbidden_actions": ()}]
    for edit in edits:
        with pytest.raises(AssignmentVerificationError) as err:
            world.verifier.verify(signed.model_copy(update=edit), world.grant)
        assert err.value.codes == {C.ASSIGNMENT_SIGNATURE_INVALID}
    with pytest.raises(AssignmentVerificationError):
        world.verifier.verify(signed.without_signature())
    # re-submitting an already signed (or edited-and-still-signed) assignment as a proposal is refused
    with pytest.raises(AssignmentRejected) as info:
        world.authority.issue_assignment(signed.model_copy(update={"assignment_id": "ASG-777"}), world.grant)
    assert info.value.decision.codes == {C.PROPOSAL_ALREADY_SIGNED}


def test_supervisor_cannot_sign_assignments_independently():
    world = build_trust_world()
    proposal = AgentAssignment.model_validate(assignment_dict(assignment_id="ASG-SUP"))
    supervisor_key = Ed25519Signer(Ed25519PrivateKey.generate(), key_name="supervisor", key_version=1,
                                   principal=SUPERVISOR)
    # 1. a SUPERVISOR principal is refused by the signing primitive itself
    with pytest.raises(signing.KeyNotAuthorizedError):
        sign_object(proposal, supervisor_key, now=NOW)
    # 2. a supervisor key can never be registered as an assignment-signing key
    with pytest.raises(ValidationError, match="may not sign"):
        trusted_key_for(supervisor_key, (SignedObjectType.AGENT_ASSIGNMENT,), NOW)
    # 3. impersonating the authority with a self-generated key fails verification everywhere
    impostor = Ed25519Signer(Ed25519PrivateKey.generate(), key_name="authority-assignment", key_version=1,
                             principal=AUTHORITY)
    self_signed = proposal.with_signature(sign_object(proposal, impostor, now=NOW))
    with pytest.raises(AssignmentVerificationError) as err:
        world.verifier.verify(self_signed, world.grant)
    assert err.value.codes == {C.ASSIGNMENT_SIGNATURE_INVALID}
    # 4. the authority will not launder a self-signed proposal
    with pytest.raises(AssignmentRejected) as info:
        world.authority.issue_assignment(self_signed, world.grant)
    assert info.value.decision.codes == {C.PROPOSAL_ALREADY_SIGNED}
    # 5. the Authority Service cannot be built around a non-authority or untrusted key
    common = dict(trust_store=world.trust_store, registry=world.registry, workers=world.workers,
                  grant_status=world.status, active_policy=POLICY, clock=world.clock)
    for bad_signer in (supervisor_key, impostor, world.gateway_signer, world.issuer_signer):
        with pytest.raises(KeyManagementError):
            AuthorityService(signer=bad_signer, **common)
    # 6. the surface a supervisor receives has no signing capability and exposes no signer
    port: AssignmentProposalPort = world.authority
    public = [n for n in dir(port) if not n.startswith("_")]
    assert sorted(public) == ["evaluate", "grant_violations", "issue_assignment"]
    assert not any(isinstance(getattr(port, n), Signer) for n in public)
    assert [n for n in dir(AssignmentProposalPort) if not n.startswith("_")] == ["issue_assignment"]
    # 7. the legitimate path still works for the same proposal
    assert world.verifier.verify(world.authority.issue_assignment(proposal, world.grant), world.grant)


def test_signed_assignments_verify_independently_of_the_authority_service():
    world = build_trust_world()
    signed_json = world.issue().model_dump_json()
    grant_json = world.grant.model_dump_json()
    # A separate component (e.g. the future gateway) holding only public key records:
    public_records = tuple(type(k).model_validate_json(k.model_dump_json()) for k in world.trust_store.all())
    gateway_side = AssignmentVerifier(TrustStore(public_records), lambda: NOW)
    assignment = AgentAssignment.model_validate_json(signed_json)
    grant = MissionGrant.model_validate_json(grant_json)
    verified = gateway_side.verify(assignment, grant)
    assert verified.metadata.signer_identity == AUTHORITY and verified.object_type is SignedObjectType.AGENT_ASSIGNMENT
    assert check_assignment_within_grant(assignment, grant) == []
    # with only the issuer key trusted, the assignment is not accepted
    issuer_only = TrustStore(tuple(k for k in public_records if k.key_name == "mission-issuer"))
    with pytest.raises(AssignmentVerificationError):
        AssignmentVerifier(issuer_only, lambda: NOW).verify(assignment, grant)
    # the verifier re-checks containment against whichever grant it is shown
    narrow = world.sign_grant(permitted_tools=["intel_lookup"], permitted_operations=[READ_OPS[1]],
                              permitted_permission_classes=["READ"], approval_requirements=[])
    with pytest.raises(AssignmentVerificationError) as err:
        gateway_side.verify(assignment, MissionGrant.model_validate_json(narrow.model_dump_json()))
    assert err.value.codes == {C.TOOL_NOT_PERMITTED, C.OPERATION_NOT_PERMITTED}
    verify_object(assignment, TrustStore(public_records), now=NOW)
