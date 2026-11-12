"""Mission grant issuance helper (P2): sign a grant with a MISSION_ISSUER key and audit the issuance."""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from gamis.schemas.mission import MissionGrant
from gamis.security.keys import Signer
from gamis.security.signing import sign_object

if TYPE_CHECKING:
    from gamis.audit.recorder import AuditRecorder


def issue_mission_grant(grant: MissionGrant, signer: Signer, *, now: datetime,
                        recorder: "AuditRecorder | None" = None, new_mission: bool = True) -> MissionGrant:
    """Sign ``grant``. With a recorder, MISSION_CREATED (optional) and GRANT_ISSUED are written before the
    signed grant is returned; if auditing fails the grant is not released."""
    grant = grant.without_signature().revalidate()
    if signer.principal != grant.issuer_identity:
        raise ValueError("the signing key does not belong to the grant's issuer_identity")
    signed = grant.with_signature(sign_object(grant, signer, now=now))
    if recorder is not None:
        if new_mission:
            recorder.mission_created(signed)
        recorder.grant_issued(signed)
    return signed
