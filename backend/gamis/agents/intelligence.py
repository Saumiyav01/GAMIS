"""Deterministic, provenance-preserving evidence correlation and claim assessment."""
from __future__ import annotations

import re
from collections import defaultdict

from gamis.agents.intelligence_models import (ConfidenceAssessment, ContradictionType, EvidenceContradiction,
                                              EvidenceCorrelation, EvidenceIntelligenceReport, VerificationStatus,
                                              VerifiedClaim)
from gamis.agents.models import LLMClaim, WorkerReport
from gamis.schemas.common import require_unique
from gamis.schemas.evidence import EvidenceItem
from gamis.security.digest import canonical_digest


class EvidenceIntelligence:
    def __init__(self, evidence_store):
        self._evidence = evidence_store

    def analyze(self, mission_id: str, reports: tuple[WorkerReport, ...],
                final_claims: tuple[LLMClaim, ...] = ()) -> EvidenceIntelligenceReport:
        items: dict[str, EvidenceItem] = {}
        bundles = []
        receipt_ids: set[str] = set()
        gaps: list[str] = []
        for report in reports:
            bundle = self._evidence.get_bundle(report.evidence_bundle_id, purpose="evidence intelligence")
            if bundle.mission_id != mission_id or bundle.worker_id != report.worker_id:
                raise ValueError(f"worker report {report.task_id} does not match its signed evidence bundle")
            bundle_items = {item.evidence_id: item for item in bundle.evidence_items}
            if set(bundle_items) != set(report.evidence_ids):
                raise ValueError(f"worker report {report.task_id} evidence differs from its signed bundle")
            if set(bundle.referenced_tool_receipts) != set(report.receipt_ids):
                raise ValueError(f"worker report {report.task_id} receipts differ from its signed bundle")
            report_claims = tuple((claim.statement, claim.confidence, claim.supporting_evidence_ids,
                                   claim.contradicting_evidence_ids, claim.rationale) for claim in report.claims)
            bundle_claims = tuple((claim.statement, claim.confidence, claim.supporting_evidence_ids,
                                   claim.contradicting_evidence_ids, claim.rationale) for claim in bundle.claims)
            if report_claims != bundle_claims:
                raise ValueError(f"worker report {report.task_id} claims differ from its signed bundle")
            for receipt_id in bundle.referenced_tool_receipts:
                receipt = self._evidence.get_receipt(receipt_id)
                if receipt.mission_id != mission_id or receipt.worker_id != report.worker_id:
                    raise ValueError(f"receipt {receipt_id} is outside the worker's mission provenance")
                receipt_ids.add(receipt_id)
            items.update(bundle_items)
            bundles.append((report, bundle))
            gaps.extend(report.missing_information)
            gaps.extend(report.limitations)

        for evidence_id in self._evidence.list_evidence_ids(mission_id=mission_id):
            if evidence_id not in items:
                items[evidence_id] = self._evidence.get_evidence(
                    evidence_id, purpose="evidence intelligence inventory")
                gaps.append(f"Evidence {evidence_id} is persisted but is not included in a signed worker bundle.")
        stored_receipts = set(self._evidence.list_receipt_ids(mission_id=mission_id))
        if not receipt_ids <= stored_receipts:
            raise ValueError("signed worker bundles reference a receipt absent from the mission evidence store")
        for receipt_id in stored_receipts - receipt_ids:
            receipt = self._evidence.get_receipt(receipt_id)
            if receipt.mission_id != mission_id:
                raise ValueError(f"receipt {receipt_id} is outside the mission evidence store")
            receipt_ids.add(receipt_id)
            gaps.append(f"Receipt {receipt_id} is persisted but is not referenced by a completed worker bundle.")

        correlations = self._correlate(items.values())
        claim_assessments: list[VerifiedClaim] = []
        contradictions: list[EvidenceContradiction] = []
        supporting: set[str] = set()
        contradicting: set[str] = set()
        for report, bundle in bundles:
            for claim in bundle.claims:
                refs = set(claim.supporting_evidence_ids) | set(claim.contradicting_evidence_ids)
                if not refs <= set(items):
                    raise ValueError(f"claim {claim.claim_id} references evidence not in the persisted mission")
                supporting.update(claim.supporting_evidence_ids)
                contradicting.update(claim.contradicting_evidence_ids)
                claim_id = "CLM-" + canonical_digest({
                    "mission_id": mission_id, "worker_id": report.worker_id, "task_id": report.task_id,
                    "statement": claim.statement, "supporting": claim.supporting_evidence_ids,
                    "contradicting": claim.contradicting_evidence_ids,
                })[:24]
                assessed, confidence = self._assess_claim(
                    claim_id, claim.statement, claim.confidence, claim.supporting_evidence_ids,
                    claim.contradicting_evidence_ids, items, (report.worker_id,), claim.rationale,
                    bool(report.missing_information))
                claim_assessments.append(assessed)
                if claim.disputed or (claim.supporting_evidence_ids and claim.contradicting_evidence_ids):
                    contradictions.append(EvidenceContradiction(
                        contradiction_id="CON-" + canonical_digest({
                            "claim_id": claim_id, "supporting": claim.supporting_evidence_ids,
                            "contradicting": claim.contradicting_evidence_ids,
                        })[:24],
                        contradiction_type=ContradictionType.DIRECT_CONTRADICTION,
                        description=f"Claim remains disputed: {claim.statement}",
                        evidence_ids=tuple(dict.fromkeys((*claim.supporting_evidence_ids,
                                                          *claim.contradicting_evidence_ids))),
                        claim_ids=(claim_id,)))

        for index, claim in enumerate(final_claims):
            refs = set(claim.supporting_evidence_ids) | set(claim.contradicting_evidence_ids)
            if not refs or not refs <= set(items):
                raise ValueError("final assessment claim has missing or unavailable persisted evidence")
            claim_id = "CLM-" + canonical_digest({
                "mission_id": mission_id, "worker_id": "supervisor-local", "index": index,
                "statement": claim.statement, "supporting": claim.supporting_evidence_ids,
                "contradicting": claim.contradicting_evidence_ids,
            })[:24]
            assessed, _ = self._assess_claim(
                claim_id, claim.statement, claim.confidence, claim.supporting_evidence_ids,
                claim.contradicting_evidence_ids, items, ("supervisor-local",), claim.rationale,
                False)
            claim_assessments.append(assessed)
            if claim.supporting_evidence_ids and claim.contradicting_evidence_ids:
                contradictions.append(EvidenceContradiction(
                    contradiction_id="CON-" + canonical_digest({"claim_id": claim_id})[:24],
                    contradiction_type=ContradictionType.DIRECT_CONTRADICTION,
                    description=f"Final assessment claim remains disputed: {claim.statement}",
                    evidence_ids=tuple(dict.fromkeys((*claim.supporting_evidence_ids,
                                                      *claim.contradicting_evidence_ids))),
                    claim_ids=(claim_id,)))

        contradictions.extend(self._source_contradictions(items.values()))
        contradictions.extend(self._cross_claim_contradictions(claim_assessments))
        for contradiction in contradictions:
            gaps.append(contradiction.description)
        if not claim_assessments:
            gaps.append("No worker claim could be verified against persisted evidence.")

        all_evidence_ids = tuple(sorted(items))
        all_receipt_ids = tuple(sorted(receipt_ids))
        require_unique(all_evidence_ids, "mission evidence ID")
        require_unique(all_receipt_ids, "mission receipt ID")
        return EvidenceIntelligenceReport(
            evidence_count=len(all_evidence_ids), receipt_ids=all_receipt_ids,
            evidence_correlations=tuple(correlations), contradictions=tuple(contradictions),
            verified_claims=tuple(claim_assessments), evidence_gaps=tuple(dict.fromkeys(gaps)),
            supporting_evidence_ids=tuple(sorted(supporting)),
            contradicting_evidence_ids=tuple(sorted(contradicting)),
            limitations=("Evidence strength is deterministic and separate from model confidence.",
                         "Contradictions are retained; this layer does not resolve them."),
        )

    def _correlate(self, items) -> list[EvidenceCorrelation]:
        groups: dict[str, list[EvidenceItem]] = defaultdict(list)
        for item in items:
            groups[item.integrity_digest].append(item)
        correlations = []
        for digest, group in sorted(groups.items()):
            if len(group) < 2:
                continue
            workers = set()
            for item in group:
                links = self._evidence.evidence_links(item.evidence_id)
                for _, _, worker_id, _ in links:
                    workers.add(worker_id)
                if not links:
                    workers.add(item.provenance.collected_by)
            evidence_ids = tuple(sorted(item.evidence_id for item in group))
            correlations.append(EvidenceCorrelation(
                correlation_id="COR-" + digest[:24], content_digest=digest, evidence_ids=evidence_ids,
                source_record_ids=tuple(sorted({item.source_record_id for item in group if item.source_record_id})),
                worker_ids=tuple(sorted(workers)),
                receipt_ids=tuple(sorted({item.receipt_id for item in group if item.receipt_id})),
                timestamps=tuple(sorted({item.timestamp.isoformat() for item in group})),
                explanation="Identical content digests occur in multiple evidence records; originals are retained.",
            ))
        return correlations

    @staticmethod
    def _assess_claim(claim_id, statement, model_confidence, supporting_ids, contradicting_ids, items,
                      worker_ids, rationale, has_missing_information):
        supporting = [items[eid] for eid in supporting_ids]
        contradicting = [items[eid] for eid in contradicting_ids]
        cited = supporting + contradicting
        if not cited:
            status = VerificationStatus.UNVERIFIED
        elif not supporting and contradicting:
            status = VerificationStatus.CONTRADICTED
        elif supporting and contradicting:
            status = VerificationStatus.PARTIALLY_SUPPORTED
        elif has_missing_information:
            status = VerificationStatus.PARTIALLY_SUPPORTED
        else:
            status = VerificationStatus.SUPPORTED
        relevance = len(supporting) / len(cited) if cited else 0.0
        reliability = (sum(item.source_type.value == "TOOL_RESULT" and item.receipt_id is not None
                           for item in supporting) / len(supporting) if supporting else 0.0)
        independent_sources = {
            items[evidence_id].source for evidence_id in supporting_ids
        }
        independent = min(1.0, len(independent_sources) / 2.0) if supporting else 0.0
        contradiction_factor = len(contradicting) / len(cited) if cited else 1.0
        completeness = 0.5 if has_missing_information else 1.0
        base = (0.30 * relevance + 0.25 * reliability + 0.20 * independent
                + 0.15 * completeness + 0.10 * (1.0 - contradiction_factor))
        evidence_strength = max(0.0, min(1.0, base * (1.0 - 0.6 * contradiction_factor)))
        confidence = ConfidenceAssessment(
            evidence_strength=evidence_strength, model_confidence=model_confidence,
            relevance=relevance, reliability=reliability, independent_corroboration=independent,
            contradiction_factor=contradiction_factor, completeness=completeness,
            rationale=(f"Evidence score={evidence_strength:.3f}; relevance={relevance:.3f}, "
                       f"receipt-backed reliability={reliability:.3f}, independent corroboration={independent:.3f}, "
                       f"contradiction factor={contradiction_factor:.3f}, completeness={completeness:.3f}. "
                       f"Model confidence ({model_confidence:.3f}) is reported separately. {rationale}")[:4000],
        )
        provenance_by_id = {item.provenance.provenance_id: item.provenance
                            for item in (*supporting, *contradicting)}
        provenance = tuple(provenance_by_id[key] for key in sorted(provenance_by_id))
        claim = VerifiedClaim(
            claim_id=claim_id, description=statement, supporting_evidence_ids=tuple(supporting_ids),
            contradicting_evidence_ids=tuple(contradicting_ids), verification_status=status,
            confidence=evidence_strength, confidence_assessment=confidence, provenance=provenance,
            worker_ids=tuple(worker_ids), explanation=rationale)
        return claim, confidence

    @staticmethod
    def _source_contradictions(items) -> list[EvidenceContradiction]:
        by_record: dict[str, list[EvidenceItem]] = defaultdict(list)
        for item in items:
            if item.source_record_id:
                by_record[item.source_record_id].append(item)
        found = []
        for record_id, group in by_record.items():
            digests = {item.integrity_digest for item in group}
            timestamps = {item.timestamp for item in group}
            kind = None
            if len(timestamps) > 1:
                kind = ContradictionType.TEMPORAL_INCONSISTENCY
            elif len(digests) > 1:
                kind = ContradictionType.SOURCE_DISAGREEMENT
            if kind is not None:
                found.append(EvidenceContradiction(
                    contradiction_id="CON-" + canonical_digest(
                        {"record": record_id, "type": kind.value,
                         "items": sorted(item.evidence_id for item in group)})[:24],
                    contradiction_type=kind,
                    description=f"Source record {record_id} has conflicting content or timestamps; neither version was removed.",
                    evidence_ids=tuple(sorted(item.evidence_id for item in group))))
        return found

    @staticmethod
    def _cross_claim_contradictions(claims: list[VerifiedClaim]) -> list[EvidenceContradiction]:
        grouped: dict[str, list[VerifiedClaim]] = defaultdict(list)
        for claim in claims:
            normalized = re.sub(r"\W+", " ", claim.description.casefold()).strip()
            grouped[normalized].append(claim)
        found = []
        for statement, group in grouped.items():
            if len(group) < 2:
                continue
            supports = {eid for claim in group for eid in claim.supporting_evidence_ids}
            contradicts = {eid for claim in group for eid in claim.contradicting_evidence_ids}
            if supports & contradicts:
                claim_ids = tuple(sorted(claim.claim_id for claim in group))
                evidence_ids = tuple(sorted(supports | contradicts))
                found.append(EvidenceContradiction(
                    contradiction_id="CON-" + canonical_digest({"statement": statement, "claims": claim_ids})[:24],
                    contradiction_type=ContradictionType.DIRECT_CONTRADICTION,
                    description="Workers cite the same claim with conflicting evidence relations.",
                    evidence_ids=evidence_ids, claim_ids=claim_ids))
        return found
