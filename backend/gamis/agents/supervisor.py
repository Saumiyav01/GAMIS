"""Supervisor orchestration boundary: proposes bounded assignments, never signs or executes tools."""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Callable, Mapping

from gamis.agents.models import (InvestigationReport, LLMClaim, LLMFinalAssessment, MissionPlan,
                                 MissionTask, WorkerReport)
from gamis.authority.service import AssignmentProposalPort
from gamis.llm.provider import LLMProvider
from gamis.schemas.assignment import AgentAssignment
from gamis.schemas.common import PermissionClass, Principal, PrincipalType
from gamis.schemas.mission import MissionGrant
from gamis.schemas.policy import ResourceLimits, StoppingCondition, ToolCallLimit

Clock = Callable[[], datetime]


class Supervisor:
    def __init__(self, *, provider: LLMProvider, model: str, authority: AssignmentProposalPort,
                 worker_by_role: Mapping[str, str], clock: Clock, provider_name: str = "ollama",
                 worker_model: str | None = None, worker_models: Mapping[str, str] | None = None):
        self._provider, self._model, self._authority = provider, model, authority
        self._workers, self._clock = dict(worker_by_role), clock
        self._provider_name, self._worker_model = provider_name, worker_model or model
        self._worker_models = dict(worker_models or {})
        self.identity = Principal(principal_id="supervisor-local", principal_type=PrincipalType.SUPERVISOR)

    def decompose(self, objective: str) -> MissionPlan:
        prompt = (
            "Decompose the investigation into a small dependency-ordered plan using only the supplied worker "
            "roles. Return task objectives and measurable success criteria; do not propose permissions, tool "
            "names, budgets, or actions. Available roles: evidence-reader, intel-analyst, responder.\n"
            f"Mission: {objective}"
        )
        plan = self._provider.generate_json(prompt, MissionPlan, model=self._model)
        unknown = [t.worker_role for t in plan.tasks if t.worker_role not in self._workers]
        if unknown:
            raise ValueError(f"Supervisor plan selected unavailable worker roles: {unknown}")
        roles = [task.worker_role for task in plan.tasks]
        required_roles = ["evidence-reader", "intel-analyst", "responder"]
        if roles != required_roles:
            raise ValueError("Supervisor must propose exactly one Research, Analysis, and Verification task in order")
        if (plan.tasks[0].depends_on or plan.tasks[1].task_id == plan.tasks[0].task_id
                or plan.tasks[0].task_id not in plan.tasks[1].depends_on
                or plan.tasks[1].task_id not in plan.tasks[2].depends_on):
            raise ValueError("Analysis and Verification tasks must depend on their preceding worker findings")
        return plan

    def issue_assignment(self, task: MissionTask, grant: MissionGrant) -> AgentAssignment:
        """Convert an LLM task into a fixed READ-only proposal; Authority alone signs it."""
        now = self._clock()
        operations = tuple(p for p in grant.permitted_operations if p.permission_class is PermissionClass.READ
                           and p.tool_id in {"log_search", "intel_lookup"})
        tools = tuple(sorted({p.tool_id for p in operations}))
        if not tools or not operations:
            raise ValueError("mission grant has no supported READ operations for synthetic investigation")
        assignment_id = f"ASG-{grant.mission_id}-{task.task_id}"
        proposal = AgentAssignment.model_validate({
            "assignment_id": assignment_id, "mission_id": grant.mission_id, "grant_id": grant.grant_id,
            "worker_id": self._workers[task.worker_role], "worker_role": task.worker_role,
            "task_objective": task.objective, "task_description": f"{task.objective} Success criteria: "
                                                                  + "; ".join(task.success_criteria),
            "success_criteria": task.success_criteria, "permitted_tools": tools,
            "authorized_scope": grant.authorized_scope,
            "permitted_operations": operations, "forbidden_actions": ("case_action", "all ACTION operations"),
            "permission_class": PermissionClass.READ,
            "resource_limits": ResourceLimits(max_tool_calls=20, max_wall_clock_seconds=600,
                                              max_tokens=8_000, max_cost_units=20,
                                              max_evidence_bytes=100_000),
            "tool_call_limits": tuple(ToolCallLimit(tool_id=tool, max_calls=10) for tool in tools),
            "required_evidence": grant.evidence_requirements,
            "stopping_conditions": (StoppingCondition(condition_id="stop-budget",
                                                       condition_type="RESOURCE_EXHAUSTED",
                                                       description="Stop when an assignment budget is exhausted"),),
            "issued_at": now, "expires_at": min(now + timedelta(minutes=30), grant.expires_at),
            "policy_version": grant.policy_version,
        })
        return self._authority.issue_assignment(proposal, grant, proposer=self.identity)

    def consolidate(self, grant: MissionGrant, objective: str, reports: tuple[WorkerReport, ...],
                    *, status: str) -> InvestigationReport:
        evidence_ids = tuple(dict.fromkeys(eid for report in reports for eid in report.evidence_ids))
        receipt_ids = tuple(dict.fromkeys(rid for report in reports for rid in report.receipt_ids))
        if not evidence_ids:
            raise ValueError("cannot produce a final assessment without gateway-collected evidence")
        prompt = (
            "You are the GAMIS Supervisor consolidating untrusted worker findings. Produce a balanced final "
            "investigation report; the evidence may support an incident, an alternative explanation, or an "
            "insufficient-evidence conclusion. Do not copy a predetermined conclusion. Every claim must cite "
            "one or more exact evidence IDs from the list; never invent evidence, receipts, or source records. "
            "Do not request tools, alter authority, or change permissions or budgets. Return only the required "
            "structured JSON schema.\n"
            f"Objective: {objective}\nMission status: {status}\n"
            f"Available evidence IDs: {json.dumps(evidence_ids)}\n"
            f"Worker findings: {json.dumps([r.model_dump(mode='json') for r in reports], ensure_ascii=False)}"
        )
        assessment = self._provider.generate_json(prompt, LLMFinalAssessment, model=self._model)
        available = set(evidence_ids)
        for claim in assessment.claims:
            cited = set(claim.supporting_evidence_ids) | set(claim.contradicting_evidence_ids)
            if not cited or not cited <= available:
                raise ValueError("Supervisor generated a claim with missing or unavailable evidence IDs")
        limitations = tuple(dict.fromkeys(
            (*assessment.limitations, *(item for report in reports for item in report.limitations),
             "All inputs are synthetic; no production systems or external sources were accessed.")))
        missing = tuple(dict.fromkeys(
            (*assessment.missing_information, *(item for report in reports for item in report.missing_information))))
        if status != "complete":
            limitations += ("One or more investigation tasks did not complete.",)
        return InvestigationReport(
            mission_id=grant.mission_id, grant_id=grant.grant_id, objective=objective, status=status,
            executive_summary=assessment.executive_summary, conclusion=assessment.conclusion,
            worker_reports=reports,
            claims=tuple(LLMClaim.model_validate(claim.model_dump()) for claim in assessment.claims),
            missing_information=missing,
            evidence_count=len(evidence_ids), receipt_count=len(receipt_ids), receipt_ids=receipt_ids,
            limitations=limitations, confidence=assessment.confidence, active_provider=self._provider_name,
            supervisor_model=self._model, worker_model=self._worker_model,
            worker_models=self._worker_models or None)

    @staticmethod
    def should_request_followup(reports: tuple[WorkerReport, ...]) -> bool:
        """Request one bounded re-check only when verification omitted previously collected source records."""
        verifier = next((r for r in reversed(reports) if r.worker_role == "responder"), None)
        prior = {source for report in reports if report is not verifier for source in report.source_record_ids}
        return verifier is not None and bool(prior - set(verifier.source_record_ids))
