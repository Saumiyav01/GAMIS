# ADR-0001: Governance is enforced outside the LLM
Status: Accepted
Context: Prompt-only restrictions can be bypassed by direct or indirect injection.
Decision: Permissions, budgets, idempotency, and audit are enforced by deterministic code in an Authority Service
and Secure Tool Gateway. Workers have no direct tool handles. Tool output is data, never instructions.
Consequences: Injection can still influence a worker's reasoning; the claim is only that it cannot widen authority.
