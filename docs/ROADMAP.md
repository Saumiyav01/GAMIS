# Roadmap (P0–P11)

Each phase ends with tests, doc updates, a limitations report, and a stop for review.

| Phase | Scope |
|---|---|
| P0 | Test harness, deterministic mock tools, synthetic investigation + attack datasets, failure-injection scenarios, baseline evaluation harness |
| P1 | Typed schemas (AgentAssignment, EvidenceBundle, ToolRequest/Receipt, mission/report), canonical serialization, assignment signing/verification, tamper tests |
| P2 | Append-only audit events, hash chaining, evidence + receipt storage, integrity verification |
| P3 | Authority Service: assignment validation, mission grants, role/tool permissions, READ/ACTION separation, budgets, expiry/stop conditions |
| P4 | Secure Tool Gateway: authenticate, validate permissions/budgets/schemas, idempotency, audit, integrity-protected receipts, reject-before-execution |
| P5 | Controlled tools (`log_search`, `intel_lookup`, `case_action`) on synthetic adapters; ACTION disabled by default; timeouts and failure handling |
| P6 | Evidence aggregation: validation, correlation, support vs contradiction, preserved disputes, evidence-based confidence, partial reports, stopping logic |
| P7 | Supervisor + three workers, dispatch, structured responses, bounded retries/timeouts, all calls via gateway |
| P8 | Model adapter abstraction, configurable providers, structured output + validation, deterministic mock mode, works without API key |
| P9 | Runtime containment: worker isolation, fs/network restrictions, resource limits, gateway-bypass prevention, documented limits |
| P10 | Security + performance evaluation; ungoverned vs prompt-defended vs governed; reproducible metrics, no fabricated results |
| P11 | Docker completion, backend/frontend integration, config validation, deployment + API docs, security limitations, demo, release docs |
