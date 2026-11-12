# GAMIS Local Dashboard API

The FastAPI application is an adapter over one `LocalRuntime`; it does not duplicate or replace the Authority
Service, Secure Tool Gateway, mission store, evidence store, or audit ledger. Run it on loopback only.

## Start locally (PowerShell)

From the extracted repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .\backend
Copy-Item .\backend\.env.example .\backend\.env
```

For a mock run, edit `backend\.env` and set `GAMIS_LLM_PROVIDER=mock`. To use Ollama, leave its configured
provider in place, install and start Ollama separately, then pull the configured model:

```powershell
ollama pull qwen2.5:7b
```

Terminal 1 (from the repository root):

```powershell
.\scripts\start-api.ps1
```

For code reload, run `.\scripts\start-api.ps1 -Reload`. If needed, run `ollama serve` in Terminal 2. Open
`http://127.0.0.1:8000/` for the supplied dashboard and
`http://127.0.0.1:8000/docs` for the generated OpenAPI reference. The dashboard uses the same-origin API by
default. Its Connection page can point it to another local API URL. CORS is limited to loopback development
origins and can be overridden with `GAMIS_CORS_ORIGINS` (comma-separated). Do not expose this unauthenticated
development API to a network.

The API uses the existing runtime's environment configuration. A dashboard mission may select `ollama` or
`mock`; Ollama models must be listed by that local Ollama server and are checked before a grant is created.
The selected provider/model configuration is persisted with the mission so supported recovery uses the same
configuration. Runtime state defaults to `$HOME\.gamis`; set `GAMIS_HOME` or `GAMIS_STATE_DIR` to change it.

## Routes

All errors use:

```json
{"error":{"code":"MISSION_NOT_FOUND","message":"..."}}
```

Validation errors return HTTP 422; missing missions return 404; invalid state transitions return 409; unavailable
providers return 503; unsupported features return 501.

| Method and path | Behavior |
|---|---|
| `GET /health` | API status, selected provider, and audit-ledger head (not a ledger verification). |
| `GET /api/models?provider=mock\|ollama` | Locally available models and configured per-role selection. Ollama connectivity failures return 503. |
| `GET /api/missions` | Persisted mission summaries, progress, evidence/receipt counts, and token/tool/evidence budgets. |
| `POST /api/missions` | Accepts `{ "objective": "...", "provider": "mock" }`; provider and available model selections are optional. Returns 202 and a persisted mission/grant ID. Scope, permissions, and budgets are fixed by the runtime, not request fields. |
| `GET /api/missions/{mission_id}` | Persisted mission state and verified recovery eligibility. |
| `GET /api/missions/{mission_id}/job` | In-process submission status where available. |
| `GET /api/missions/{mission_id}/tasks` | Persisted tasks, issued assignments (scope/operations only), worker reports, and errors. |
| `GET /api/missions/{mission_id}/report` | Final persisted evidence-intelligence report; returns 409 until it is ready. |
| `POST /api/missions/{mission_id}/resume` | Queues runtime recovery only when grant, expiry, checkpoint, and mission-state checks allow it. It does not refresh or reactivate authority. |
| `POST /api/missions/{mission_id}/cancel` | Uses the existing runtime cancellation flow, which suspends the durable grant before stopping new executions. |
| `GET /api/missions/{mission_id}/recovery` | Checkpoint integrity/status, resume eligibility, grant state, and uncertain-action state. |
| `GET /api/agents` | Registered worker identities and latest persisted task state. |
| `GET /api/evidence?mission_id={id}&limit=200` | Persisted evidence with verified record, sanitized derivative (when available), provenance links, and claim relations. |
| `GET /api/missions/{mission_id}/evidence` | Mission-filtered evidence. |
| `GET /api/missions/{mission_id}/receipts` | Actual signed ToolReceipts from the Gateway store. |
| `GET /api/missions/{mission_id}/gateway` | Actual authorization/request/execution audit events, receipts, and uncertain-action state. |
| `GET /api/ledger?start=1&limit=100&mission_id={id}` | Actual append-only audit events. |
| `GET /api/ledger/verify` | Recomputes and verifies the actual ledger using the runtime trust store. |
| `GET /api/evaluation/scenarios` | Existing evaluation harness scenario definitions only; no GAMIS-backed scenario runner is provided. |
| `GET /api/approvals` | Returns 501 because no persistent human approval queue exists. |
| `POST /api/approvals/{approval_id}/decision` | Returns 501; the dashboard cannot approve protected operations. |
| `POST /api/gateway/requests` | Returns 501; a browser cannot submit tool requests or invoke adapters. |

## Authorization boundary

The dashboard cannot create grants or assignments, choose mission scope, change permissions or budgets, mark
denied operations successful, dispatch tools, or approve ACTION operations. Only the Supervisor and workers in
the runtime receive signed authorization; workers call tools through the existing Gateway, which authenticates
the worker and verifies signatures, scope, expiry, revocation, registry, permission, budgets, approval, and
idempotency before adapter dispatch. The dashboard's Gateway page is read-only. No API route exposes direct
adapter access.

The runtime currently provides only synthetic in-memory tools, no durable approval queue, and no evaluation
scenario execution service. These are reported as unsupported rather than simulated.
