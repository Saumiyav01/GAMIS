# GAMIS V4 — local governed investigation

GAMIS is a local P0–P7 synthetic investigation system. Signed grants and assignments are issued by the
existing Authority Service; **every worker tool call must pass through the Secure Tool Gateway**. By default,
the Supervisor and all three workers use structured JSON inference from local Ollama. Mock mode is a
separate deterministic option; GAMIS never silently falls back to mock if Ollama is unavailable.

The included end-to-end mission investigates synthetic authentication and network events and produces a
persisted report, evidence, audit events, and signed ToolReceipts. It does not access production systems or
perform real external actions.

## Requirements

- Windows 10/11 with PowerShell 5.1+.
- Python 3.12+.
- Ollama installed locally for model-backed runs. Ollama and its model weights are **not included**.

## Install

From the extracted GAMIS folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .\backend
Copy-Item .\backend\.env.example .\backend\.env
```

The source ZIP has no secrets or runtime data. By default, databases and development signing keys are
created under `$HOME\.gamis`, outside the source tree. Set `GAMIS_HOME` to move runtime state. Never point
`GAMIS_DEV_KEY_DIR` inside the source tree.

## Run with Ollama (default)

1. Install Ollama using the official installer at [ollama.com](https://ollama.com/).
2. Start the Ollama application, or run `ollama serve` in a separate terminal.
3. Pull the configured model:

   ```powershell
   ollama pull qwen2.5:7b
   ```

4. `backend\.env` defaults to `OLLAMA_HOST=http://localhost:11434` and configures
   `GAMIS_SUPERVISOR_MODEL` and `GAMIS_WORKER_MODEL` as `qwen2.5:7b`. Change either variable to a model
   installed in Ollama. GAMIS checks connectivity and model availability before creating a mission. If
   Ollama is unreachable, start the Ollama application or run `ollama serve`; if the model is missing, run
   `ollama pull <model>`. GAMIS reports either problem and does not fall back to mock.
5. Submit the synthetic investigation:

   ```powershell
   .\scripts\run.ps1 mission submit
   ```

The script loads `backend\.env` and uses the repository `.venv` if present. To override the selected provider
for one run, use `.\scripts\run.ps1 mission submit --provider ollama`.

## Run without Ollama

The deterministic provider requires no Ollama process or model weights:

```powershell
.\scripts\run.ps1 mission submit --provider mock
```

To make mock mode the default, set `GAMIS_LLM_PROVIDER=mock` in `backend\.env`. Ollama remains the default
provider in the supplied configuration. Supervisor and worker model names are configurable separately.

## Inspect missions

`mission submit` prints the final report and mission ID. Use that ID with:

```powershell
.\scripts\run.ps1 models --provider ollama
.\scripts\run.ps1 mission submit --provider ollama
.\scripts\run.ps1 mission list
.\scripts\run.ps1 mission status MIS-<id>
.\scripts\run.ps1 mission report MIS-<id>
.\scripts\run.ps1 mission receipts MIS-<id>
.\scripts\run.ps1 mission evidence MIS-<id>
.\scripts\run.ps1 mission resume MIS-<id> --provider mock
.\scripts\run.ps1 mission cancel MIS-<id> --reason "Operator stop"
.\scripts\run.ps1 verify --ledger "$HOME\.gamis\audit.db" `
    --evidence-db "$HOME\.gamis\evidence.db" --content-dir "$HOME\.gamis\evidence-objects" `
    --trust-store "$HOME\.gamis\trust.json"
```

`mission submit` reports the active provider and selected models. An Ollama run invokes the supervisor model
for task decomposition, each worker model for that worker's findings, and the supervisor model again for the
final evidence-backed assessment. `status` shows Research, Analysis, and Verification Worker task states.
Receipts are gateway-signed and
include request, worker, tool, permission class, outcome, and result digests. Workers persist signed P2
EvidenceBundles containing structured claims, evidence items, and receipt references. Evidence records are
linked to their mission, assignment, worker, and receipt. Mission status and reports are persisted in local SQLite
databases. To revoke a grant, use `mission revoke <grant-id> --reason "..."`; the Gateway reads this
persistent status on every execution and fails closed if activation was not durably audited.

## Configuration

Copy and edit `backend\.env.example`. The main settings are:

| Variable | Default | Purpose |
|---|---|---|
| `GAMIS_LLM_PROVIDER` | `ollama` | `ollama` or deterministic `mock` |
| `OLLAMA_HOST` | `http://localhost:11434` | Local Ollama endpoint |
| `GAMIS_SUPERVISOR_MODEL` | `qwen2.5:7b` | Supervisor model |
| `GAMIS_WORKER_MODEL` | `qwen2.5:7b` | Default model shared by workers |
| `GAMIS_RESEARCH_MODEL` | unset | Optional Research Worker model override |
| `GAMIS_ANALYSIS_MODEL` | unset | Optional Analysis Worker model override |
| `GAMIS_VERIFICATION_MODEL` | unset | Optional Verification Worker model override |
| `GAMIS_LLM_TIMEOUT` | `90` | Per-request timeout in seconds |
| `GAMIS_LLM_RETRIES` | `1` | Bounded network retries |
| `GAMIS_LLM_TEMPERATURE` | `0.2` | Ollama generation temperature (0–2) |
| `GAMIS_LLM_CONTEXT_TOKENS` | `8192` | Ollama context limit |
| `GAMIS_WORKER_CONCURRENCY` | `3` | Maximum scheduled workers (1–32) |
| `GAMIS_HOME` | `$HOME\.gamis` | Persistent database, evidence, and key location |

The CLI loads `backend\.env` without overriding already-set process environment variables. No hosted LLM API
key is used. Ollama access is local HTTP. Models generate task descriptions, evidence-cited findings, and a
final assessment only; they cannot authorize assignments, change budgets, select permissions, or execute tools.
Generated evidence references are validated against the exact IDs collected by the worker or mission before
they are persisted.

## Live dashboard and HTTP API

The supplied `gamis_dashboard.html` is served by the FastAPI adapter over the same `LocalRuntime`, mission
store, Secure Tool Gateway, evidence store, and audit ledger used by GAMIS. The dashboard defaults to the
same-origin API, polls actual persisted mission/worker state, and visibly reports connection or request
errors. It never substitutes demo data after a failed request.

The API and dashboard dependencies are included in `backend\pyproject.toml` and `backend\requirements.txt`.
From the repository root in PowerShell, install as above, then:

1. In `backend\.env`, choose `GAMIS_LLM_PROVIDER=mock` for an offline run, or leave `ollama` and install/start
   Ollama separately. Ollama and its model weights are not bundled.
2. For Ollama, in another terminal run `ollama serve` if the Ollama application is not already running, then
   `ollama pull qwen2.5:7b` (or pull the model configured in `backend\.env`).
3. Start the API from the repository root (the script reads `backend\.env` and uses `.venv` when present):

   ```powershell
   .\scripts\start-api.ps1
   ```

   For auto-reload during local development, run `.\scripts\start-api.ps1 -Reload`.

4. Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) for the dashboard or
   [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for OpenAPI. Submit an investigation from Mission
   Control and select mock or Ollama; installed Ollama models are listed and checked before creating a grant.
5. Inspect persisted worker tasks, Gateway receipts/decisions, evidence, reports, and ledger events in their
   corresponding dashboard pages. Mission resume/cancel are offered only through supported runtime checks.

The API binds to loopback in the command above and is a local development interface, not an authenticated
network service. It does not expose browser-triggered adapter calls, authority changes, approval decisions, or
synthetic scenario simulation. Because this runtime has no persistent human approval queue and no GAMIS-backed
evaluation runner, those dashboard capabilities are explicitly reported as unsupported. API schemas and route
semantics are documented in [docs/API.md](docs/API.md).

## Security and known limitations

- Worker tool calls are authenticated with Ed25519 credentials and checked against signed grants and
  assignments, including scope, expiry, revocation, tool registry integrity, operation permission, strict
  arguments, and persistent worker/mission budgets.
- READ and ACTION permissions are independent. ACTION requires an explicit approval provider and a stable
  idempotency key. The sample ACTION tool is disabled; the demo issues READ-only assignments.
- An uncertain ACTION is never retried. It remains `UNCERTAIN` until a trusted operator provides a
  reconciliation reference; reconciliation does not redispatch it.
- The demo uses synthetic, in-memory tool adapters. It is not a production connector and has no real external
  action capability.
- Development Ed25519 keys are persisted outside the source tree as unencrypted PEM files and are **not
  production key management**. Use a protected signer/HSM before any real-world deployment.
- Mission status, gateway budgets/idempotency/actions, evidence, reports, and audit records persist in local
  SQLite. P3's assignment issuance ledger and worker directory remain in-memory; each CLI mission obtains a
  new grant, and the Gateway independently checks the persistent revocation status for every call.
- Token budgets use prompt-size estimates because Ollama token accounting is not exposed by the common
  provider interface. Model inference cost is not billed or measured. No production guarantee is implied.
- The mock provider verifies orchestration and security wiring, not LLM quality. Ollama model quality and
  availability depend on the locally installed model.
- The Supervisor's executive summary, claims, missing-information list, confidence, and conclusion are
  model-generated. This is a decision-support report, not a confirmed incident verdict; citations must resolve
  to persisted evidence items and gateway receipt references.

## Evidence intelligence and recovery (P6/P7)

- Final reports include evidence correlations by content digest, unresolved temporal/source conflicts,
  claim-by-claim verification, model confidence kept separate from deterministic evidence-strength factors,
  provenance, evidence gaps, and all mission evidence/receipt references. Evidence items not included in a
  completed signed worker bundle are retained and explicitly marked as unbundled; they are not silently used as
  claim support.
- Mission plans, signed grants/assignments, worker/task states, reports, retry counters, cancellation state,
  token accounting, evidence/receipt inventories, gateway usage, and action lifecycle snapshots are checkpointed
  in SQLite. Checkpoints are append-only, digest-chained, and cross-checked against the separate audit ledger
  before resuming.
- Failed READ-only worker tasks may be retried once. ACTION assignments are never automatically retried, and
  an `UNCERTAIN` action remains blocked by the Gateway's idempotency record. A reconciliation reference is an
  operator attestation, not automatic tool read-back or proof of a real-world outcome.
- `mission cancel` suspends the durable grant before requesting cancellation, preventing new Gateway
  executions. `mission resume` requires an ACTIVE, unexpired, signature-valid grant and verified checkpoint;
  it does not refresh expired assignments or reactivate suspended/revoked grants. Incomplete work that cannot
  be safely authorized again remains partial.
- The synthetic demo grants READ only and disables ACTION, so it has no outstanding human approval to restore.
  Protected ACTION approvals remain request-bound and must be revalidated for each dispatch; approval tokens are
  never replayed during recovery. The assignment issuance ledger and worker directory remain in-memory services;
  persisted signed assignments are cryptographically checked and restored to the Authority's accounting ledger
  during an authorized resume.

See [Implementation status](docs/IMPLEMENTATION_STATUS.md), [Architecture](docs/ARCHITECTURE.md), and
[Roadmap](docs/ROADMAP.md).

## Tests

```powershell
python -m pip install -e ".\backend[dev]"
python -m pytest .\backend\tests
```

## Build the single source archive

From the repository root, run:

```powershell
python .\scripts\build_source_zip.py
```

This creates `GAMIS_CONNECTED_DASHBOARD.zip` next to the repository, verifies its manifest and CRC, and
excludes private keys, `.env`, databases, caches, Git internals, and virtual environments.
