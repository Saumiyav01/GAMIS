# GAMIS V4
### Governed Autonomous Multi-Agent Investigation System

**Autonomous investigation. Enforced authority. Verifiable execution.**

GAMIS is a governed multi-agent investigation framework designed to execute complex investigative tasks through specialized AI agents while maintaining strict boundaries around permissions, authorization, tool execution, evidence handling and accountability.

Unlike conventional autonomous agent systems that rely primarily on LLM instructions to control behaviour, GAMIS places governance outside the LLM. Agents can investigate, analyse and verify information, but their execution authority is independently validated by the governance layer.

The objective is to combine autonomous reasoning with enforceable security boundaries and traceable execution.

---

## 1. The Problem

Autonomous AI agents introduce significant security and reliability challenges:

- **Excessive authority:** Agents may attempt operations beyond their intended responsibilities.
- **Prompt injection:** Malicious instructions embedded in retrieved content can influence model behaviour.
- **Uncontrolled tool execution:** Agents may invoke tools without sufficient authorization.
- **Evidence integrity:** Investigation conclusions may lack reliable provenance.
- **Runaway execution:** Unbounded tool calls and resource consumption can create operational risks.
- **Insufficient accountability:** Conventional agent workflows may not provide verifiable records of execution.

GAMIS addresses these challenges through an independent governance architecture that separates reasoning from authorization.

---

## 2. Core Architecture

GAMIS follows a governance-first architecture.

```text
                 MISSION INITIATOR
                        |
                        v
                   MISSION GRANT
                        |
                        v
               LLM SUPERVISOR
               (Task Proposals)
                        |
                        v
              AUTHORITY SERVICE
             (Independent Validation)
                        |
                        v
              SIGNED WORK ORDERS
                        |
           +------------+------------+
           |            |            |
           v            v            v
      RESEARCH      ANALYSIS     VERIFICATION
       WORKER        WORKER         WORKER
           |            |            |
           +------------+------------+
                        |
                        v
             SECURE TOOL GATEWAY
                        |
             +----------+----------+
             |          |          |
             v          v          v
           READ       ACTION    TOOL POLICY
           TOOLS      TOOLS     ENFORCEMENT
             |          |
             +----------+
                        |
                        v
                EXECUTION RECEIPTS
                        |
             +----------+----------+
             |                     |
             v                     v
       EVIDENCE STORE         AUDIT LEDGER
             |                     |
             +----------+----------+
                        |
                        v
               INVESTIGATION REPORT
```

### Architectural Components

| Component | Responsibility |
|---|---|
| Mission Initiator | Defines the investigation objective and constraints. |
| Mission Grant | Establishes the maximum permitted authority. |
| LLM Supervisor | Decomposes investigations into proposed tasks. |
| Authority Service | Independently validates and authorizes assignments. |
| Signed Work Orders | Bind worker identity, scope, permissions and execution limits. |
| Specialized Workers | Perform research, analysis and verification. |
| Secure Tool Gateway | Enforces authorization before tool execution. |
| Evidence Store | Preserves investigation evidence and provenance. |
| Audit Ledger | Maintains a tamper-evident execution history. |

---

## 3. Multi-Agent System

GAMIS uses specialized workers rather than relying on a single general-purpose agent.

### Research Worker — Evidence Reader

Responsibilities:
- Retrieve assigned investigation records.
- Identify relevant events.
- Extract supporting evidence.
- Produce evidence-linked findings.

### Analysis Worker — Intelligence Analyst

Responsibilities:
- Analyse suspicious patterns.
- Correlate investigation records.
- Identify potential relationships.
- Develop analytical claims.

### Verification Worker — Responder

Responsibilities:
- Examine investigation findings.
- Check supporting evidence.
- Identify contradictions and missing information.
- Assess whether conclusions are adequately supported.

### LLM Supervisor

The supervisor coordinates the investigation and proposes task assignments.

It cannot independently authorize its own requests, modify governance policies or bypass the Authority Service.

---

## 4. Governance and Security

GAMIS separates agent reasoning from execution authority.

### Independent Authorization

Each worker receives a signed assignment that defines its permitted execution scope.

Authorization checks include:

- Mission grant validation.
- Assignment signature verification.
- Worker identity validation.
- Permission enforcement.
- Scope validation.
- Expiry and revocation checks.
- Resource budget enforcement.
- Approval requirements.

### Secure Tool Gateway

All worker tool execution is routed through the Secure Tool Gateway.

The gateway enforces:

- READ and ACTION permission separation.
- Tool registry validation.
- Assignment and grant verification.
- Execution budgets.
- Approval gating for restricted actions.
- Idempotency and replay protection.
- Signed execution receipts.
- Audit and evidence integration.

Workers do not directly access tool adapters.

### Cryptographic Accountability

GAMIS uses cryptographic signing and verification to establish the integrity and provenance of assignments and execution receipts.

The audit ledger uses hash chaining to make unauthorized historical modifications detectable.

**Important:** A valid execution receipt establishes execution provenance and integrity; it does not independently prove that an agent's interpretation or conclusion is correct.

### Prompt Injection Boundaries

Retrieved documents, tool outputs and model-generated content are treated as untrusted data.

Untrusted content must not be allowed to modify:

- Worker permissions.
- Mission authority.
- Budgets.
- Tool registry.
- Governance policies.
- Authorization decisions.

---

## 5. Evidence and Investigation Workflow

GAMIS associates investigation findings with evidence references and execution provenance.

The investigation workflow is:

1. Receive an investigation objective.
2. Decompose the objective into bounded tasks.
3. Validate and authorize worker assignments.
4. Execute research and analysis through controlled tools.
5. Collect evidence and execution receipts.
6. Verify findings and identify limitations.
7. Produce an evidence-backed investigation report.

Reports can contain:

- Investigation objective.
- Executive summary.
- Worker findings.
- Evidence references.
- Supporting claims.
- Confidence assessments.
- Missing information.
- Investigation limitations.
- Execution receipt references.

GAMIS should distinguish between observed evidence, analytical inference and unverified conclusions.

---

## 6. Technology Stack

| Layer | Technologies |
|---|---|
| Backend | Python |
| Agent orchestration | Python-based multi-agent runtime |
| Local LLM inference | Ollama |
| Default configured model | Qwen 2.5 7B |
| Cryptography | Ed25519-based signing and verification |
| Persistence | SQLite |
| API | Python backend API |
| Frontend | React, TypeScript, Vite |
| Styling | Tailwind CSS |
| Testing | Pytest |

The system supports deterministic mock execution for testing and demonstration without requiring a running LLM.

Ollama provides the local inference path when configured and available.

---

## 7. Project Structure

```text
GAMIS/
│
├── backend/
│   ├── gamis/
│   │   ├── agents/
│   │   ├── aggregation/
│   │   ├── api/
│   │   ├── audit/
│   │   ├── authority/
│   │   ├── core/
│   │   ├── evaluation/
│   │   ├── evidence/
│   │   ├── gateway/
│   │   ├── llm/
│   │   ├── schemas/
│   │   ├── security/
│   │   ├── storage/
│   │   ├── tools/
│   │   ├── cli.py
│   │   └── runtime.py
│   │
│   ├── app/
│   ├── seeds/
│   ├── tests/
│   ├── .env.example
│   ├── pyproject.toml
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
│
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   ├── IMPLEMENTATION_STATUS.md
│   ├── ROADMAP.md
│   └── adr/
│
├── scripts/
│   ├── run.ps1
│   ├── start-api.ps1
│   ├── build_source_zip.py
│   └── generate_seeds.py
│
├── docker-compose.yml
├── gamis_dashboard.html
├── MANIFEST.json
└── README.md
```

---

## 8. Installation and Local Setup

### Prerequisites

- Python 3.12
- Git
- Windows PowerShell (for the provided scripts)
- Ollama (for local LLM inference)

### Step 1: Clone the repository

```bash
git clone https://github.com/Saumiyav01/GAMIS.git
cd GAMIS
```

### Step 2: Create a virtual environment

```powershell
py -3.12 -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install backend dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -e .\backend
```

### Step 4: Configure environment

```powershell
Copy-Item .\backend\.env.example .\backend\.env
```

Review the environment configuration before running the application.

Never commit populated environment files, private keys or credentials.

---

## 9. Running GAMIS

### Option A: Mock Mode

Mock mode enables deterministic local execution without requiring Ollama.

```powershell
.\scripts\run.ps1 mission submit --provider mock
```

This mode is useful for:
- Testing the mission lifecycle.
- Demonstrating agent orchestration.
- Testing governance workflows.
- Validating evidence and receipt generation.

Mock execution must not be represented as live LLM reasoning.

### Option B: Local LLM Mode Using Ollama

Install Ollama from:

https://ollama.com/

Start Ollama and download the configured model:

```powershell
ollama pull qwen2.5:7b
```

Verify available models:

```powershell
ollama list
```

Run a mission using the Ollama provider:

```powershell
.\scripts\run.ps1 mission submit --provider ollama
```

Live inference requires a running Ollama service and an available configured model.

### Mission Inspection

Check mission status:

```powershell
.\scripts\run.ps1 mission status <mission_id>
```

View the investigation report:

```powershell
.\scripts\run.ps1 mission report <mission_id>
```

Inspect execution receipts:

```powershell
.\scripts\run.ps1 mission receipts <mission_id>
```

Inspect evidence:

```powershell
.\scripts\run.ps1 mission evidence <mission_id>
```

---

## 10. Testing

GAMIS includes unit, integration, security, scenario and failure-oriented tests.

Run the backend test suite:

```powershell
cd backend
python -m pytest tests -q
```

Run the Ollama provider tests:

```powershell
python -m pytest tests/unit/test_ollama_provider.py -v
```

Run the P4/P5 integration tests:

```powershell
python -m pytest tests/integration/test_p4_p5_local.py -v
```

Run the audit ledger tests:

```powershell
python -m pytest tests/unit/test_p2_audit_ledger.py -v
```

Consult `docs/IMPLEMENTATION_STATUS.md` for the implementation status and recorded validation results.

---

## 11. Current Demonstration

The local mock-mode demonstration completed an investigation into suspicious network events.

**Mission objective:**

Investigate suspicious network events and determine whether the available evidence supports a security incident.

Reported execution:

| Metric | Result |
|---|---:|
| Mission status | COMPLETE |
| Worker reports | 3 |
| Signed receipts | 6 |
| Evidence items | 27 |
| Mission confidence | 0.78 |

### Investigation conclusion

The synthetic records contained repeated failed login attempts followed by a successful login.

The available evidence supported a possible security incident but did not establish real-world attribution, impact or completeness of the records.

### Demonstrated capabilities

- Three-worker mission execution.
- Research, analysis and verification task separation.
- Evidence collection.
- Signed execution receipts.
- Mission lifecycle completion.
- Structured investigation reporting.

**Demonstration limitation:** These results were obtained using synthetic data in mock mode. They do not establish live LLM performance or real-world incident detection.

---

## 12. Known Limitations

GAMIS is an evolving research and engineering prototype, not a production-certified security platform.

The current implementation has documented limitations, including:

- Development-key storage requires production-grade hardening.
- Some P3 issuance and worker-directory state remains in-memory.
- Token budgets are estimates.
- A production authenticated human-approval channel is not yet implemented.
- Production external tool connectors are not included.
- Live Ollama execution must be independently validated in the deployment environment.

See `docs/IMPLEMENTATION_STATUS.md` for the detailed status.

---

## 13. Roadmap

| Phase | Focus |
|---|---|
| P0 | Test harness and synthetic scenario foundation |
| P1 | Typed schemas, cryptography and Authority Service |
| P2 | Audit ledger and evidence storage |
| P3 | Runtime authorization and governance |
| P4 | Secure Tool Gateway |
| P5 | Local multi-agent runtime and orchestration |
| P6 | Evidence intelligence |
| P7 | Resilience and recovery |

---

## 14. Design Principles

GAMIS is built around five principles:

1. **Governance outside the LLM:** Models propose and reason; independent services authorize.
2. **Least privilege:** Every worker operates within a bounded assignment.
3. **Controlled execution:** Tool calls pass through mandatory authorization checks.
4. **Evidence-backed conclusions:** Findings retain provenance and explicit limitations.
5. **Verifiable accountability:** Assignments, receipts and audit events support execution traceability.

---

## 15. Repository

**GitHub:** https://github.com/Saumiyav01/GAMIS

Contributions, technical feedback and research collaboration are welcome.

---

## License

No license has been specified yet. All rights are reserved by default unless a license is added to this repository.

---

**GAMIS V4 — Governed autonomy with enforceable authority boundaries and verifiable execution.**
