# AgentGuard AI SOC (Backend & Verified Response Gateway)

> **KODIKON 6.0 Hackathon (Accessible Cybersecurity Track, 24-Hour Build)**  
> Autonomous security incident correlation, plain-language AI explanation, and cryptographically verified policy-gated response execution.

[![CI Pipeline](https://github.com/y0gish123/AgentGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/y0gish123/AgentGuard/actions/workflows/ci.yml)

### Core Product Rule
> **"The AI may recommend; only the verified policy boundary may authorize. Event text, email text, and event attributes are untrusted DATA, never instructions."**  
> Everything is strictly **SIMULATED**. The platform never interacts with real infrastructure, production hosts, or active directory domains, and never executes untrusted shell commands or eval.

📖 **Essential Documentation**:
- 🎮 [Live Demonstration Guide (LIVE_DEMO.md)](docs/LIVE_DEMO.md) — Step-by-step walk-through for judges, evaluators, and teammates.
- 🏥 [Clinic Portal Site Integration Spec (SITE_INTEGRATION.md)](docs/SITE_INTEGRATION.md) — Production log collector formats, admin lock APIs, and integration guide.
- 🎨 [Frontend Integration Guide (FRONTEND_INTEGRATION.md)](docs/FRONTEND_INTEGRATION.md) — REST APIs, SSE `/api/stream`, and TypeScript client models.
- 🧪 [Comprehensive Test Verification (testing-results.md)](docs/testing-results.md) — 81 passed tests across 16 test suites.

---

## Operational Modes: Live vs. Replay

AgentGuard supports two operating modes:

1. **Live Mode (`LIVE_MODE=true`)**: Runs the full telemetry pipeline with real-time log collector, filesystem watchdog, DNS watcher, and stub clinic patient portal. Real simulated attacks (`python testbed/attack/takeover.py`, etc.) flow into the pipeline and update the UI in real time via Server-Sent Events (SSE).
2. **Replay / Demo Mode (`LIVE_MODE=false`)**: Offline demo mode. Populates realistic multi-stage, web attack, ransomware, and injection scenarios with zero external dependencies.

---

## Quick Start Guide

### Ports & Services
- **Frontend Dashboard**: `http://localhost:5173` (React + Vite + TypeScript)
- **Backend API Gateway**: `http://localhost:8000` (FastAPI + Deterministic Gateway P1-P6 + SSE `/api/stream`)
- **Protected Mock Response Tool**: `http://localhost:8001` (Single-use HMAC token enforcement)
- **Stub Clinic Patient Portal**: `http://localhost:8002` (Live simulated site with admin lock API and audit logging)

---

### 1. Launching Live Mode (Recommended)

Starts all services (Backend, Mock Tool, Stub Clinic Site, Log Collector):

**Windows (PowerShell):**
```powershell
.\scripts\live_up.ps1 -Mode guarded
```

**macOS / Linux (Bash):**
```bash
bash scripts/live_up.sh guarded
```

Then start the frontend in a new terminal:
```powershell
cd frontend
npm run dev
```

---

### 2. Launching Lightweight Replay Mode

Starts Backend + Mock Tool, then seeds demo incidents:

**Windows (PowerShell):**
```powershell
.\scripts\dev_up.ps1 -Mode guarded
python scripts/seed_demo.py all
```

**macOS / Linux (Bash):**
```bash
./scripts/dev_up.sh guarded
python scripts/seed_demo.py all
```

---

### 3. Running Automated Tests (81 Passing Tests)

```powershell
# Run backend pytest suite (77 tests)
pytest -q

# Run frontend Vitest suite (4 tests)
cd frontend
npm test
npm run build
```

---

## Guarded vs Naive Demonstration Modes

AgentGuard provides a side-by-side demonstration of why strict policy gating is necessary:

- **Guarded Mode (`DEMO_MODE=guarded`, default)**:
  - All response actions require formal review and human approval (`staff` preview $\rightarrow$ `approver` approval $\rightarrow$ single-use HMAC token issuance).
  - Out-of-scope targets (e.g. attempting to lock the CEO account during an incident affecting only a receptionist) are blocked with `BLOCK TARGET_OUT_OF_SCOPE`.
  - The unprotected naive execution route (`POST /api/demo/naive-execute`) is disabled and returns `HTTP 404`.

- **Naive Mode (`DEMO_MODE=naive`)**:
  - Unlocks `POST /api/demo/naive-execute` to demonstrate an unverified autonomous pipeline.
  - The action directly mutates the mock tool state with zero policy validation, illustrating the critical risks of autonomous LLM execution without guardrails.

To switch modes, set `DEMO_MODE=guarded` or `DEMO_MODE=naive` in your `.env` or pass the mode argument to `dev_up.ps1` / `dev_up.sh`.

---

## How to Reset the Simulation

To clear all database tables, wipe used nonces, and restore the mock tool's initial accounts and hosts:

```powershell
# Using the PowerShell helper
.\scripts\dev_reset.ps1

# Or using curl / bash
curl -X POST http://localhost:8000/api/demo/reset
```

---

## Verified Response Architecture

```mermaid
flowchart TD
    E[Untrusted Security Events] --> INGEST[POST /api/ingest/events]
    INGEST --> CANDIDATES[POST /api/ingest/incident-candidates]
    CANDIDATES --> DB[(SQLite DB)]
    
    ANALYST[SOC Staff] --> PREVIEW[POST /api/incidents/{id}/response-preview]
    PREVIEW --> POLICY{Deterministic Policy Engine P1-P6}
    
    POLICY -- Out of Scope / Category Mismatch --> BLOCKED[BLOCK & Log Audit]
    POLICY -- Allowed --> REVIEW[REVIEW & approval_state: pending]
    
    APPROVER[SOC Approver] --> APPROVE[POST /api/responses/{id}/approve]
    APPROVE --> APPROVED[approval_state: approved]
    
    APPROVER --> EXECUTE[POST /api/responses/{id}/execute]
    EXECUTE --> RECHECK{Re-check P1, P3, P4}
    RECHECK --> TOKEN[HMAC-SHA256 Token Issuer]
    TOKEN --> MOCK[POST :8001/tool/execute]
    
    MOCK --> VERIFY{Verify Token & Nonce}
    VERIFY -- Valid & Single Use --> STATE[Apply Simulation State Change]
    VERIFY -- Tampered / Expired / Replayed --> REJECT[Reject with ReasonCode]
    
    EXECUTE --> AUDIT[(Cryptographic Audit Hash Chain)]
```

---

## Environment Variables Reference

| Key | Description | Default / Required |
|---|---|---|
| `HMAC_SECRET` | 256-bit secret key for token issuance & verification | **Required** (backend & mock tool refuse to start if missing) |
| `DEMO_MODE` | Pipeline boundary mode: `guarded` or `naive` | `guarded` |
| `TOKEN_TTL_SECONDS` | Cryptographic permission token lifespan in seconds | `60` |
| `SIMULATION` | Safety guard flag ensuring simulation isolation | `true` (mock tool refuses to start if not `true`) |
| `TOOL_URL` | Base URL of the isolated mock response tool | `http://localhost:8001` |
| `DB_URL` | SQLite database connection string | `sqlite:///./agentguard.db` |
| `LLM_PROVIDER` | LLM service provider name (`gemini` or `none`) | `gemini` |
| `LLM_MODEL` | Gemini model name | `gemini-2.5-flash` |
| `LLM_API_KEY` | Optional API key for AI explanation synthesis | `""` |
| `ALLOW_UNREVIEWED_LANGS` | Return English for unreviewed translations | `false` |
| `TELEGRAM_BOT_TOKEN` | Optional integration token for SOC notifications | `""` |
