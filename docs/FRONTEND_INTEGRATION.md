# AgentGuard AI SOC - Frontend Integration Guide

Welcome to the AgentGuard backend! This document provides everything you need to connect the React/TypeScript dashboard to the backend and verified response gateway.

---

## 1. Quick Setup & Base URL

- **Backend Base URL**: `http://localhost:8000` (or `http://127.0.0.1:8000`)
- **Mock Tool State Proxy**: `GET /api/demo/tool-state`
  > **IMPORTANT**: The frontend must **NEVER** call the mock tool on port 8001 directly. Always communicate through the backend API gateway.

### Vite Proxy Configuration (`frontend/vite.config.ts`)
To avoid CORS issues in local development, configure a proxy in Vite:

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});
```

### TypeScript Types Generation
You can generate full TypeScript types directly from the OpenAPI 3.1 specification at any time:

```bash
npx openapi-typescript docs/openapi.json -o frontend/src/api-types.ts
```

---

## 2. Authentication & Identity Headers

AgentGuard uses simulated zero-trust header-based authentication. Send these headers on all requests from the dashboard:

| Header | Description | Allowed Values | Default if omitted |
|---|---|---|---|
| `X-User` | Identifier of active operator | e.g. `"priya.analyst"`, `"soc.lead"` | `"anonymous"` |
| `X-Role` | Operational authority role | `staff` or `approver` | `staff` |

- **`staff`**: Can view incidents, request explanations, and trigger action **previews**. Cannot approve or execute actions.
- **`approver`**: Can approve pending reviews and trigger verified action **execution**.

---

## 3. Standardized Error Format

Every error response returns HTTP 4xx/5xx with the standardized `ErrorBody` schema:

```json
{
  "code": "TARGET_OUT_OF_SCOPE",
  "plain_message": "This account or computer is not part of this incident, so the action was refused.",
  "detail_id": "err-9b2f4c"
}
```

---

## 4. Reason Codes & Plain Language Sentences

These sentences are returned by the policy boundary and should be surfaced directly to users in the UI:

| Reason Code | Plain Language UI Message |
|---|---|
| `APPROVAL_REQUIRED` | *"This action is allowed for this incident but a person must approve it first."* |
| `TARGET_OUT_OF_SCOPE` | *"This account or computer is not part of this incident, so the action was refused."* |
| `ACTION_NOT_ALLOWED_FOR_CATEGORY` | *"This type of action is not allowed for this kind of incident."* |
| `INCIDENT_NOT_OPEN` | *"This incident is already contained or closed."* |
| `ROLE_NOT_PERMITTED` | *"Only an approver can do this."* |
| `APPROVAL_NOT_RECORDED` | *"This action has not been approved yet."* |
| `EXECUTED_OK` | *"The action was carried out in the simulation."* |
| `TOKEN_MISSING` | *"The action tool did not receive a permission token."* |
| `TOKEN_BAD_SIGNATURE` | *"The permission token was not valid."* |
| `TOKEN_EXPIRED` | *"The permission token expired, so nothing was changed."* |
| `TOKEN_REPLAYED` | *"This permission was already used, so nothing was changed."* |
| `TOKEN_SCOPE_MISMATCH` | *"The permission does not match this exact action, so nothing was changed."* |
| `TOOL_UNAVAILABLE` | *"The action tool is not reachable, so nothing was changed."* |

---

## 5. Core Enums

```typescript
export type Source = 'replay' | 'wazuh' | 'collector' | 'phishing_check' | 'simulator';
export type EventType =
  | 'authentication_failure'
  | 'authentication_success'
  | 'privilege_change'
  | 'scheduled_task_created'
  | 'process_start'
  | 'backup_tampering'
  | 'file_change_burst'
  | 'file_created'
  | 'phishing_check';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Category = 'phishing_attempt' | 'account_takeover' | 'ransomware_like_activity' | 'multi_stage';
export type IncidentStatus = 'open' | 'contained' | 'closed';
export type LinkRule = 'LINK_SAME_USER_30M' | 'LINK_SAME_HOST_30M' | 'NONE';
export type Confidence = 'low' | 'needs_review' | 'likely';
export type ActionType = 'lock_account' | 'revoke_session' | 'isolate_host';
export type ProposedBy = 'human' | 'ai';
export type Role = 'staff' | 'approver';
export type PolicyDecision = 'ALLOW' | 'REVIEW' | 'BLOCK';
export type ApprovalState = 'not_required' | 'pending' | 'approved' | 'rejected';
export type ExecutionStatus = 'not_started' | 'succeeded' | 'rejected_by_tool' | 'blocked' | 'failed';
```

---

## 6. Seeded Entities & Test Data

The system includes pre-configured entities for demo scenarios:

- **Users**:
  - `priya.rec` (compromised medical records receptionist)
  - `front.desk` (ransomware simulation victim)
  - `ceo` (executive account - used to test out-of-scope blocks!)
  - `svc-backup` (automated service account)
- **Hosts**:
  - `clinic-pc-01` (Windows workstation for `priya.rec`)
  - `clinic-pc-02` (Workstation for `front.desk`)
  - `db-server-01` (Critical database server - out-of-scope for host isolation!)
- **Incidents**:
  - `inc-3f9a1c20`: multi_stage incident on `clinic-pc-01` with 10 evidence events.
  - `inc-7b2e90d1`: ransomware_like_activity on `clinic-pc-02`.
  - `inc-9a2c3f8e`: poisoned event incident (tests XSS & prompt-injection resilience).
  - `inc-99c0ffee`: closed incident (tests `INCIDENT_NOT_OPEN` policy block).

---

## 7. The Three Core Operational Flows

### Flow A: Normal Verified Remediation (REVIEW -> APPROVE -> EXECUTE)
1. **Preview Action**:
   `POST /api/incidents/inc-3f9a1c20/response-preview`
   ```json
   {
     "action_type": "lock_account",
     "target_id": "priya.rec",
     "requested_by": "analyst-1",
     "proposed_by": "human"
   }
   ```
   **Response**: `policy_decision: "REVIEW"`, `approval_state: "pending"`, `execution_status: "not_started"`.

2. **Approve Action (Approver Role Only)**:
   `POST /api/responses/{response_id}/approve` (Header: `X-Role: approver`)
   ```json
   {
     "decision": "approve",
     "reason": "Host privilege escalation confirmed unauthorized."
   }
   ```
   **Response**: `approval_state: "approved"`.

3. **Execute Action (Approver Role Only)**:
   `POST /api/responses/{response_id}/execute` (Header: `X-Role: approver`)
   **Response**: `execution_status: "succeeded"`, `reason_code: "EXECUTED_OK"`.
   Verify tool state updated via `GET /api/demo/tool-state`.

---

### Flow B: Policy Enforcement Block (TARGET_OUT_OF_SCOPE)
1. **Preview Action on Out-of-Scope Target**:
   `POST /api/incidents/inc-3f9a1c20/response-preview`
   ```json
   {
     "action_type": "lock_account",
     "target_id": "ceo",
     "requested_by": "analyst-1",
     "proposed_by": "human"
   }
   ```
2. **Response**:
   `policy_decision: "BLOCK"`, `reason_code: "TARGET_OUT_OF_SCOPE"`, `execution_status: "blocked"`.
   Mock tool state remains unchanged.

---

### Flow C: Unprotected Pipeline Comparison (Naive Mode)
To demonstrate the danger of unverified autonomous pipelines:
1. Start backend in naive mode: `DEMO_MODE=naive`.
2. Post directly to naive execute:
   `POST /api/demo/naive-execute`
   ```json
   {
     "incident_id": "inc-3f9a1c20",
     "action_type": "lock_account",
     "target_id": "ceo",
     "proposed_by": "ai"
   }
   ```
3. **Outcome**: The CEO account is locked immediately without policy checks, demonstrating why the verified policy gateway is essential.

---

## 8. Complete API Route Reference

| Method | Path | Description | Request Body Example | Response Body Example |
|---|---|---|---|---|
| `GET` | `/api/health` | Health probe | — | `{"status": "ok"}` |
| `GET` | `/api/incidents` | Incident list | Query params: `status`, `severity`, `limit`, `offset` | `shared/examples/incident_list_response.json` |
| `GET` | `/api/incidents/{id}` | Incident detail & events | — | `shared/examples/incident_detail_response.json` |
| `POST` | `/api/incidents/{id}/explanation` | AI explanation | `{"lang": "en"}` | `shared/examples/explanation_response.json` |
| `POST` | `/api/incidents/{id}/response-preview` | Evaluate policy | `shared/examples/preview_request.json` | `shared/examples/preview_response.json` |
| `POST` | `/api/responses/{id}/approve` | Approve response | `shared/examples/approve_request.json` | `shared/examples/approve_response.json` |
| `POST` | `/api/responses/{id}/execute` | Verified execution | — | `shared/examples/execute_response.json` |
| `POST` | `/api/phishing/check` | Threat check | `shared/examples/phishing_check_request.json` | `shared/examples/phishing_check_response.json` |
| `GET` | `/api/funnel` | Pipeline metrics | — | `shared/examples/funnel_response.json` |
| `GET` | `/api/meta` | System metadata | — | `shared/examples/meta_response.json` |
| `GET` | `/api/audit` | Audit log | — | `shared/examples/audit_list_response.json` |
| `GET` | `/api/audit/verify` | Verify hash chain | — | `shared/examples/audit_verify_response.json` |
| `POST` | `/api/demo/seed` | Seed scenario | Query param: `scenario=all` | `shared/examples/seed_response.json` |
| `POST` | `/api/demo/reset` | Reset simulation | — | `{"backend_reset": true, "mock_tool_reset": {"ok": true}}` |
| `GET` | `/api/demo/tool-state` | Proxy to tool state | — | `shared/examples/tool_state_response.json` |
| `POST` | `/api/demo/naive-execute` | Naive execution | `shared/examples/naive_execute_request.json` | `{"status": "executed_unprotected", ...}` |

