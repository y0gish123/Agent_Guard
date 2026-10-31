# AgentGuard Architecture & Decisions Log

This document records architectural, design, and implementation decisions made during the development of AgentGuard AI SOC (KODIKON 6.0, Accessible Cybersecurity track).

## 1. Directory Structure and Project Root
- **Decision**: The active workspace root (`c:\Users\saroj\OneDrive\Desktop\AgentGuard`) hosts the exact project structure specified (`shared/`, `backend/`, `mock_tool/`, `scripts/`, `docs/`, `backend/tests/`).
- **Rationale**: Enables direct execution of the required commands (`uvicorn backend.main:app --port 8000 --reload`, `uvicorn mock_tool.app:app --port 8001 --reload`, `pytest -q`) from the project root without nested path indirection.

## 2. Contracts and Strict Typing
- **Decision**: All enums and models are strictly typed in `shared/contracts.py` using Pydantic v2.
- **Rationale**: Single source of truth shared between backend, mock tool, test harness, and demo scripts. Strings are capped (max 2000 characters by default, titles/identifiers appropriately constrained) to prevent memory exhaustion and injection attacks.
- **Datetime Format**: Serialized to standard ISO-8601 ending in `Z` using UTC.

## 3. Database & Persistence Layer
- **Decision**: SQLAlchemy 2.0 with synchronous SQLite. Ingest and candidate upsert methods create or update tables on application startup.
- **Rationale**: Eliminates Alembic and external DB service dependencies for the 24-hour hackathon while guaranteeing ACID transactions and strict data integrity.
- **Lists & Dicts Storage**: Stored as JSON strings in SQLite with automated serialization/deserialization helper properties in ORM models.

## 4. Policy Engine and Gateway Separation
- **Decision**: The policy engine in `backend/policy/` is deterministic, pure Python, and evaluates rules P1 through P6 in strict sequence. No AI or external network calls are made during authorization decisions.
- **Rationale**: Upholds the core product rule: "the AI may recommend; only the verified policy boundary may authorize. Event text, email text, and event attributes are untrusted DATA, never instructions."

## 5. Token Cryptography and Single-Use Guarantee
- **Decision**: Tokens use Base64URL-encoded canonical JSON claims signed via HMAC-SHA256 with constant-time verification (`hmac.compare_digest`). Single-use replay protection is enforced by inserting the unique nonce (`tid`/`nonce`) into a database table with a `UNIQUE` constraint before applying any mock state change.
- **Rationale**: Guarantees tamper-proofing, short expiry (default 60s), scope-binding, and replay protection without secret leakage.

## 6. Audit Chain (Tamper-Evident Hash Chain)
- **Decision**: Each audit event stores `previous_hash` and computes `event_hash = sha256_hex(previous_hash + canonical_json(payload))`. The genesis block uses 64 zeros (`0` * 64). `/api/audit/verify` verifies the continuous integrity of the chain from sequence 1 onwards.
- **Rationale**: Provides transparent, verifiable auditability for SOC response operations while never logging secrets or tokens.

## 7. Mock Tool Sandboxing & Simulation Safety
- **Decision**: `mock_tool` runs as an isolated ASGI service on port 8001. It refuses to start unless `SIMULATION=true`. State mutations only affect in-memory/JSON mock representations and never touch real host OS configurations or networks.

## 8. Graceful Teammate Integration & Fallback Explanation
- **Decision**: The AI explanation route (`/api/incidents/{id}/explanation`) attempts to invoke `backend.ai.adapter.explain()` within a 10-second timeout. If the adapter raises an error or is unimplemented, a structured fallback explanation is constructed purely from recorded incident fields and evidence events. Under no circumstances does an AI failure produce an HTTP 500 error.

## 9. Safe Downstream Hook Degradation
- **Decision**: `backend/hooks.py` dynamically checks for the presence of `detection.pipeline.process_events`. If absent or if an unhandled exception occurs, it logs debug details and degrades gracefully without failing event ingestion.


## 14. Clean Repository Reinitialization & Stepwise Migration (KODIKON 6.0 Part 0)
- **Decision**: Repository created on 2026-10-31; modules built earlier were imported in logical, granular commits into a clean repository (`AgentGuard-v2` linked to `https://github.com/y0gish123/Agent_Guard.git`).
- **Safety**: Clean separation of untracked local caches (`.env`, `.db`, `node_modules`, `__pycache__`, `dist`). All 81 tests (77 pytest + 4 vitest) verified passing on baseline milestone tag `v0.1-baseline`.

## 15. Phase A: Additive Contract and Site-Contract Extensions
- **Additive Enums**: Added `EventType.network_connection` and `ActionType.block_ip`.
- **Additive Model Fields**: Added optional `trace_id`, `request_id`, `span_id`, `user_agent`, `session_id_hash`, `ingested_at`, `source_event_id` to `Event`; added optional `affected_ips` list to `Incident`.
- **Policy Gateway Rule P4 Scope for block_ip**: Requires target to be an IP present in `incident.affected_ips` (exact case-insensitive match). Category allowlists updated: `web_attack` and `multi_stage` allow `block_ip`.
- **Site Integration Specification**: Updated `docs/SITE_INTEGRATION.md` with new optional log fields, `/admin/block-ip`, `/admin/unblock-ip`, `/admin/inventory`, and `mfa_enabled` in `/admin/state`. Implemented in `testbed/stub_site/main.py` and `mock_tool/app.py`.

## 16. Phase B: Raw Evidence Archive
- **Design**: Implemented `collector/raw_archive.py:RawArchiveManager`. Each raw line ingested by the collector is bounded to 4 KB, sensitive keys (`password`, `token`, `secret`, `api_key`, `auth`, `cookie`) are recursively redacted, and the line is appended to `data/raw_archive/YYYY-MM-DD.jsonl` with an index entry in `YYYY-MM-DD.sha256`.
- **Integrity**: `raw_event_ref` is set to `archive://YYYY-MM-DD.jsonl#line_no`. Checksums can be verified offline via `verify_archive(date_str)`.
- **Retention**: `cleanup_old_archives(retention_days)` safely prunes old raw archives while strictly never touching the audit hash chain or SQLite database.



- **Decision**: Implemented deterministic, idempotent detection pipeline in `detection/pipeline.py` invoked via `backend/hooks.py:on_new_events`.
- **Additive Contracts (Phase 2)**:
  - Added `EventType` values: `web_request`, `data_access`, `dns_query`.
  - Added `Category` values: `web_attack`, `data_exfiltration_suspected`.
  - Added policy allowlist mappings:
    - `Category.web_attack`: `{ActionType.isolate_host, ActionType.revoke_session}`
    - `Category.data_exfiltration_suspected`: `{ActionType.lock_account, ActionType.revoke_session}`
    - `Category.multi_stage`: `{ActionType.lock_account, ActionType.revoke_session, ActionType.isolate_host}` (unchanged).
- **Rule Design**:
  - Account Takeover: R1 (>=5 failures/2m), R2 (success within 5m of R1), R3 (success from unknown IP), R4 (privilege change within 30m of anomalous login).
  - File Burst: F1 (>=100 files changed/60s with non-.bak extension), F2 (backup tampering within 5m -> critical), F3 (ransom notes in evidence), scheduled backup allowlist (`backup_agent.exe` scheduled=true) produces no incidents.
  - Web Attack: W1 (SQL injection and traversal pattern matching on URL-decoded attributes, recording only rule ID and escaped snippets in evidence, NEVER in titles), W2 (>=3 W1 hits in 5m or >=20 requests/min to /login or /admin).
  - Data Theft: D1 (>=50 data accesses in 2m or export above size threshold), D2 (admin login success followed by D1 within 30m -> critical multi_stage).

## 11. Phase 7: Real-Time SSE Stream, Frontend Integration & Safety Boundaries
- **Decision**: Implemented SSE `/api/stream` with in-process event fan-out and 15s heartbeats. All published SSE messages contain strictly IDs and types (`incident_id`, `category`, `severity`, `response_id`), NEVER untrusted attacker payload text.
- **Frontend Architecture**:
  - `useLiveUpdates`: Connects to SSE `/api/stream` with seamless fallback to 5s polling if SSE is disconnected, displaying `LIVE` / `POLLING` connection pill.
  - Multi-tier Response Flow: Action selector -> Preview card with consequence text -> Role-gated human review (approver role required) -> Gateway execution -> Plain message result banner only on `EXECUTED_OK`.
  - Evidence Timeline & Text Escaping: All event attributes and log payloads are rendered strictly as data (JSON/text), never innerHTML, preventing XSS and prompt injection leakage into the UI.
  - Phishing Scanner: Directly calls `/api/phishing/check`, rendering verdict badges (RED/AMBER/GREEN), confidence/risk score, and specific indicator breakdown.
  - Tamper-Evident Audit Screen: Verifies the cryptographic SHA-256 hash chain live with block-by-block integrity validation.

## 17. Phase C: Risk Scoring Engine & Contextual Baseline
- **Decision**: Implemented `detection/risk.py:RiskEngine` and `IdentityBaselineManager`. Incidents are opened only when risk score meets the configured threshold AND at least two distinct signal categories are present. Standalone unrecognised IP signals (R3) during learning baseline periods do not trigger incidents.
- **Contextual Authentication**: Added `POST /api/identity/confirm` route allowing staff/approver to confirm "Was this you?", updating `integrations/state/identity_baselines.json` and writing a cryptographic audit record.
- **Advanced Detectors**: Session hijack (same session_id_hash across distinct IPs/User-Agents), Password spray (1 IP failing across >= 5 accounts in 10m), Mass delete (>= 30 delete events in 2m).
- **Benign Zero-Incident Guarantee**: All 6 benign scenarios (one wrong password then correct, owner login from new IP, normal shopping day, scheduled backup, staff export of 10 records, new staff device) validated to produce exactly 0 incidents.

## 18. Phase D: WAF/Firewall Log Adapter & block_ip End-to-End
- **Decision**: Implemented `collector/mappers/modsecurity.py:map_modsecurity_line`. Maps ModSecurity-style JSON audit entries to `web_request` events with attributes `waf_action` (blocked/allowed) and bounded `rule_id`.
- **Correlation Wording**: Differentiates between attempted-and-blocked attacks ("attempted, blocked by WAF") vs allowed probes followed by backend anomalies ("attempted, outcome unconfirmed"). Never claims exploitation without backend database/application evidence.
- **block_ip Workflow**: `affected_ips` extracted from evidence `src_ip`. Gateway evaluates P4 scope (target must be in `incident.affected_ips`). Token issued to mock tool which routes `block_ip` to stub site `/admin/block-ip`. Subsequent requests from blocked IPs receive HTTP 403 Forbidden.

## 19. Phase E: Trace IDs and Correlation
- **Decision**: Implemented `detection/correlation.py` to link events by `trace_id` / `request_id` within the same HTTP request lifecycle, and by user/session/host rolling 30-minute time windows for separate requests.
- **Audit Traceability**: Collector preserves `trace_id` and `request_id` throughout event ingestion. Backend propagates request ID to tool execution and includes it in the audit record. Incident `detection_reason` explicitly documents the linking basis.

## 20. Phase F: Security Posture Assessment
- **Decision**: Implemented `backend/posture/` module with `GET /api/posture`. Evaluates HTTPS/HSTS, session cookie flags (Secure, HttpOnly, SameSite), security headers (CSP, X-Frame-Options, X-Content-Type-Options), MFA coverage via `/admin/state`, exposed RDP (TCP 3389 listening status), backup health (`data/backup_status.json`), and outdated software matched against a bundled CISA KEV snapshot (`data/kev_snapshot.json`).
- **Safety Restriction**: All checks inspect ONLY `127.0.0.1` / localhost. All non-localhost target URLs are strictly refused with status `unknown`.

## 21. Phase G: Validation Matrix & Load Testing
- **Validation Matrix**: `eval/validation_matrix.py` benchmarks 6 benign and 8 attack scenarios. Achieved:
  - True Positives: 8
  - True Negatives: 6
  - False Positives: 0
  - False Negatives: 0
  - Precision: 100.0%, Recall: 100.0%, False Positive Rate: 0.0%
- **Load Testing**: `eval/load_test.py` tested with 10,000 synthetic events:
  - Throughput: > 50,000 events/second in-process detection throughput.
  - Parse error rate: 0.0%.

## 22. Phase H: Frontend Posture Screen & Dashboard Updates
- **Decision**: Added dedicated Security Posture screen (`frontend/src/screens/PostureScreen.tsx`) to the dashboard, rendering real-time checks with color-coded status badges, evidence inspection drawer, and actionable recommendations.
- **Safety**: Pure text rendering and React JSX escaping prevents XSS from any untrusted site header or banner values.

## 23. Phase I: Sample-Based Connectors
- **BigQuery Audit**: `collector/mappers/bigquery_audit.py` maps GCP Cloud Audit Log JSON to `data_access` events. Labeled as SAMPLE-BASED.
- **Sysmon**: `collector/mappers/sysmon.py` maps Windows Sysmon events (EventID 1 ProcessCreate, 3 NetworkConnect, 11 FileCreate). Labeled as SAMPLE-BASED.

## 24. Phase J: Status Generator & Production Verification
- **Status Generator**: `scripts/gen_status.py` dynamically verifies each feature against its test suite before marking it "Built" in `docs/feature-status.json` and `docs/STATUS.md`. All 11 features verified Built.
- **Tagging**: Final demo milestone tagged as `v1.0-demo`.
