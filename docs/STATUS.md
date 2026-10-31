# AgentGuard Feature Status

Generated: 2026-10-31T17:38:56Z

> [!NOTE]
> A feature is marked **Built** only if its automated test suite passes.
> SAMPLE-BASED features use synthetic data and are not connected to live systems.

| Feature | Status | Description |
|---------|--------|-------------|
| Deterministic Policy Gateway | ✅ Built | P1-P6 rules: only authorizes when all checks pass. AI only recommends. |
| Tamper-Evident Audit Chain | ✅ Built | SHA256 hash chain; /api/audit/verify detects tampering. |
| Raw Evidence Archive (Phase B) | ✅ Built | 4KB-capped append-only archive with SHA256 checksums and retention cleanup. |
| Risk Scoring Engine (Phase C) | ✅ Built | Weighted multi-signal risk engine, session hijack, password spray, mass delete d |
| WAF/ModSecurity Log Adapter (Phase D) | ✅ Built | Maps ModSecurity JSON audit entries to web_request events. SAMPLE-BASED. |
| Trace ID Correlation (Phase E) | ✅ Built | Links events by trace_id/request_id or user/session/time window. |
| Security Posture Assessment (Phase F) | ✅ Built | HTTPS/HSTS, cookie flags, security headers, MFA, RDP, backup, KEV check. Localho |
| Validation Matrix (Phase G) | ✅ Built | 6 benign / 8 attack scenarios; TP/FP/TN/FN, precision, recall. |
| Sample-Based Connectors (Phase I) | ✅ Built | BigQuery audit log and Sysmon event mappers. SAMPLE-BASED, not live. |
| Phishing Scoring | ✅ Built | Deterministic rule-based phishing scorer with verdict red/amber/green. |
| Contract Extensions (Phase A) | ✅ Built | block_ip action, network_connection event, optional trace/session fields, affect |