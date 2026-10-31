# AgentGuard - Victim Site Integration Specification

This document specifies the exact contract a clinic web application must meet to integrate with the AgentGuard AI SOC telemetry pipeline and automated response gateway.

---

## 1. Overview Architecture

```
[ Victim Clinic Website ] (Port 8002 / custom)
    │
    ├── 1. Writes JSON-lines logs to disk:
    │      ├── auth.log       (login, logout, privilege changes, lockouts)
    │      ├── access.log     (HTTP requests, status, queries)
    │      └── data.log       (patient chart access, exports)
    │
    └── 2. Exposes Admin API (Port 8002) protected by X-Admin-Key
           ├── POST /admin/lock
           ├── POST /admin/unlock
           ├── POST /admin/revoke-sessions
           ├── POST /admin/isolate
           ├── POST /admin/unisolate
           └── GET  /admin/state

        ▲
        │ Calls via Verified Token Gateway
[ Mock Tool / Portal Gateway ] (Port 8001, TOOL_BACKEND=portal)
        ▲
        │ Signed HMAC-SHA256 Token
[ AgentGuard Backend ] (Port 8000)
        ▲
        │ Ingests batched events every 1s
[ AgentGuard Collector ] (collector/collector.py)
        │ Tails auth.log, access.log, data.log
```

---

## 2. Telemetry Log Formats (JSON Lines)

Each file receives one JSON object per line, UTF-8 encoded, with a trailing newline `\n`.

### (a) Auth Log: `auth.log`

Tails authentication and session lifecycle events.

| Field | Type | Required | Description |
|---|---|---|---|
| `ts` | string | Yes | UTC ISO-8601 with trailing `Z` (e.g. `2026-10-31T15:00:00Z`) |
| `event` | string | Yes | One of: `login_failed`, `login_success`, `role_changed`, `account_locked`, `sessions_revoked`, `access_denied` |
| `attempted_username` | string | Yes | Raw username entered in login form (capped at 300 chars) |
| `username` | string \| null | Yes | Resolved database username, or `null` if unauthenticated |
| `src_ip` | string | Yes | Client IP address (e.g. `192.168.1.50`, `203.0.113.50`) |
| `host_id` | string | Yes | Server hostname or machine ID (e.g. `clinic-web-01`) |
| `session_id_hash` | string \| null | No | SHA-256 prefix of session token (first 16 hex chars; NEVER raw session ID) |
| `detail` | object | No | Optional key-value metadata (e.g. `{"reason": "bad_password"}`) |

**Example Line:**
```json
{"ts":"2026-10-31T15:00:00Z","event":"login_failed","attempted_username":"priya.rec","username":null,"src_ip":"203.0.113.50","host_id":"clinic-web-01","session_id_hash":null,"detail":{"reason":"bad_password"}}
```

---

### (b) Web Access Log: `access.log`

Records incoming HTTP requests for web-attack detection (SQLi, path traversal, probing).

| Field | Type | Required | Description |
|---|---|---|---|
| `ts` | string | Yes | UTC ISO-8601 with trailing `Z` |
| `method` | string | Yes | HTTP method (`GET`, `POST`, `PUT`, `DELETE`) |
| `path` | string | Yes | URL request path (e.g. `/patients/view`) |
| `query` | string | Yes | Raw URL query string without leading `?` (e.g. `id=1%20OR%201=1`) |
| `status` | integer | Yes | HTTP response status code (e.g. `200`, `403`, `500`) |
| `bytes` | integer | Yes | Response body length in bytes |
| `src_ip` | string | Yes | Client IP address |
| `username` | string \| null | Yes | Authenticated user or `null` if anonymous |
| `host_id` | string | Yes | Server hostname |
| `trace_id` | string \| null | No | Optional distributed tracing ID / request ID |
| `user_agent` | string \| null | No | Optional client User-Agent string |
| `session_id_hash` | string \| null | No | Optional SHA-256 prefix of session token |

> **Graceful Degradation**: If the monitored site does not emit `trace_id`, `user_agent`, or `session_id_hash`, AgentGuard treats them as null/unknown and continues operating normally without guessing.

**Example Line:**
```json
{"ts":"2026-10-31T15:01:00Z","method":"GET","path":"/records","query":"id=1%20UNION%20SELECT%20username,password%20FROM%20users","status":200,"bytes":1024,"src_ip":"203.0.113.195","username":"priya.rec","host_id":"clinic-web-01"}
```

---

### (c) Data Access Log: `data.log`

Records electronic medical records (EMR) queries and exports to detect data theft.

| Field | Type | Required | Description |
|---|---|---|---|
| `ts` | string | Yes | UTC ISO-8601 with trailing `Z` |
| `username` | string | Yes | User who performed the action |
| `action` | string | Yes | One of: `view_record`, `export`, `search`, `delete` |
| `record_count` | integer | Yes | Number of patient records viewed or exported |
| `bytes` | integer | Yes | Approximate payload size in bytes |
| `src_ip` | string | Yes | Client IP address |
| `host_id` | string | Yes | Server hostname |
| `trace_id` | string \| null | No | Optional distributed tracing ID / request ID |
| `user_agent` | string \| null | No | Optional client User-Agent string |
| `session_id_hash` | string \| null | No | Optional SHA-256 prefix of session token |

> **Graceful Degradation**: If the monitored site does not emit `trace_id`, `user_agent`, or `session_id_hash`, AgentGuard treats them as null/unknown and continues operating normally without guessing.

**Example Line:**
```json
{"ts":"2026-10-31T15:02:00Z","username":"front.desk","action":"export","record_count":150,"bytes":85000,"src_ip":"192.168.1.51","host_id":"clinic-web-01"}
```

---

## 3. Site Admin API Specification

The victim website must provide an administrative endpoint listening on `localhost` (default port 8002). All mutation endpoints require the HTTP header:
```http
X-Admin-Key: <SITE_ADMIN_KEY>
```

### Endpoints

| Method | Path | Request Body | Description |
|---|---|---|---|
| `POST` | `/admin/lock` | `{"username": "<user>"}` | Locks the account. Future logins return HTTP 423 Locked. |
| `POST` | `/admin/unlock` | `{"username": "<user>"}` | Unlocks the account. |
| `POST` | `/admin/revoke-sessions` | `{"username": "<user>"}` | Invalidate all active sessions for the user. |
| `POST` | `/admin/isolate` | `{"host_id": "<host>"}` | Put host in isolation/maintenance mode. Logins return 503. |
| `POST` | `/admin/unisolate` | `{"host_id": "<host>"}` | Removes host isolation mode. |
| `POST` | `/admin/block-ip` | `{"ip": "<ip>", "ttl_seconds": 3600}` | Blocks IP. Blocked IPs receive HTTP 403. Optional TTL. |
| `POST` | `/admin/unblock-ip` | `{"ip": "<ip>"}` | Unblocks a previously blocked IP. |
| `GET` | `/admin/inventory` | None | Returns component software manifest (name, version). |
| `GET` | `/admin/state` | None | Returns accounts (incl. optional `mfa_enabled`), sessions, and status. |
| `POST` | `/admin/reset` | None | Resets state to clean demonstration baseline. |

> **Graceful Degradation**: If `/admin/block-ip` or `/admin/inventory` are not implemented by the external site, AgentGuard falls back to mock shadow state for IP blocks and reports software posture as "unknown".

### Expected Response Format
All admin calls return JSON:
```json
{
  "ok": true,
  "action": "lock",
  "target": "priya.rec",
  "status": "locked"
}
```

---

## 4. Copy-Paste Code Snippets for Victim Site

### Python (FastAPI / Flask)
```python
import json
from datetime import datetime, timezone

def log_auth_event(event_type: str, attempted: str, user: str, ip: str, host: str = "clinic-web-01"):
    payload = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": event_type,
        "attempted_username": attempted[:300],
        "username": user,
        "src_ip": ip,
        "host_id": host,
        "session_id_hash": None,
        "detail": {},
    }
    with open("./site_logs/auth.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")
```

### Node.js (Express)
```javascript
const fs = require('fs');

function logAuthEvent(eventType, attempted, user, ip, host = "clinic-web-01") {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    event: eventType,
    attempted_username: String(attempted).slice(0, 300),
    username: user || null,
    src_ip: ip,
    host_id: host,
    session_id_hash: null,
    detail: {}
  });
  fs.appendFileSync('./site_logs/auth.log', line + '\n', 'utf8');
}
```

### PHP
```php
function log_auth_event($event_type, $attempted, $user, $ip, $host = "clinic-web-01") {
    $data = [
        "ts" => gmdate("Y-m-d\TH:i:s\Z"),
        "event" => $event_type,
        "attempted_username" => substr($attempted, 0, 300),
        "username" => $user ?: null,
        "src_ip" => $ip,
        "host_id" => $host,
        "session_id_hash" => null,
        "detail" => []
    ];
    file_put_contents('./site_logs/auth.log', json_encode($data) . "\n", FILE_APPEND | LOCK_EX);
}
```

---

## 5. Integration Checklist

- [ ] Site binds strictly to `localhost` (`127.0.0.1:8002`).
- [ ] Passwords stored using PBKDF2, bcrypt, or SHA-256 with salt.
- [ ] Uses only synthetic/fake patient data.
- [ ] Writes `auth.log`, `access.log`, `data.log` in exact JSON-lines format.
- [ ] Implements `/admin/lock`, `/admin/revoke-sessions`, `/admin/isolate`, `/admin/state`.
- [ ] Verifies `X-Admin-Key` header on all `/admin/*` mutation routes.

