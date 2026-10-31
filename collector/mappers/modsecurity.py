"""ModSecurity JSON audit log mapper for AgentGuard collector.

Maps ModSecurity-style JSON audit entries to web_request Events.
Label: SIMULATION - tested on ModSecurity-format sample events, not connected to a live WAF.

Input format (one JSON object per line):
{
  "unique_id": "...",
  "timestamp": "2026-10-31T14:00:00Z",
  "client_ip": "1.2.3.4",
  "uri": "/admin/login",
  "method": "POST",
  "status": 403,
  "action": "blocked",       # "blocked" | "allowed"
  "rule_id": "941100",
  "rule_message": "XSS Attack Detected via libinjection",
  "bytes": 1234
}
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, Optional

from shared.contracts import Event, EventType, Severity, Source


_MAX_RULE_ID_LEN = 32
_MAX_MSG_LEN = 200
_MAX_URI_LEN = 300
_MAX_IP_LEN = 64


def _parse_ts(ts_str: Optional[str]) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        s = ts_str.rstrip("Z") + "+00:00" if ts_str.endswith("Z") else ts_str
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


def map_modsecurity_line(raw_line: str, filename: str, line_no: int) -> Optional[Event]:
    """Map one ModSecurity JSON audit entry to an Event. Returns None on parse error.

    WAF outcome wording:
    - action=blocked  → waf_action="blocked"  → detection_reason includes "attempted, blocked"
    - action=allowed  → waf_action="allowed"  → detection_reason includes "attempted, outcome unconfirmed"
    """
    if not raw_line or not raw_line.strip():
        return None
    try:
        data: Dict[str, Any] = json.loads(raw_line.strip())
    except Exception:
        return None

    # Deterministic event_id from filename + line_no + raw content
    hash_input = f"waf:{filename}:{line_no}:{raw_line}".encode("utf-8")
    event_id = f"evt-waf-{hashlib.sha256(hash_input).hexdigest()[:8]}"

    ts = _parse_ts(data.get("timestamp") or data.get("ts"))

    client_ip = str(data.get("client_ip", "127.0.0.1"))[:_MAX_IP_LEN]
    uri = str(data.get("uri", "/"))[:_MAX_URI_LEN]
    method = str(data.get("method", "GET"))[:10]
    http_status = int(data.get("status", 0))
    raw_action = str(data.get("action", "allowed")).lower()[:20]
    waf_action = "blocked" if raw_action == "blocked" else "allowed"
    rule_id = str(data.get("rule_id", ""))[:_MAX_RULE_ID_LEN]
    rule_message = str(data.get("rule_message", ""))[:_MAX_MSG_LEN]
    num_bytes = int(data.get("bytes", 0))
    unique_id = str(data.get("unique_id", ""))[:64]
    host_id = str(data.get("host_id", "clinic-web-01"))[:100]

    # Use unique_id as both trace_id and request_id if present
    trace_id = unique_id or None
    request_id = unique_id or None

    severity = Severity.high if waf_action == "blocked" else Severity.medium

    attrs: Dict[str, Any] = {
        "src_ip": client_ip,
        "path": uri,
        "method": method,
        "status": http_status,
        "bytes": num_bytes,
        "waf_action": waf_action,
        "rule_id": rule_id,
    }
    # Rule message is bounded and treated as structured data, not free text
    if rule_message:
        attrs["rule_message"] = rule_message

    return Event(
        event_id=event_id,
        timestamp=ts,
        source=Source.collector,
        host_id=host_id,
        user_id=None,   # WAF logs do not carry authenticated user identity
        event_type=EventType.web_request,
        severity=severity,
        raw_event_ref=f"{filename}#{line_no}"[:200],
        attributes=attrs,
        trace_id=trace_id,
        request_id=request_id,
        span_id=None,
        user_agent=str(data.get("user_agent", ""))[:500] or None,
        session_id_hash=None,
        source_event_id=unique_id or None,
        schema_version="1.0",
    )


def waf_outcome_label(event: Event) -> str:
    """Return human-readable WAF outcome for correlation wording.

    Used by detection to produce different incident wording based on WAF action.
    """
    action = event.attributes.get("waf_action", "unknown")
    if action == "blocked":
        return "attempted, blocked by WAF"
    elif action == "allowed":
        return "attempted, outcome unconfirmed (WAF allowed)"
    return "attempted, WAF outcome unknown"

