"""Log line to Event contract mapper for AgentGuard collector."""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, Optional

from shared.contracts import Event, EventType, Severity, Source

# Baselines for known IPs
KNOWN_IPS = {"192.168.1.10", "192.168.1.50", "192.168.1.51", "10.0.0.15", "10.0.0.16", "127.0.0.1", "localhost"}


def _parse_ts(ts_str: Optional[str]) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


def map_log_line_to_event(log_type: str, raw_line: str, filename: str, line_no: int) -> Optional[Event]:
    """Map a single JSON-lines entry to a validated Event contract model."""
    if not raw_line or not raw_line.strip():
        return None

    import json
    try:
        data = json.loads(raw_line.strip())
    except Exception:
        return None

    ts = _parse_ts(data.get("ts"))
    host_id = str(data.get("host_id", "clinic-web-01"))[:100]
    raw_ref = f"{filename}#{line_no}"[:200]

    # Generate deterministic event_id: evt-col-<8hex>
    hash_input = f"{filename}:{line_no}:{raw_line}".encode("utf-8")
    event_id = f"evt-col-{hashlib.sha256(hash_input).hexdigest()[:8]}"

    if log_type == "auth":
        event_name = str(data.get("event", "")).lower()
        attempted_user = str(data.get("attempted_username", ""))[:300]
        user_id = data.get("username")
        resolved_user = str(user_id) if user_id else (attempted_user or None)
        src_ip = str(data.get("src_ip", "127.0.0.1"))[:100]

        # Determine EventType & Severity
        if event_name == "login_failed":
            event_type = EventType.authentication_failure
            severity = Severity.medium
        elif event_name == "login_success":
            event_type = EventType.authentication_success
            severity = Severity.medium if src_ip not in KNOWN_IPS else Severity.low
        elif event_name == "role_changed":
            event_type = EventType.privilege_change
            severity = Severity.high
        elif event_name in ("account_locked", "sessions_revoked", "access_denied"):
            event_type = EventType.process_start
            severity = Severity.medium
        else:
            event_type = EventType.process_start
            severity = Severity.low

        attrs: Dict[str, Any] = {
            "src_ip": src_ip,
            "attempted_username": attempted_user,
            "event_action": event_name,
        }
        if data.get("detail"):
            for k, v in data["detail"].items():
                attrs[f"detail_{k}"] = str(v)[:200]

        return Event(
            event_id=event_id,
            timestamp=ts,
            source=Source.collector,
            host_id=host_id,
            user_id=resolved_user,
            event_type=event_type,
            severity=severity,
            raw_event_ref=raw_ref,
            attributes=attrs,
            schema_version="1.0",
        )

    elif log_type == "access":
        src_ip = str(data.get("src_ip", "127.0.0.1"))[:100]
        path = str(data.get("path", ""))[:300]
        query = str(data.get("query", ""))[:1000]
        method = str(data.get("method", "GET"))[:10]
        status = int(data.get("status", 200))
        num_bytes = int(data.get("bytes", 0))
        user_id = str(data.get("username")) if data.get("username") else None

        attrs = {
            "src_ip": src_ip,
            "path": path,
            "query": query,
            "method": method,
            "status": status,
            "bytes": num_bytes,
        }

        return Event(
            event_id=event_id,
            timestamp=ts,
            source=Source.collector,
            host_id=host_id,
            user_id=user_id,
            event_type=EventType.web_request,
            severity=Severity.medium if status >= 400 else Severity.low,
            raw_event_ref=raw_ref,
            attributes=attrs,
            schema_version="1.0",
        )

    elif log_type == "data":
        user_id = str(data.get("username", "anonymous"))[:100]
        action = str(data.get("action", "view_record"))[:50]
        record_count = int(data.get("record_count", 1))
        num_bytes = int(data.get("bytes", 0))
        src_ip = str(data.get("src_ip", "127.0.0.1"))[:100]

        attrs = {
            "action": action,
            "record_count": record_count,
            "bytes": num_bytes,
            "src_ip": src_ip,
        }

        # Elevated severity for bulk exports
        severity = Severity.high if (action == "export" or record_count >= 50) else Severity.low

        return Event(
            event_id=event_id,
            timestamp=ts,
            source=Source.collector,
            host_id=host_id,
            user_id=user_id,
            event_type=EventType.data_access,
            severity=severity,
            raw_event_ref=raw_ref,
            attributes=attrs,
            schema_version="1.0",
        )

    return None

