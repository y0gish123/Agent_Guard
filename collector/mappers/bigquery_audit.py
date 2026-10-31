"""Google Cloud Audit Log mapper for AgentGuard collector.

Maps GCP audit-log style JSON entries to data_access Events.
Label: SAMPLE-BASED — not connected to a live Google Cloud project.
Tested against the sample in docs/samples/bigquery_audit_sample.json.

Input format (GCP Cloud Audit Log export):
{
  "insertId": "abc123",
  "timestamp": "2026-10-31T14:00:00Z",
  "protoPayload": {
    "authenticationInfo": {"principalEmail": "user@example.com"},
    "methodName": "google.bigquery.v2.TableDataService.list",
    "resourceName": "projects/my-project/datasets/patients/tables/records",
    "requestMetadata": {
      "callerIp": "1.2.3.4"
    }
  },
  "resource": {"type": "bigquery_dataset", "labels": {"project_id": "my-project"}},
  "labels": {"bytes_processed": "40960"}
}
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, Optional

from shared.contracts import Event, EventType, Severity, Source


def _parse_ts(ts_str: Optional[str]) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        s = ts_str.rstrip("Z") + "+00:00" if ts_str.endswith("Z") else ts_str
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def map_bigquery_audit_entry(entry: Dict[str, Any], source_file: str = "bigquery_audit", line_no: int = 0) -> Optional[Event]:
    """Map one GCP Cloud Audit Log entry to a data_access Event.

    SAMPLE-BASED: not connected to a live GCP project.
    """
    try:
        insert_id = str(entry.get("insertId", ""))[:64]
        ts = _parse_ts(entry.get("timestamp") or entry.get("receiveTimestamp"))

        proto = entry.get("protoPayload", {})
        auth_info = proto.get("authenticationInfo", {})
        principal = str(auth_info.get("principalEmail", auth_info.get("principal", "unknown")))[:100]
        method = str(proto.get("methodName", "unknown"))[:100]
        resource = str(proto.get("resourceName", ""))[:200]
        req_meta = proto.get("requestMetadata", {})
        caller_ip = str(req_meta.get("callerIp", "127.0.0.1"))[:64]
        user_agent = str(req_meta.get("callerSuppliedUserAgent", ""))[:300] or None

        labels = entry.get("labels", {})
        bytes_processed = int(labels.get("bytes_processed", 0))

        # Determine action from method name
        method_lower = method.lower()
        if "list" in method_lower or "get" in method_lower or "read" in method_lower:
            action = "read"
        elif "insert" in method_lower or "create" in method_lower:
            action = "write"
        elif "delete" in method_lower or "drop" in method_lower:
            action = "delete"
        elif "export" in method_lower:
            action = "export"
        elif "query" in method_lower:
            action = "query"
        else:
            action = "access"

        hash_input = f"bq:{source_file}:{line_no}:{insert_id}:{method}".encode("utf-8")
        event_id = f"evt-bq-{hashlib.sha256(hash_input).hexdigest()[:8]}"

        severity = Severity.high if (action in ("export", "delete") or bytes_processed >= 50000) else Severity.low

        return Event(
            event_id=event_id,
            timestamp=ts,
            source=Source.collector,
            host_id=None,
            user_id=principal,
            event_type=EventType.data_access,
            severity=severity,
            raw_event_ref=f"{source_file}#{line_no}"[:200],
            attributes={
                "action": action,
                "method": method[:100],
                "resource": resource[:200],
                "bytes": bytes_processed,
                "src_ip": caller_ip,
                "insert_id": insert_id,
            },
            trace_id=insert_id or None,
            request_id=insert_id or None,
            span_id=None,
            user_agent=user_agent,
            session_id_hash=None,
            source_event_id=insert_id or None,
            schema_version="1.0",
        )
    except Exception:
        return None


def map_bigquery_audit_file(path: str) -> list:
    """Map a JSON file (array or single object) of GCP audit log entries to Events.

    SAMPLE-BASED: not connected to a live GCP project.
    """
    events = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            entries = data
        else:
            entries = [data]
        for i, entry in enumerate(entries):
            ev = map_bigquery_audit_entry(entry, source_file=path, line_no=i)
            if ev:
                events.append(ev)
    except Exception:
        pass
    return events

