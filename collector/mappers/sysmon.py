"""Sysmon event log mapper for AgentGuard collector.

Maps Sysmon-style events (EventID 1=ProcessCreate, 3=NetworkConnect, 11=FileCreate)
to AgentGuard Event contracts.
Label: SAMPLE-BASED — tested on Sysmon-format sample events.

Sysmon EventID mapping:
  1  → process_start
  3  → network_connection
  11 → file_created (triggers file_change_burst if >= 100 in 60s on same host)

Detection rules:
  - Unusual process chain: Office app (winword.exe, excel.exe) spawning command shell (cmd.exe, powershell.exe)
  - Process followed by file burst on same host → included in ransomware detection pipeline
  - Network connection to non-RFC1918 IP from a process that spawned from Office
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional

from shared.contracts import Event, EventType, Severity, Source

_OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "onenote.exe"}
_SHELL_PROCESSES = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
_RFC1918 = [("10.", 8), ("172.16.", 16), ("192.168.", 24), ("127.", 8)]


def _is_private_ip(ip: str) -> bool:
    for prefix, _ in _RFC1918:
        if ip.startswith(prefix):
            return True
    return False


def _parse_ts(ts_str: Optional[str]) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        s = ts_str.rstrip("Z") + "+00:00" if ts_str.endswith("Z") else ts_str
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def map_sysmon_line(raw_line: str, filename: str, line_no: int) -> Optional[Event]:
    """Map one Sysmon JSON event to an AgentGuard Event.

    SAMPLE-BASED: tested on Sysmon-format sample events.
    """
    if not raw_line or not raw_line.strip():
        return None
    try:
        data: Dict[str, Any] = json.loads(raw_line.strip())
    except Exception:
        return None

    event_id_sysmon = int(data.get("EventID", 0))
    ts = _parse_ts(data.get("UtcTime") or data.get("timestamp"))
    host_id = str(data.get("Computer", "unknown-host"))[:100]
    user = str(data.get("User", ""))[:100] or None
    process_guid = str(data.get("ProcessGuid", ""))[:64]
    parent_image = str(data.get("ParentImage", "")).lower()
    image = str(data.get("Image", "")).lower()

    hash_input = f"sysmon:{filename}:{line_no}:{raw_line}".encode("utf-8")
    evt_id = f"evt-sys-{hashlib.sha256(hash_input).hexdigest()[:8]}"

    attrs: Dict[str, Any] = {
        "sysmon_event_id": event_id_sysmon,
        "process_guid": process_guid[:64],
        "image": image[:200],
        "parent_image": parent_image[:200],
    }

    if event_id_sysmon == 1:  # ProcessCreate
        # Detect unusual parent-child chain (Office → shell)
        parent_proc = parent_image.split("\\")[-1] if "\\" in parent_image else parent_image
        child_proc = image.split("\\")[-1] if "\\" in image else image

        is_suspicious = parent_proc in _OFFICE_PROCESSES and child_proc in _SHELL_PROCESSES
        severity = Severity.high if is_suspicious else Severity.low

        attrs["command_line"] = str(data.get("CommandLine", ""))[:300]
        attrs["parent_proc"] = parent_proc[:100]
        attrs["child_proc"] = child_proc[:100]
        if is_suspicious:
            attrs["suspicious_chain"] = f"{parent_proc} → {child_proc}"

        return Event(
            event_id=evt_id,
            timestamp=ts,
            source=Source.collector,
            host_id=host_id,
            user_id=user,
            event_type=EventType.process_start,
            severity=severity,
            raw_event_ref=f"{filename}#{line_no}"[:200],
            attributes=attrs,
            trace_id=process_guid or None,
            source_event_id=process_guid or None,
            schema_version="1.0",
        )

    elif event_id_sysmon == 3:  # NetworkConnect
        dest_ip = str(data.get("DestinationIp", "127.0.0.1"))[:64]
        dest_port = int(data.get("DestinationPort", 0))
        src_ip = str(data.get("SourceIp", "127.0.0.1"))[:64]

        is_external = not _is_private_ip(dest_ip)
        severity = Severity.medium if is_external else Severity.low

        attrs["src_ip"] = src_ip
        attrs["dest_ip"] = dest_ip
        attrs["dest_port"] = dest_port
        attrs["external"] = is_external

        return Event(
            event_id=evt_id,
            timestamp=ts,
            source=Source.collector,
            host_id=host_id,
            user_id=user,
            event_type=EventType.network_connection,
            severity=severity,
            raw_event_ref=f"{filename}#{line_no}"[:200],
            attributes=attrs,
            trace_id=process_guid or None,
            schema_version="1.0",
        )

    elif event_id_sysmon == 11:  # FileCreate
        file_path = str(data.get("TargetFilename", ""))[:300]
        attrs["file_path"] = file_path

        return Event(
            event_id=evt_id,
            timestamp=ts,
            source=Source.collector,
            host_id=host_id,
            user_id=user,
            event_type=EventType.file_created,
            severity=Severity.low,
            raw_event_ref=f"{filename}#{line_no}"[:200],
            attributes=attrs,
            schema_version="1.0",
        )

    return None


def map_sysmon_file(path: str) -> List[Event]:
    """Map a JSONL Sysmon file to Events. SAMPLE-BASED."""
    events = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                ev = map_sysmon_line(line.strip(), filename=path, line_no=i + 1)
                if ev:
                    events.append(ev)
    except Exception:
        pass
    return events

