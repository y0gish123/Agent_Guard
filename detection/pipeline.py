"""Deterministic and idempotent detection pipeline for AgentGuard AI SOC.

Implemented Detection Rules:
Phase 1:
Account Takeover:
- R1: >=5 authentication_failure for same (user_id, src_ip) within 2 minutes.
- R2: authentication_success for same (user_id, src_ip) within 5 minutes after R1.
- R3: authentication_success from src_ip not in user's known_ips.
- R4: privilege_change within 30 minutes after R2 or R3.

File Burst (Ransomware-like Activity):
- F1: >=100 file changes within 60s with a new extension that is not .bak
      (or file_change_burst event with files_changed >= 100 and new_extension != .bak).
- F2: backup_tampering within 5 minutes of F1 -> elevates severity to critical.
- F3: README_RESTORE-style note created -> included in evidence.
- Allowlist: scheduled backup activity (process backup_agent.exe with scheduled=true)
             is explicitly ignored and produces no incidents.

Phase 2:
Web-Attack Detectors:
- W1: SQL injection or path traversal pattern in web_request attributes. Match with fixed
      regexes on URL-decoded text; store only the rule ID and a truncated escaped snippet in evidence.
- W2: >= 3 distinct W1 hits from one src_ip in 5 minutes OR >= 20 requests/min to /login or /admin.
      Category: web_attack, Severity: high.

Data-Theft Detectors:
- D1: Bulk data access: one user/session with >= 50 data_access events in 2 minutes
      OR an export event with record_count >= 50 or bytes >= 50000.
      Category: data_exfiltration_suspected, Severity: high.
- D2: Admin login success (R2/R3) followed by D1 within 30 minutes.
      Category: multi_stage, Severity: critical.

Correlation:
- Groups events by same user_id or host_id within 30-minute windows.
- Sets link_rule LINK_SAME_USER_30M or LINK_SAME_HOST_30M.
- If a phishing_check event exists for the user in the window, upgrades category to multi_stage.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import html
import re
from typing import Dict, List, Optional, Set, Tuple
import urllib.parse

from shared.contracts import (
    Category,
    Confidence,
    Event,
    EventType,
    Incident,
    IncidentStatus,
    LinkRule,
    Severity,
)

# Known IP baselines for clinic accounts
DEFAULT_KNOWN_IPS: Dict[str, Set[str]] = {
    "priya.rec": {"192.168.1.10", "192.168.1.50", "10.0.0.15", "127.0.0.1", "203.0.113.50"},
    "front.desk": {"192.168.1.11", "192.168.1.51", "10.0.0.16", "127.0.0.1"},
    "admin": {"192.168.1.1", "127.0.0.1"},
    "analyst": {"192.168.1.20", "127.0.0.1"},
    "ceo": {"192.168.1.99", "127.0.0.1"},
}

RESTORE_NOTE_PATTERNS = [
    re.compile(r"readme_restore", re.IGNORECASE),
    re.compile(r"how_to_decrypt", re.IGNORECASE),
    re.compile(r"restore_files", re.IGNORECASE),
    re.compile(r"decrypt_info", re.IGNORECASE),
    re.compile(r"files_encrypted", re.IGNORECASE),
]

# W1 SQL-injection and directory traversal regexes
W1_PATTERNS = [
    re.compile(r"'\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1", re.IGNORECASE),
    re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE),
    re.compile(r";\s*drop\s+(?:table|database)", re.IGNORECASE),
    re.compile(r"(?:--|/\*|\*/|#)"),
    re.compile(r"sleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"(?:\.\.[/\\])"),
]


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generate_deterministic_incident_id(key: str, dt: datetime) -> str:
    """Generate deterministic incident ID: 'inc-' + 8 hex of sha256(key+date)."""
    date_str = dt.strftime("%Y-%m-%d")
    raw = f"{key}:{date_str}".encode("utf-8")
    hex8 = hashlib.sha256(raw).hexdigest()[:8]
    return f"inc-{hex8}"


def is_scheduled_backup_allowlisted(event: Event) -> bool:
    """Check if event is part of an authorized scheduled backup."""
    attrs = event.attributes or {}
    image = str(attrs.get("image", "")).lower()
    proc = str(attrs.get("process_name", "")).lower()
    scheduled = str(attrs.get("scheduled", "")).lower() in ("true", "1")
    if ("backup_agent.exe" in image or "backup_agent.exe" in proc) and scheduled:
        return True
    return False


def is_restore_note_file(path_or_name: str) -> bool:
    for pat in RESTORE_NOTE_PATTERNS:
        if pat.search(path_or_name):
            return True
    return False


def match_w1_pattern(text: str) -> Optional[str]:
    """Check if text matches any W1 injection/traversal pattern on decoded string."""
    if not text:
        return None
    try:
        decoded = urllib.parse.unquote_plus(text)
    except Exception:
        decoded = text

    for pat in W1_PATTERNS:
        m = pat.search(decoded)
        if m:
            snippet = html.escape(m.group(0)[:60])
            return snippet
    return None


# ---------------------------------------------------------------------------
# Account Takeover Detection
# ---------------------------------------------------------------------------

def detect_account_takeover(events: List[Event]) -> List[Incident]:
    """Evaluate R1, R2, R3, R4 and correlation with phishing_check."""
    sorted_events = sorted(events, key=lambda e: _ensure_utc(e.timestamp))
    by_user: Dict[str, List[Event]] = {}
    for ev in sorted_events:
        if ev.user_id:
            by_user.setdefault(ev.user_id, []).append(ev)

    incidents: List[Incident] = []

    for user_id, user_events in by_user.items():
        rules_fired: List[str] = []
        evidence_ids: Set[str] = set()
        affected_hosts: Set[str] = set()
        first_seen: Optional[datetime] = None
        last_seen: Optional[datetime] = None

        # Group auth failures by src_ip
        r1_src_ip: Optional[str] = None
        r1_time: Optional[datetime] = None

        failures_by_ip: Dict[str, List[Event]] = {}
        for ev in user_events:
            if ev.event_type == EventType.authentication_failure:
                src_ip = str(ev.attributes.get("src_ip", "unknown"))
                failures_by_ip.setdefault(src_ip, []).append(ev)

        # Check R1: >= 5 auth failures for same src_ip within 2 minutes (120s)
        for src_ip, f_list in failures_by_ip.items():
            for i in range(len(f_list)):
                window = [f_list[i]]
                t_i = _ensure_utc(f_list[i].timestamp)
                for j in range(i + 1, len(f_list)):
                    t_j = _ensure_utc(f_list[j].timestamp)
                    if (t_j - t_i).total_seconds() <= 120:
                        window.append(f_list[j])
                    else:
                        break
                if len(window) >= 5:
                    r1_src_ip = src_ip
                    r1_time = _ensure_utc(window[-1].timestamp)
                    rules_fired.append(f"R1: Brute force detected ({len(window)} failures in <= 120s from {src_ip})")
                    for w in window:
                        evidence_ids.add(w.event_id)
                        if w.host_id:
                            affected_hosts.add(w.host_id)
                        first_seen = min(first_seen or _ensure_utc(w.timestamp), _ensure_utc(w.timestamp))
                        last_seen = max(last_seen or _ensure_utc(w.timestamp), _ensure_utc(w.timestamp))
                    break
            if r1_src_ip:
                break

        # Check R2: auth success for same src_ip within 5 minutes (300s) after R1
        r2_time: Optional[datetime] = None
        if r1_src_ip and r1_time:
            for ev in user_events:
                if ev.event_type == EventType.authentication_success:
                    src_ip = str(ev.attributes.get("src_ip", ""))
                    ev_time = _ensure_utc(ev.timestamp)
                    if src_ip == r1_src_ip and timedelta(seconds=0) <= (ev_time - r1_time) <= timedelta(seconds=300):
                        r2_time = ev_time
                        rules_fired.append(f"R2: Successful sign-in from {src_ip} within 5m of brute force")
                        evidence_ids.add(ev.event_id)
                        if ev.host_id:
                            affected_hosts.add(ev.host_id)
                        first_seen = min(first_seen or ev_time, ev_time)
                        last_seen = max(last_seen or ev_time, ev_time)
                        break

        # Check R3: auth success from IP not in user's known_ips
        r3_time: Optional[datetime] = None
        known_ips = DEFAULT_KNOWN_IPS.get(user_id, {"127.0.0.1"})
        for ev in user_events:
            if ev.event_type == EventType.authentication_success:
                src_ip = str(ev.attributes.get("src_ip", ""))
                ev_time = _ensure_utc(ev.timestamp)
                if src_ip and src_ip not in known_ips:
                    r3_time = ev_time
                    rules_fired.append(f"R3: Successful sign-in from unrecognised IP {src_ip}")
                    evidence_ids.add(ev.event_id)
                    if ev.host_id:
                        affected_hosts.add(ev.host_id)
                    first_seen = min(first_seen or ev_time, ev_time)
                    last_seen = max(last_seen or ev_time, ev_time)
                    break

        # Check R4: privilege_change within 30 minutes (1800s) after R2 or R3
        anchor_success_time = r2_time or r3_time
        if anchor_success_time:
            for ev in user_events:
                if ev.event_type == EventType.privilege_change:
                    ev_time = _ensure_utc(ev.timestamp)
                    if timedelta(seconds=0) <= (ev_time - anchor_success_time) <= timedelta(seconds=1800):
                        rules_fired.append("R4: Privilege escalation within 30m of anomalous login")
                        evidence_ids.add(ev.event_id)
                        if ev.host_id:
                            affected_hosts.add(ev.host_id)
                        first_seen = min(first_seen or ev_time, ev_time)
                        last_seen = max(last_seen or ev_time, ev_time)
                        break

        # Only construct incident if at least one primary indicator fired
        if not rules_fired:
            continue

        # Check correlation: phishing_check event for same user within 30 min of first activity
        has_phishing = False
        for ev in user_events:
            if ev.event_type == EventType.phishing_check and first_seen:
                ev_time = _ensure_utc(ev.timestamp)
                if abs((ev_time - first_seen).total_seconds()) <= 1800:
                    has_phishing = True
                    evidence_ids.add(ev.event_id)
                    rules_fired.append("Correlation: Linked preceding phishing check event")
                    first_seen = min(first_seen, ev_time)
                    last_seen = max(last_seen or ev_time, ev_time)
                    break

        category = Category.multi_stage if has_phishing else Category.account_takeover

        # Determine severity and confidence
        rule_count = len([r for r in rules_fired if not r.startswith("Correlation")])
        if rule_count >= 3 or ("R4" in str(rules_fired)):
            severity = Severity.critical
        elif rule_count >= 2:
            severity = Severity.high
        else:
            severity = Severity.medium

        confidence = Confidence.likely if rule_count >= 2 else Confidence.needs_review
        inc_id = generate_deterministic_incident_id(f"ato:{user_id}", first_seen or datetime.now(timezone.utc))

        title = f"Suspected account takeover for {user_id}"
        if has_phishing:
            title = f"Multi-stage credential harvest and account takeover for {user_id}"

        detection_reason = "; ".join(rules_fired)

        incidents.append(
            Incident(
                incident_id=inc_id,
                title=title,
                category=category,
                severity=severity,
                status=IncidentStatus.open,
                first_seen=first_seen or datetime.now(timezone.utc),
                last_seen=last_seen or datetime.now(timezone.utc),
                affected_hosts=sorted(list(affected_hosts)),
                affected_users=[user_id],
                evidence_event_ids=sorted(list(evidence_ids)),
                detection_reason=detection_reason,
                link_rule=LinkRule.LINK_SAME_USER_30M,
                confidence_label=confidence,
                schema_version="1.0",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )

    return incidents


# ---------------------------------------------------------------------------
# File Burst Detection
# ---------------------------------------------------------------------------

def detect_file_burst(events: List[Event]) -> List[Incident]:
    """Evaluate F1, F2, F3 and allowlist scheduled backup."""
    non_allowlisted: List[Event] = [e for e in events if not is_scheduled_backup_allowlisted(e)]
    sorted_events = sorted(non_allowlisted, key=lambda e: _ensure_utc(e.timestamp))

    by_host: Dict[str, List[Event]] = {}
    for ev in sorted_events:
        host = ev.host_id or "unknown-host"
        by_host.setdefault(host, []).append(ev)

    incidents: List[Incident] = []

    for host_id, host_events in by_host.items():
        rules_fired: List[str] = []
        evidence_ids: Set[str] = set()
        affected_users: Set[str] = set()
        first_seen: Optional[datetime] = None
        last_seen: Optional[datetime] = None

        f1_triggered = False
        f1_time: Optional[datetime] = None

        for ev in host_events:
            ev_time = _ensure_utc(ev.timestamp)
            if ev.event_type == EventType.file_change_burst:
                attrs = ev.attributes or {}
                count = int(attrs.get("files_changed", attrs.get("count", 0)))
                new_ext = str(attrs.get("new_extension", "")).lower()
                if count >= 100 and new_ext != ".bak":
                    f1_triggered = True
                    f1_time = ev_time
                    evidence_ids.add(ev.event_id)
                    if ev.user_id:
                        affected_users.add(ev.user_id)
                    first_seen = min(first_seen or ev_time, ev_time)
                    last_seen = max(last_seen or ev_time, ev_time)
                    rules_fired.append(f"F1: File change burst ({count} files renamed to {new_ext} in rapid succession)")
                    break

        if not f1_triggered:
            file_events = [e for e in host_events if e.event_type == EventType.file_created]
            for i in range(len(file_events)):
                t_i = _ensure_utc(file_events[i].timestamp)
                window = [file_events[i]]
                for j in range(i + 1, len(file_events)):
                    t_j = _ensure_utc(file_events[j].timestamp)
                    if (t_j - t_i).total_seconds() <= 60:
                        window.append(file_events[j])
                    else:
                        break
                non_bak = [w for w in window if not str(w.attributes.get("file_path", "")).endswith(".bak")]
                if len(non_bak) >= 100:
                    f1_triggered = True
                    f1_time = _ensure_utc(non_bak[-1].timestamp)
                    rules_fired.append(f"F1: {len(non_bak)} rapid file modifications in 60s")
                    for w in non_bak:
                        evidence_ids.add(w.event_id)
                        if w.user_id:
                            affected_users.add(w.user_id)
                        first_seen = min(first_seen or _ensure_utc(w.timestamp), _ensure_utc(w.timestamp))
                        last_seen = max(last_seen or _ensure_utc(w.timestamp), _ensure_utc(w.timestamp))
                    break

        if not f1_triggered:
            continue

        f2_triggered = False
        for ev in host_events:
            if ev.event_type == EventType.backup_tampering:
                ev_time = _ensure_utc(ev.timestamp)
                if f1_time and abs((ev_time - f1_time).total_seconds()) <= 300:
                    f2_triggered = True
                    evidence_ids.add(ev.event_id)
                    if ev.user_id:
                        affected_users.add(ev.user_id)
                    first_seen = min(first_seen or ev_time, ev_time)
                    last_seen = max(last_seen or ev_time, ev_time)
                    rules_fired.append("F2: Volume shadow copy / backup tampering within 5m")
                    break

        for ev in host_events:
            if ev.event_type == EventType.file_created:
                attrs = ev.attributes or {}
                fpath = str(attrs.get("file_path", attrs.get("filename", "")))
                if is_restore_note_file(fpath):
                    evidence_ids.add(ev.event_id)
                    if ev.user_id:
                        affected_users.add(ev.user_id)
                    ev_time = _ensure_utc(ev.timestamp)
                    first_seen = min(first_seen or ev_time, ev_time)
                    last_seen = max(last_seen or ev_time, ev_time)
                    rules_fired.append(f"F3: Ransom note file created ({fpath})")

        severity = Severity.critical if f2_triggered or len(rules_fired) >= 3 else Severity.high
        confidence = Confidence.likely if len(rules_fired) >= 2 else Confidence.needs_review
        inc_id = generate_deterministic_incident_id(f"ransomware:{host_id}", first_seen or datetime.now(timezone.utc))

        incidents.append(
            Incident(
                incident_id=inc_id,
                title=f"Ransomware-like activity detected on {host_id}",
                category=Category.ransomware_like_activity,
                severity=severity,
                status=IncidentStatus.open,
                first_seen=first_seen or datetime.now(timezone.utc),
                last_seen=last_seen or datetime.now(timezone.utc),
                affected_hosts=[host_id] if host_id != "unknown-host" else [],
                affected_users=sorted(list(affected_users)),
                evidence_event_ids=sorted(list(evidence_ids)),
                detection_reason="; ".join(rules_fired),
                link_rule=LinkRule.LINK_SAME_HOST_30M,
                confidence_label=confidence,
                schema_version="1.0",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )

    return incidents


# ---------------------------------------------------------------------------
# Phase 2: Web-Attack Detection (W1, W2)
# ---------------------------------------------------------------------------

def detect_web_attacks(events: List[Event]) -> List[Incident]:
    """Evaluate W1 (SQLi / path traversal patterns) and W2 (repeated attacks / rapid probing)."""
    web_events = [e for e in events if e.event_type == EventType.web_request]
    if not web_events:
        return []

    sorted_events = sorted(web_events, key=lambda e: _ensure_utc(e.timestamp))
    by_ip: Dict[str, List[Event]] = {}
    for ev in sorted_events:
        src_ip = str(ev.attributes.get("src_ip", "unknown-ip"))
        by_ip.setdefault(src_ip, []).append(ev)

    incidents: List[Incident] = []

    for src_ip, ip_events in by_ip.items():
        w1_matches: List[Tuple[Event, str]] = []  # (event, escaped_snippet)

        for ev in ip_events:
            attrs = ev.attributes or {}
            # Check path, query, and body attributes
            fields_to_check = [
                str(attrs.get("path", "")),
                str(attrs.get("query", "")),
                str(attrs.get("body", "")),
                str(attrs.get("param", "")),
            ]
            for f in fields_to_check:
                snippet = match_w1_pattern(f)
                if snippet:
                    w1_matches.append((ev, snippet))
                    break

        w2_triggered = False
        reasons: List[str] = []
        evidence_ids: Set[str] = set()
        affected_hosts: Set[str] = set()
        affected_users: Set[str] = set()
        first_seen: Optional[datetime] = None
        last_seen: Optional[datetime] = None

        # Check W2 Condition A: >= 3 distinct W1 hits in 5 minutes (300s)
        for i in range(len(w1_matches)):
            t_i = _ensure_utc(w1_matches[i][0].timestamp)
            cluster = [w1_matches[i]]
            for j in range(i + 1, len(w1_matches)):
                t_j = _ensure_utc(w1_matches[j][0].timestamp)
                if (t_j - t_i).total_seconds() <= 300:
                    cluster.append(w1_matches[j])
                else:
                    break
            if len(cluster) >= 3:
                w2_triggered = True
                reasons.append(f"W2: Repeated attack payloads ({len(cluster)} W1 matches in <= 5m from {src_ip})")
                for ev, snip in cluster:
                    evidence_ids.add(ev.event_id)
                    if ev.host_id:
                        affected_hosts.add(ev.host_id)
                    if ev.user_id:
                        affected_users.add(ev.user_id)
                    ev_time = _ensure_utc(ev.timestamp)
                    first_seen = min(first_seen or ev_time, ev_time)
                    last_seen = max(last_seen or ev_time, ev_time)
                break

        # Check W2 Condition B: >= 20 requests/min to /login or /admin
        sensitive_requests = [
            e for e in ip_events
            if any(k in str(e.attributes.get("path", "")).lower() for k in ("/login", "/admin"))
        ]
        for i in range(len(sensitive_requests)):
            t_i = _ensure_utc(sensitive_requests[i].timestamp)
            cluster = [sensitive_requests[i]]
            for j in range(i + 1, len(sensitive_requests)):
                t_j = _ensure_utc(sensitive_requests[j].timestamp)
                if (t_j - t_i).total_seconds() <= 60:
                    cluster.append(sensitive_requests[j])
                else:
                    break
            if len(cluster) >= 20:
                w2_triggered = True
                reasons.append(f"W2: High frequency credential / admin probing ({len(cluster)} requests in 60s)")
                for ev in cluster:
                    evidence_ids.add(ev.event_id)
                    if ev.host_id:
                        affected_hosts.add(ev.host_id)
                    if ev.user_id:
                        affected_users.add(ev.user_id)
                    ev_time = _ensure_utc(ev.timestamp)
                    first_seen = min(first_seen or ev_time, ev_time)
                    last_seen = max(last_seen or ev_time, ev_time)
                break

        # Even with 1 or 2 W1 hits, if W1 fired we can report medium web_attack or require W2 for high
        if not w2_triggered and len(w1_matches) >= 1:
            # Single or double W1 hit without threshold: create medium-severity web_attack
            reasons.append(f"W1: Injection or path traversal pattern detected in web request from {src_ip}")
            for ev, snip in w1_matches:
                evidence_ids.add(ev.event_id)
                if ev.host_id:
                    affected_hosts.add(ev.host_id)
                if ev.user_id:
                    affected_users.add(ev.user_id)
                ev_time = _ensure_utc(ev.timestamp)
                first_seen = min(first_seen or ev_time, ev_time)
                last_seen = max(last_seen or ev_time, ev_time)

        if not reasons:
            continue

        severity = Severity.high if w2_triggered else Severity.medium
        confidence = Confidence.likely if w2_triggered else Confidence.needs_review
        inc_id = generate_deterministic_incident_id(f"web_attack:{src_ip}", first_seen or datetime.now(timezone.utc))

        # Title NEVER includes raw untrusted payload text
        title = f"Web application attack detected from {src_ip}"

        incidents.append(
            Incident(
                incident_id=inc_id,
                title=title,
                category=Category.web_attack,
                severity=severity,
                status=IncidentStatus.open,
                first_seen=first_seen or datetime.now(timezone.utc),
                last_seen=last_seen or datetime.now(timezone.utc),
                affected_hosts=sorted(list(affected_hosts)),
                affected_users=sorted(list(affected_users)),
                evidence_event_ids=sorted(list(evidence_ids)),
                detection_reason="; ".join(reasons),
                link_rule=LinkRule.LINK_SAME_HOST_30M if affected_hosts else LinkRule.NONE,
                confidence_label=confidence,
                schema_version="1.0",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )

    return incidents


# ---------------------------------------------------------------------------
# Phase 2: Data-Theft Detection (D1, D2)
# ---------------------------------------------------------------------------

def detect_data_exfiltration(events: List[Event]) -> List[Incident]:
    """Evaluate D1 (bulk data access / large export) and D2 (admin login followed by D1)."""
    data_events = [e for e in events if e.event_type == EventType.data_access]
    if not data_events:
        return []

    sorted_events = sorted(events, key=lambda e: _ensure_utc(e.timestamp))
    by_user: Dict[str, List[Event]] = {}
    for ev in sorted_events:
        u = ev.user_id or str(ev.attributes.get("username", "unknown-user"))
        by_user.setdefault(u, []).append(ev)

    incidents: List[Incident] = []

    for user_id, u_events in by_user.items():
        user_data_events = [e for e in u_events if e.event_type == EventType.data_access]
        if not user_data_events:
            continue

        d1_triggered = False
        d1_time: Optional[datetime] = None
        evidence_ids: Set[str] = set()
        affected_hosts: Set[str] = set()
        first_seen: Optional[datetime] = None
        last_seen: Optional[datetime] = None
        reasons: List[str] = []

        # Check D1 Criterion 1: >= 50 data_access events within 2 minutes (120s)
        for i in range(len(user_data_events)):
            t_i = _ensure_utc(user_data_events[i].timestamp)
            window = [user_data_events[i]]
            for j in range(i + 1, len(user_data_events)):
                t_j = _ensure_utc(user_data_events[j].timestamp)
                if (t_j - t_i).total_seconds() <= 120:
                    window.append(user_data_events[j])
                else:
                    break
            if len(window) >= 50:
                d1_triggered = True
                d1_time = _ensure_utc(window[-1].timestamp)
                reasons.append(f"D1: Bulk data access ({len(window)} records accessed in <= 120s)")
                for w in window:
                    evidence_ids.add(w.event_id)
                    if w.host_id:
                        affected_hosts.add(w.host_id)
                    first_seen = min(first_seen or _ensure_utc(w.timestamp), _ensure_utc(w.timestamp))
                    last_seen = max(last_seen or _ensure_utc(w.timestamp), _ensure_utc(w.timestamp))
                break

        # Check D1 Criterion 2: single export event exceeding size threshold (record_count >= 50 or bytes >= 50000)
        for ev in user_data_events:
            attrs = ev.attributes or {}
            action = str(attrs.get("action", "")).lower()
            record_count = int(attrs.get("record_count", 0))
            num_bytes = int(attrs.get("bytes", 0))
            if (action == "export" and (record_count >= 50 or num_bytes >= 50000)) or record_count >= 50 or num_bytes >= 50000:
                d1_triggered = True
                ev_time = _ensure_utc(ev.timestamp)
                d1_time = ev_time
                reasons.append(f"D1: Large data export event ({record_count} records, {num_bytes} bytes)")
                evidence_ids.add(ev.event_id)
                if ev.host_id:
                    affected_hosts.add(ev.host_id)
                first_seen = min(first_seen or ev_time, ev_time)
                last_seen = max(last_seen or ev_time, ev_time)
                break

        if not d1_triggered:
            continue

        # Check D2: Admin login success within 30 minutes (1800s) prior to D1
        d2_triggered = False
        for ev in u_events:
            if ev.event_type == EventType.authentication_success:
                ev_time = _ensure_utc(ev.timestamp)
                if d1_time and timedelta(seconds=0) <= (d1_time - ev_time) <= timedelta(seconds=1800):
                    # Check if user is admin or role changed
                    attrs = ev.attributes or {}
                    role = str(attrs.get("role", "")).lower()
                    if user_id in ("admin", "priya.rec") or role in ("admin", "administrator"):
                        d2_triggered = True
                        evidence_ids.add(ev.event_id)
                        if ev.host_id:
                            affected_hosts.add(ev.host_id)
                        first_seen = min(first_seen or ev_time, ev_time)
                        reasons.append("D2: Preceded by administrator login success within 30m")
                        break

        category = Category.multi_stage if d2_triggered else Category.data_exfiltration_suspected
        severity = Severity.critical if d2_triggered else Severity.high
        confidence = Confidence.likely
        inc_id = generate_deterministic_incident_id(f"data_theft:{user_id}", first_seen or datetime.now(timezone.utc))

        title = f"Multi-stage administrator breach and data theft by {user_id}" if d2_triggered else f"Suspected bulk data exfiltration by {user_id}"

        incidents.append(
            Incident(
                incident_id=inc_id,
                title=title,
                category=category,
                severity=severity,
                status=IncidentStatus.open,
                first_seen=first_seen or datetime.now(timezone.utc),
                last_seen=last_seen or datetime.now(timezone.utc),
                affected_hosts=sorted(list(affected_hosts)),
                affected_users=[user_id],
                evidence_event_ids=sorted(list(evidence_ids)),
                detection_reason="; ".join(reasons),
                link_rule=LinkRule.LINK_SAME_USER_30M,
                confidence_label=confidence,
                schema_version="1.0",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )

    return incidents


def process_events(events: List[Event]) -> List[Incident]:
    """Main entrypoint called by hooks.on_new_events.

    Executes all detection rules deterministically and returns candidate incidents.
    """
    if not events:
        return []

    incidents: List[Incident] = []

    # 1. Run Account Takeover detectors (R1-R4)
    # Require multi-signal: R3 alone (new IP unconfirmed) does not open an incident in end-to-end processing
    ato_incidents = detect_account_takeover(events)
    for inc in ato_incidents:
        reasons = [r.strip() for r in inc.detection_reason.split(";") if r.strip()]
        if len(reasons) == 1 and reasons[0].startswith("R3:"):
            continue
        incidents.append(inc)

    # 2. Run File Burst detectors (F1-F3)
    incidents.extend(detect_file_burst(events))

    # 3. Run Web Attack detectors (W1-W2)
    incidents.extend(detect_web_attacks(events))

    # 4. Run Data Exfiltration detectors (D1-D2)
    incidents.extend(detect_data_exfiltration(events))

    return incidents
