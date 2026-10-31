"""Unit tests for Detection Pipeline (Phase 1): R1-R4, F1-F3, Allowlist, and Correlation."""

from datetime import datetime, timezone, timedelta
import pytest

from shared.contracts import (
    Category,
    Confidence,
    Event,
    EventType,
    LinkRule,
    Severity,
    Source,
)
from detection.pipeline import (
    detect_account_takeover,
    detect_file_burst,
    process_events,
)

BASE_TIME = datetime(2026, 10, 31, 14, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str,
    event_type: EventType,
    offset_seconds: int,
    user_id: str = "priya.rec",
    host_id: str = "clinic-pc-01",
    attributes: dict = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        source=Source.replay,
        host_id=host_id,
        user_id=user_id,
        event_type=event_type,
        severity=Severity.medium,
        raw_event_ref=f"raw-{event_id}",
        attributes=attributes or {},
        schema_version="1.0",
    )


# ---------------------------------------------------------------------------
# Account Takeover Rule Tests (R1, R2, R3, R4)
# ---------------------------------------------------------------------------

def test_r1_brute_force_triggers_incident():
    """R1: >= 5 auth failures for same user and src_ip within 2 minutes."""
    events = [
        make_event(f"evt-f{i}", EventType.authentication_failure, i * 20, attributes={"src_ip": "203.0.113.99"})
        for i in range(5)
    ]
    incidents = detect_account_takeover(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == Category.account_takeover
    assert inc.affected_users == ["priya.rec"]
    assert "R1" in inc.detection_reason
    assert len(inc.evidence_event_ids) == 5


def test_r2_success_after_brute_force_elevates_severity():
    """R2: Auth success for same src_ip within 5 minutes after R1 -> high severity, likely confidence."""
    events = [
        make_event(f"evt-f{i}", EventType.authentication_failure, i * 20, attributes={"src_ip": "203.0.113.99"})
        for i in range(5)
    ]
    # Success at +120s (within 5m)
    events.append(
        make_event("evt-s1", EventType.authentication_success, 120, attributes={"src_ip": "203.0.113.99"})
    )
    incidents = detect_account_takeover(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert "R2" in inc.detection_reason
    assert inc.severity in (Severity.high, Severity.critical)
    assert inc.confidence_label == Confidence.likely


def test_r3_unrecognised_ip_triggers_detection():
    """R3: Success from IP not in user's known_ips."""
    events = [
        make_event("evt-s1", EventType.authentication_success, 0, attributes={"src_ip": "198.51.100.77"})
    ]
    incidents = detect_account_takeover(events)
    assert len(incidents) == 1
    assert "R3" in incidents[0].detection_reason


def test_r4_privilege_escalation_triggers_critical():
    """R4: privilege_change within 30 minutes after anomalous login -> critical severity."""
    events = [
        make_event("evt-s1", EventType.authentication_success, 0, attributes={"src_ip": "198.51.100.77"}),
        make_event("evt-p1", EventType.privilege_change, 600, attributes={"group_added": "Administrators"}),
    ]
    incidents = detect_account_takeover(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert "R4" in inc.detection_reason
    assert inc.severity == Severity.critical


def test_correlation_phishing_upgrades_to_multi_stage():
    """Correlation: phishing_check event in 30m window upgrades category to multi_stage."""
    events = [
        make_event("evt-phish", EventType.phishing_check, -600, attributes={"verdict": "red"}),
        make_event("evt-s1", EventType.authentication_success, 0, attributes={"src_ip": "198.51.100.77"}),
        make_event("evt-p1", EventType.privilege_change, 300, attributes={"group_added": "Administrators"}),
    ]
    incidents = detect_account_takeover(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == Category.multi_stage
    assert inc.link_rule == LinkRule.LINK_SAME_USER_30M
    assert "evt-phish" in inc.evidence_event_ids


# ---------------------------------------------------------------------------
# File Burst Rule Tests (F1, F2, F3, Allowlist)
# ---------------------------------------------------------------------------

def test_f1_file_burst_triggers_ransomware_incident():
    """F1: file_change_burst with >=100 files changed and new_extension != .bak."""
    events = [
        make_event(
            "evt-burst-1",
            EventType.file_change_burst,
            0,
            attributes={"files_changed": 150, "new_extension": ".locked", "window_sec": 30},
        )
    ]
    incidents = detect_file_burst(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == Category.ransomware_like_activity
    assert "F1" in inc.detection_reason


def test_f2_backup_tampering_elevates_to_critical():
    """F2: backup_tampering within 5m of F1 elevates severity to critical."""
    events = [
        make_event(
            "evt-burst-1",
            EventType.file_change_burst,
            0,
            attributes={"files_changed": 120, "new_extension": ".enc"},
        ),
        make_event(
            "evt-vss-1",
            EventType.backup_tampering,
            60,
            attributes={"action": "vssadmin delete shadows /all /quiet"},
        ),
    ]
    incidents = detect_file_burst(events)
    assert len(incidents) == 1
    assert incidents[0].severity == Severity.critical
    assert "F2" in incidents[0].detection_reason


def test_f3_ransom_note_included_in_evidence():
    """F3: README_RESTORE or HOW_TO_DECRYPT note included in evidence."""
    events = [
        make_event(
            "evt-burst-1",
            EventType.file_change_burst,
            0,
            attributes={"files_changed": 110, "new_extension": ".crypt"},
        ),
        make_event(
            "evt-note-1",
            EventType.file_created,
            30,
            attributes={"file_path": "C:\\Data\\README_RESTORE_FILES.txt"},
        ),
    ]
    incidents = detect_file_burst(events)
    assert len(incidents) == 1
    assert "evt-note-1" in incidents[0].evidence_event_ids
    assert "F3" in incidents[0].detection_reason


def test_allowlist_scheduled_backup_raises_nothing():
    """Benign test: Scheduled backup using backup_agent.exe with scheduled=true must produce NO incidents."""
    events = [
        make_event(
            "evt-backup-1",
            EventType.file_change_burst,
            0,
            attributes={"image": "backup_agent.exe", "scheduled": True, "files_changed": 500, "new_extension": ".bak"},
        ),
        make_event(
            "evt-backup-2",
            EventType.process_start,
            10,
            attributes={"image": "C:\\Tools\\backup_agent.exe", "scheduled": "true"},
        ),
    ]
    incidents = process_events(events)
    assert len(incidents) == 0


def test_benign_normal_activity_raises_nothing():
    """Benign test: Standard user logins from known IPs raise no incidents."""
    events = [
        make_event(
            "evt-norm-1",
            EventType.authentication_success,
            0,
            user_id="priya.rec",
            attributes={"src_ip": "192.168.1.50"},
        ),
        make_event(
            "evt-norm-2",
            EventType.file_created,
            10,
            user_id="priya.rec",
            attributes={"file_path": "C:\\Users\\priya\\report.docx"},
        ),
    ]
    incidents = process_events(events)
    assert len(incidents) == 0

