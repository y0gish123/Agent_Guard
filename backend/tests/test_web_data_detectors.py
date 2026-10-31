"""Unit tests for Phase 2: Web-Attack (W1, W2) and Data-Theft (D1, D2) Detectors."""

from datetime import datetime, timezone, timedelta
import pytest

from shared.contracts import (
    ActionType,
    Category,
    Confidence,
    Event,
    EventType,
    Incident,
    IncidentStatus,
    LinkRule,
    Severity,
    Source,
)
from detection.pipeline import (
    detect_web_attacks,
    detect_data_exfiltration,
    process_events,
)
from backend.policy.rules import (
    CATEGORY_ALLOWED_ACTIONS,
    evaluate_p3_category_allowlist,
    evaluate_p4_scope,
    PolicyRuleViolation,
)

BASE_TIME = datetime(2026, 10, 31, 15, 0, 0, tzinfo=timezone.utc)


def make_web_event(
    event_id: str,
    path: str,
    query: str = "",
    offset_seconds: int = 0,
    src_ip: str = "203.0.113.195",
    host_id: str = "web-srv-01",
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        source=Source.collector,
        host_id=host_id,
        user_id=None,
        event_type=EventType.web_request,
        severity=Severity.medium,
        raw_event_ref=f"nginx-access#{event_id}",
        attributes={
            "src_ip": src_ip,
            "path": path,
            "query": query,
            "method": "GET",
            "status": 200,
        },
        schema_version="1.0",
    )


def make_data_event(
    event_id: str,
    user_id: str,
    action: str = "view_record",
    record_count: int = 1,
    num_bytes: int = 250,
    offset_seconds: int = 0,
    host_id: str = "web-srv-01",
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        source=Source.collector,
        host_id=host_id,
        user_id=user_id,
        event_type=EventType.data_access,
        severity=Severity.low,
        raw_event_ref=f"app-audit#{event_id}",
        attributes={
            "action": action,
            "record_count": record_count,
            "bytes": num_bytes,
        },
        schema_version="1.0",
    )


# ---------------------------------------------------------------------------
# Policy Allowlists Tests
# ---------------------------------------------------------------------------

def test_web_attack_category_allowlist():
    """Policy allows isolate_host and revoke_session for web_attack, rejects lock_account."""
    inc = Incident(
        incident_id="inc-11223344",
        title="Web Attack",
        category=Category.web_attack,
        severity=Severity.high,
        status=IncidentStatus.open,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        affected_hosts=["web-srv-01"],
        affected_users=["priya.rec"],
        evidence_event_ids=["evt-1"],
        detection_reason="W1",
        link_rule=LinkRule.NONE,
        confidence_label=Confidence.likely,
        schema_version="1.0",
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )
    # Allowed
    evaluate_p3_category_allowlist(inc, ActionType.isolate_host)
    evaluate_p3_category_allowlist(inc, ActionType.revoke_session)
    # Blocked
    with pytest.raises(PolicyRuleViolation):
        evaluate_p3_category_allowlist(inc, ActionType.lock_account)


def test_data_exfiltration_category_allowlist():
    """Policy allows lock_account and revoke_session for data_exfiltration_suspected, rejects isolate_host."""
    inc = Incident(
        incident_id="inc-55667788",
        title="Data Theft",
        category=Category.data_exfiltration_suspected,
        severity=Severity.high,
        status=IncidentStatus.open,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        affected_hosts=["web-srv-01"],
        affected_users=["priya.rec"],
        evidence_event_ids=["evt-1"],
        detection_reason="D1",
        link_rule=LinkRule.NONE,
        confidence_label=Confidence.likely,
        schema_version="1.0",
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )
    # Allowed
    evaluate_p3_category_allowlist(inc, ActionType.lock_account)
    evaluate_p3_category_allowlist(inc, ActionType.revoke_session)
    # Blocked
    with pytest.raises(PolicyRuleViolation):
        evaluate_p3_category_allowlist(inc, ActionType.isolate_host)


# ---------------------------------------------------------------------------
# Web Attack Detectors Tests (W1, W2)
# ---------------------------------------------------------------------------

def test_w1_sqli_patterns_detected_without_payload_in_title():
    """W1 detects SQLi pattern (' OR 1=1, UNION SELECT, ; DROP, ../) without raw payload in title."""
    sqli_queries = [
        "id=1'%20OR%201=1--",
        "search=test'%20UNION%20SELECT%20username,password%20FROM%20users--",
        "action=test;%20DROP%20TABLE%20patients--",
        "file=../../../../etc/passwd",
    ]
    for i, q in enumerate(sqli_queries):
        ev = make_web_event(f"evt-w1-{i}", path="/api/search", query=q)
        incidents = detect_web_attacks([ev])
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.category == Category.web_attack
        # Strict principle: raw payload must NOT appear in title
        assert "UNION" not in inc.title
        assert "DROP" not in inc.title
        assert "etc/passwd" not in inc.title
        assert "W1" in inc.detection_reason


def test_w2_three_w1_hits_in_5_minutes_elevates_to_high():
    """W2: >= 3 distinct W1 hits in 5 minutes raises high-severity web_attack incident."""
    events = [
        make_web_event("evt-w-1", "/patients", "filter=' OR 1=1", offset_seconds=0),
        make_web_event("evt-w-2", "/records", "id=1 UNION SELECT 1,2", offset_seconds=60),
        make_web_event("evt-w-3", "/files", "path=../../secret.txt", offset_seconds=120),
    ]
    incidents = detect_web_attacks(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.severity == Severity.high
    assert inc.confidence_label == Confidence.likely
    assert "W2" in inc.detection_reason
    assert len(inc.evidence_event_ids) == 3


def test_w2_rapid_probing_of_login_or_admin():
    """W2: >= 20 requests in 60s to /login or /admin raises web_attack."""
    events = [
        make_web_event(f"evt-probe-{i}", path="/admin/login", offset_seconds=i * 2)
        for i in range(22)
    ]
    incidents = detect_web_attacks(events)
    assert len(incidents) == 1
    assert "W2" in incidents[0].detection_reason


# ---------------------------------------------------------------------------
# Data Theft Detectors Tests (D1, D2)
# ---------------------------------------------------------------------------

def test_d1_bulk_data_access_in_2_minutes():
    """D1: >= 50 data_access events within 2 minutes triggers data_exfiltration_suspected (high)."""
    events = [
        make_data_event(f"evt-da-{i}", user_id="front.desk", action="view_record", offset_seconds=i)
        for i in range(55)
    ]
    incidents = detect_data_exfiltration(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == Category.data_exfiltration_suspected
    assert inc.severity == Severity.high
    assert "D1" in inc.detection_reason


def test_d1_large_export_event():
    """D1: Export event with record_count >= 50 or bytes >= 50000 triggers data_exfiltration_suspected."""
    ev = make_data_event("evt-exp-1", user_id="priya.rec", action="export", record_count=500, num_bytes=120000)
    incidents = detect_data_exfiltration([ev])
    assert len(incidents) == 1
    assert incidents[0].category == Category.data_exfiltration_suspected
    assert "D1" in incidents[0].detection_reason


def test_d2_admin_login_followed_by_d1_upgrades_to_critical_multi_stage():
    """D2: Administrator login followed by bulk export within 30 min triggers critical multi_stage incident."""
    admin_login = Event(
        event_id="evt-adm-login",
        timestamp=BASE_TIME,
        source=Source.collector,
        host_id="web-srv-01",
        user_id="admin",
        event_type=EventType.authentication_success,
        severity=Severity.medium,
        raw_event_ref="auth#evt-adm-login",
        attributes={"role": "admin", "src_ip": "203.0.113.195"},
        schema_version="1.0",
    )
    bulk_export = make_data_event(
        "evt-adm-exp",
        user_id="admin",
        action="export",
        record_count=1000,
        num_bytes=500000,
        offset_seconds=600,
    )
    incidents = detect_data_exfiltration([admin_login, bulk_export])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == Category.multi_stage
    assert inc.severity == Severity.critical
    assert "D2" in inc.detection_reason


# ---------------------------------------------------------------------------
# Benign Case
# ---------------------------------------------------------------------------

def test_benign_receptionist_viewing_5_records_raises_nothing():
    """Benign test: A receptionist viewing 5 records raises no incidents."""
    events = [
        make_data_event(f"evt-rec-{i}", user_id="front.desk", action="view_record", offset_seconds=i * 10)
        for i in range(5)
    ]
    incidents = process_events(events)
    assert len(incidents) == 0
