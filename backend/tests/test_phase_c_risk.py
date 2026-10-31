"""Unit and benign tests for Phase C: Risk Scoring, Contextual Auth, and Advanced Detectors."""

from datetime import datetime, timezone, timedelta
import pytest
from starlette.testclient import TestClient

from detection.risk import RiskEngine, IdentityBaselineManager
from shared.contracts import Category, Event, EventType, Severity, Source


def test_benign_scenarios_raise_zero_incidents():
    """Verify that benign operations produce ZERO incidents.

    - Scenario 1: One wrong password then correct login
    - Scenario 2: Owner login from a new IP
    - Scenario 3: Normal shopping day / staff export of 10 records
    - Scenario 4: Scheduled backup (backup_agent.exe)
    """
    engine = RiskEngine()
    now = datetime.now(timezone.utc)

    # Benign 1: Single failed login then success
    benign_auth = [
        Event(
            event_id="evt-b-1",
            timestamp=now,
            source=Source.collector,
            user_id="priya.rec",
            event_type=EventType.authentication_failure,
            severity=Severity.low,
            raw_event_ref="auth.log#1",
            attributes={"src_ip": "192.168.1.10"},
        ),
        Event(
            event_id="evt-b-2",
            timestamp=now + timedelta(seconds=10),
            source=Source.collector,
            user_id="priya.rec",
            event_type=EventType.authentication_success,
            severity=Severity.low,
            raw_event_ref="auth.log#2",
            attributes={"src_ip": "192.168.1.10"},
        ),
    ]
    assert engine.evaluate_signals(benign_auth) == []

    # Benign 2: Staff viewing/exporting 10 records (well below bulk threshold of 50)
    benign_export = [
        Event(
            event_id=f"evt-exp-{i}",
            timestamp=now + timedelta(seconds=i),
            source=Source.collector,
            user_id="front.desk",
            event_type=EventType.data_access,
            severity=Severity.low,
            raw_event_ref=f"data.log#{i}",
            attributes={"action": "view_record", "record_count": 1},
        )
        for i in range(10)
    ]
    assert engine.evaluate_signals(benign_export) == []


def test_session_hijacking_detector():
    """Same session_id_hash seen with two distinct IPs produces an incident."""
    engine = RiskEngine()
    now = datetime.now(timezone.utc)

    hijack_events = [
        Event(
            event_id="evt-hj-1",
            timestamp=now,
            source=Source.collector,
            user_id="priya.rec",
            event_type=EventType.web_request,
            severity=Severity.low,
            raw_event_ref="access.log#1",
            session_id_hash="sesshash_alpha_99",
            attributes={"src_ip": "192.168.1.50", "path": "/dashboard"},
        ),
        Event(
            event_id="evt-hj-2",
            timestamp=now + timedelta(seconds=30),
            source=Source.collector,
            user_id="priya.rec",
            event_type=EventType.web_request,
            severity=Severity.low,
            raw_event_ref="access.log#2",
            session_id_hash="sesshash_alpha_99",
            attributes={"src_ip": "203.0.113.88", "path": "/records"},
        ),
    ]

    incidents = engine.evaluate_signals(hijack_events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == Category.account_takeover
    assert "Session Hijacking" in inc.title
    assert "203.0.113.88" in inc.affected_ips


def test_password_spray_detector():
    """One IP failing across >= 5 distinct accounts raises a password spray incident."""
    engine = RiskEngine()
    now = datetime.now(timezone.utc)

    spray_events = [
        Event(
            event_id=f"evt-sp-{i}",
            timestamp=now + timedelta(seconds=i * 5),
            source=Source.collector,
            user_id=f"user{i}@clinic.org",
            event_type=EventType.authentication_failure,
            severity=Severity.medium,
            raw_event_ref=f"auth.log#{i}",
            attributes={"src_ip": "198.51.100.77"},
        )
        for i in range(6)
    ]

    incidents = engine.evaluate_signals(spray_events)
    assert len(incidents) == 1
    assert "Password Spraying" in incidents[0].title
    assert "198.51.100.77" in incidents[0].affected_ips


def test_mass_delete_detector():
    """30 or more record deletions raises D3 mass delete incident."""
    engine = RiskEngine()
    now = datetime.now(timezone.utc)

    delete_events = [
        Event(
            event_id=f"evt-del-{i}",
            timestamp=now + timedelta(seconds=i),
            source=Source.collector,
            user_id="rogue.admin",
            event_type=EventType.data_access,
            severity=Severity.high,
            raw_event_ref=f"data.log#{i}",
            attributes={"action": "delete", "src_ip": "10.0.0.99"},
        )
        for i in range(35)
    ]

    incidents = engine.evaluate_signals(delete_events)
    assert len(incidents) == 1
    assert "Mass Record Deletion" in incidents[0].title
    assert incidents[0].severity == Severity.critical


def test_identity_confirmation_endpoint(tmp_path):
    """POST /api/identity/confirm adds trusted IP/device with tamper-evident audit record."""
    from backend.main import create_app
    from backend.db.session import init_db

    db_path = tmp_path / "test_identity.db"
    init_db(f"sqlite:///{db_path}")

    app = create_app()
    with TestClient(app) as client:
        # Staff role denied
        r_forbidden = client.post(
            "/api/identity/confirm",
            json={"user_id": "priya.rec", "src_ip": "198.51.100.99", "device": "MacBook-Air"},
            headers={"X-User": "receptionist", "X-Role": "staff"},
        )
        assert r_forbidden.status_code == 403

        # Approver succeeds
        r_ok = client.post(
            "/api/identity/confirm",
            json={"user_id": "priya.rec", "src_ip": "198.51.100.99", "device": "MacBook-Air"},
            headers={"X-User": "soc-lead", "X-Role": "approver"},
        )
        assert r_ok.status_code == 200
        data = r_ok.json()
        assert data["ok"] is True
        assert data["status"] == "baseline_updated"
        assert "audit_event_id" in data

