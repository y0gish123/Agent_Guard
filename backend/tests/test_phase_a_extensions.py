"""Unit tests for Phase A: Contract and Site-Contract Additive Extensions."""

from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from shared.contracts import (
    ActionType,
    Category,
    Event,
    EventType,
    Incident,
    IncidentStatus,
    LinkRule,
    Confidence,
    PolicyDecision,
    ReasonCode,
    Role,
    Severity,
    Source,
)
from backend.policy.evaluator import PolicyEvaluator
from testbed.stub_site.main import app as stub_site_app


def test_additive_enums_and_fields():
    """Verify new EventType, ActionType, and optional fields in Event and Incident."""
    ev = Event(
        event_id="evt-net-001",
        timestamp=datetime.now(timezone.utc),
        source=Source.collector,
        host_id="clinic-pc-01",
        user_id="priya.rec",
        event_type=EventType.network_connection,
        severity=Severity.medium,
        raw_event_ref="net.log#1",
        trace_id="tr-12345",
        request_id="req-67890",
        span_id="sp-abcde",
        user_agent="Mozilla/5.0 TestAgent",
        session_id_hash="hash1234",
        source_event_id="src-evt-99",
    )
    assert ev.event_type == EventType.network_connection
    assert ev.trace_id == "tr-12345"

    inc = Incident(
        incident_id="inc-aabbccdd",
        title="Network and Web Attack",
        category=Category.web_attack,
        severity=Severity.high,
        status=IncidentStatus.open,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        affected_hosts=["clinic-pc-01"],
        affected_users=["priya.rec"],
        affected_ips=["198.51.100.22"],
        evidence_event_ids=["evt-net-001"],
        detection_reason="Probing from suspicious external IP",
        link_rule=LinkRule.NONE,
        confidence_label=Confidence.likely,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    assert inc.affected_ips == ["198.51.100.22"]


def test_block_ip_policy_evaluation():
    """Verify block_ip scope enforcement against incident.affected_ips."""
    inc = Incident(
        incident_id="inc-aabbccdd",
        title="Web attack",
        category=Category.web_attack,
        severity=Severity.high,
        status=IncidentStatus.open,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        affected_hosts=["clinic-pc-01"],
        affected_users=["priya.rec"],
        affected_ips=["198.51.100.22"],
        evidence_event_ids=["evt-net-001"],
        detection_reason="Probing",
        link_rule=LinkRule.NONE,
        confidence_label=Confidence.likely,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    # In-scope IP -> REVIEW with APPROVAL_REQUIRED
    dec, code, reason = PolicyEvaluator.evaluate_preview(
        inc, ActionType.block_ip, "198.51.100.22", Role.approver
    )
    assert dec == PolicyDecision.REVIEW
    assert code == ReasonCode.APPROVAL_REQUIRED

    # Out-of-scope IP -> BLOCK with TARGET_OUT_OF_SCOPE
    dec_out, code_out, _ = PolicyEvaluator.evaluate_preview(
        inc, ActionType.block_ip, "203.0.113.99", Role.approver
    )
    assert dec_out == PolicyDecision.BLOCK
    assert code_out == ReasonCode.TARGET_OUT_OF_SCOPE

    # Data exfiltration category does not allow block_ip
    inc_exfil = inc.model_copy(update={"category": Category.data_exfiltration_suspected})
    dec_block, code_block, _ = PolicyEvaluator.evaluate_preview(
        inc_exfil, ActionType.block_ip, "198.51.100.22", Role.approver
    )
    assert dec_block == PolicyDecision.BLOCK
    assert code_block == ReasonCode.ACTION_NOT_ALLOWED_FOR_CATEGORY


def test_stub_site_block_ip_and_inventory():
    """Verify stub site implements block-ip, unblock-ip, and inventory."""
    client = TestClient(stub_site_app)

    # Reset site
    r_reset = client.post("/admin/reset")
    assert r_reset.status_code == 200

    # Test inventory
    r_inv = client.get("/admin/inventory", headers={"X-Admin-Key": "demo-admin-key-supersecret"})
    assert r_inv.status_code == 200
    inv_data = r_inv.json()
    assert "components" in inv_data
    assert len(inv_data["components"]) > 0

    # Test MFA flag in state
    r_state = client.get("/admin/state")
    assert r_state.status_code == 200
    assert r_state.json()["accounts"]["admin"]["mfa_enabled"] is True

    # Block IP 198.51.100.44
    r_block = client.post(
        "/admin/block-ip",
        json={"ip": "198.51.100.44", "ttl_seconds": 3600},
        headers={"X-Admin-Key": "demo-admin-key-supersecret"},
    )
    assert r_block.status_code == 200

    # Access site from blocked IP -> HTTP 403
    r_access = client.get("/", headers={"X-Demo-Source-IP": "198.51.100.44"})
    assert r_access.status_code == 403

    # Unblock IP
    r_unblock = client.post(
        "/admin/unblock-ip",
        json={"ip": "198.51.100.44"},
        headers={"X-Admin-Key": "demo-admin-key-supersecret"},
    )
    assert r_unblock.status_code == 200

    # Access now succeeds
    r_access_ok = client.get("/", headers={"X-Demo-Source-IP": "198.51.100.44"})
    assert r_access_ok.status_code == 200

