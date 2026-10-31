"""Tests for Milestone M-B: policy rules, preview, approve, and identity headers."""

import httpx
import pytest
from fastapi.testclient import TestClient


def seed_incident_1(client: TestClient):
    """Seed Incident 1: inc-3f9a1c20."""
    candidate = [
        {
            "incident_id": "inc-3f9a1c20",
            "title": "Suspicious sign-in and admin change for priya.rec",
            "category": "multi_stage",
            "severity": "high",
            "status": "open",
            "first_seen": "2026-10-29T10:00:00Z",
            "last_seen": "2026-10-29T10:15:00Z",
            "affected_hosts": ["clinic-pc-01"],
            "affected_users": ["priya.rec"],
            "evidence_event_ids": ["evt-101", "evt-110", "evt-111", "evt-112"],
            "detection_reason": "Repeated failed logins followed by privilege escalation",
            "link_rule": "LINK_SAME_USER_30M",
            "confidence_label": "likely",
            "schema_version": "1.0",
            "created_at": "2026-10-29T10:15:00Z",
            "updated_at": "2026-10-29T10:15:00Z",
        }
    ]
    resp = client.post("/api/ingest/incident-candidates", json=candidate)
    assert resp.status_code == 200


def test_2_preview_does_not_change_mock_state(client: TestClient):
    """Test 2: preview does not change mock state (call /tool/state before and after)."""
    seed_incident_1(client)

    # State before
    with httpx.Client() as http_client:
        state_before = http_client.get("http://127.0.0.1:8001/tool/state").json()

    preview_payload = {
        "action_type": "lock_account",
        "target_id": "priya.rec",
        "requested_by": "analyst-1",
        "proposed_by": "human",
    }
    resp = client.post(
        "/api/incidents/inc-3f9a1c20/response-preview",
        json=preview_payload,
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["policy_decision"] == "REVIEW"
    assert data["reason_code"] == "APPROVAL_REQUIRED"
    assert data["approval_state"] == "pending"
    assert data["execution_status"] == "not_started"

    # State after
    with httpx.Client() as http_client:
        state_after = http_client.get("http://127.0.0.1:8001/tool/state").json()

    assert state_after == state_before


def test_4_lock_account_ceo_blocked(client: TestClient):
    """Test 4: lock_account 'ceo' -> BLOCK TARGET_OUT_OF_SCOPE; state unchanged; audit record exists."""
    seed_incident_1(client)

    with httpx.Client() as http_client:
        state_before = http_client.get("http://127.0.0.1:8001/tool/state").json()

    preview_payload = {
        "action_type": "lock_account",
        "target_id": "ceo",
        "requested_by": "analyst-1",
        "proposed_by": "human",
    }
    resp = client.post(
        "/api/incidents/inc-3f9a1c20/response-preview",
        json=preview_payload,
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["policy_decision"] == "BLOCK"
    assert data["reason_code"] == "TARGET_OUT_OF_SCOPE"
    assert data["approval_state"] == "not_required"
    assert data["execution_status"] == "blocked"

    # State unchanged
    with httpx.Client() as http_client:
        state_after = http_client.get("http://127.0.0.1:8001/tool/state").json()
    assert state_after == state_before

    # Verify audit record exists
    audit_resp = client.get("/api/audit")
    assert audit_resp.status_code == 200
    audit_records = audit_resp.json()
    decision_records = [
        r for r in audit_records
        if r["event_type"] == "policy_decision"
        and r["payload"].get("target_id") == "ceo"
        and r["payload"].get("reason_code") == "TARGET_OUT_OF_SCOPE"
    ]
    assert len(decision_records) >= 1


def test_5_isolate_host_out_of_scope(client: TestClient):
    """Test 5: isolate_host 'db-server-01' on incident 1 -> BLOCK TARGET_OUT_OF_SCOPE."""
    seed_incident_1(client)

    preview_payload = {
        "action_type": "isolate_host",
        "target_id": "db-server-01",
        "requested_by": "analyst-1",
        "proposed_by": "human",
    }
    resp = client.post(
        "/api/incidents/inc-3f9a1c20/response-preview",
        json=preview_payload,
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["policy_decision"] == "BLOCK"
    assert data["reason_code"] == "TARGET_OUT_OF_SCOPE"
    assert data["execution_status"] == "blocked"


def test_6_isolate_host_on_account_takeover_category(client: TestClient):
    """Test 6: isolate_host on a pure account_takeover incident -> BLOCK ACTION_NOT_ALLOWED_FOR_CATEGORY."""
    candidate = [
        {
            "incident_id": "inc-4a8b1c90",
            "title": "Credential Stuffing on priya.rec",
            "category": "account_takeover",
            "severity": "medium",
            "status": "open",
            "first_seen": "2026-10-29T11:00:00Z",
            "last_seen": "2026-10-29T11:10:00Z",
            "affected_hosts": ["clinic-pc-01"],
            "affected_users": ["priya.rec"],
            "evidence_event_ids": ["evt-101"],
            "detection_reason": "Multiple credential attempts",
            "link_rule": "LINK_SAME_USER_30M",
            "confidence_label": "likely",
            "schema_version": "1.0",
            "created_at": "2026-10-29T11:10:00Z",
            "updated_at": "2026-10-29T11:10:00Z",
        }
    ]
    client.post("/api/ingest/incident-candidates", json=candidate)

    preview_payload = {
        "action_type": "isolate_host",
        "target_id": "clinic-pc-01",
        "requested_by": "analyst-1",
        "proposed_by": "human",
    }
    resp = client.post(
        "/api/incidents/inc-4a8b1c90/response-preview",
        json=preview_payload,
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["policy_decision"] == "BLOCK"
    assert data["reason_code"] == "ACTION_NOT_ALLOWED_FOR_CATEGORY"
    assert data["execution_status"] == "blocked"


def test_8_staff_role_rejected_for_approve_and_execute(client: TestClient):
    """Test 8: staff role calls approve or execute -> 403 ROLE_NOT_PERMITTED."""
    seed_incident_1(client)

    preview_payload = {
        "action_type": "lock_account",
        "target_id": "priya.rec",
        "requested_by": "analyst-1",
        "proposed_by": "human",
    }
    prev_resp = client.post(
        "/api/incidents/inc-3f9a1c20/response-preview",
        json=preview_payload,
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert prev_resp.status_code == 200
    resp_id = prev_resp.json()["response_id"]

    # Staff attempts approve -> 403
    appr_resp = client.post(
        f"/api/responses/{resp_id}/approve",
        json={"decision": "approve", "reason": "Staff unauthorized approval"},
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert appr_resp.status_code == 403
    err_body = appr_resp.json()
    assert err_body["code"] == "ROLE_NOT_PERMITTED"

    # Staff attempts execute -> 403
    exec_resp = client.post(
        f"/api/responses/{resp_id}/execute",
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert exec_resp.status_code == 403
    err_body2 = exec_resp.json()
    assert err_body2["code"] == "ROLE_NOT_PERMITTED"

    # Verify audit contains error records
    audit_resp = client.get("/api/audit")
    assert audit_resp.status_code == 200
    records = audit_resp.json()
    role_errors = [
        r for r in records
        if r["event_type"] == "error"
        and r["payload"].get("reason_code") == "ROLE_NOT_PERMITTED"
    ]
    assert len(role_errors) >= 2

