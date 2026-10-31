"""Tests for Milestone M-C: token issuer, mock tool, execute flow, and token rejection cases."""

import time
import httpx
import pytest
from fastapi.testclient import TestClient

from backend.authorization.token_issuer import TokenIssuer
from backend.config import get_settings
from mock_tool.app import app as mock_app, state_manager
from mock_tool.verifier import TokenVerifier


def seed_incident_1(client: TestClient):
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


def test_3_full_preview_approve_execute_lifecycle(client: TestClient):
    """Test 3: lock_account priya.rec on incident 1: preview REVIEW -> approve -> execute -> EXECUTED_OK."""
    # Reset mock tool state
    with httpx.Client() as http_client:
        http_client.post("http://127.0.0.1:8001/tool/reset")

    seed_incident_1(client)

    # 1. Preview
    prev_resp = client.post(
        "/api/incidents/inc-3f9a1c20/response-preview",
        json={
            "action_type": "lock_account",
            "target_id": "priya.rec",
            "requested_by": "analyst-1",
            "proposed_by": "human",
        },
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert prev_resp.status_code == 200
    prev_data = prev_resp.json()
    assert prev_data["policy_decision"] == "REVIEW"
    resp_id = prev_data["response_id"]

    # 2. Approve
    appr_resp = client.post(
        f"/api/responses/{resp_id}/approve",
        json={"decision": "approve", "reason": "Confirmed unauthorized admin escalation."},
        headers={"X-User": "soc-approver", "X-Role": "approver"},
    )
    assert appr_resp.status_code == 200
    assert appr_resp.json()["approval_state"] == "approved"

    # 3. Execute
    exec_resp = client.post(
        f"/api/responses/{resp_id}/execute",
        headers={"X-User": "soc-approver", "X-Role": "approver"},
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["execution_status"] == "succeeded"
    assert exec_data["reason_code"] == "EXECUTED_OK"
    assert "token" not in str(exec_data)

    # 4. Check mock tool state: priya.rec locked
    with httpx.Client() as http_client:
        state = http_client.get("http://127.0.0.1:8001/tool/state").json()
    assert state["accounts"]["priya.rec"]["locked"] is True

    # 5. Check audit trail
    audit_resp = client.get("/api/audit")
    assert audit_resp.status_code == 200
    records = audit_resp.json()
    event_types = [r["event_type"] for r in records if r.get("response_id") == resp_id]

    assert "proposal" in event_types
    assert "policy_decision" in event_types
    assert "approval" in event_types
    assert "token_issued" in event_types
    assert "tool_result" in event_types

    # Replay execution attempt on already succeeded response should yield 409 TOKEN_REPLAYED
    replay_resp = client.post(
        f"/api/responses/{resp_id}/execute",
        headers={"X-User": "soc-approver", "X-Role": "approver"},
    )
    assert replay_resp.status_code == 409
    assert replay_resp.json()["code"] == "TOKEN_REPLAYED"


def test_7_execute_without_approval_rejected(client: TestClient):
    """Test 7: execute without approval -> 409 APPROVAL_NOT_RECORDED; no token issued."""
    seed_incident_1(client)

    prev_resp = client.post(
        "/api/incidents/inc-3f9a1c20/response-preview",
        json={
            "action_type": "lock_account",
            "target_id": "priya.rec",
            "requested_by": "analyst-1",
            "proposed_by": "human",
        },
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert prev_resp.status_code == 200
    resp_id = prev_resp.json()["response_id"]

    # Attempt execute immediately without approve
    exec_resp = client.post(
        f"/api/responses/{resp_id}/execute",
        headers={"X-User": "soc-approver", "X-Role": "approver"},
    )
    assert exec_resp.status_code == 409
    assert exec_resp.json()["code"] == "APPROVAL_NOT_RECORDED"

    # Verify no token was issued in audit log
    audit_resp = client.get("/api/audit")
    assert audit_resp.status_code == 200
    records = audit_resp.json()
    token_events = [
        r for r in records
        if r.get("response_id") == resp_id and r["event_type"] == "token_issued"
    ]
    assert len(token_events) == 0


def test_9_mock_tool_token_verifications(mock_client: TestClient):
    """Test 9: Tool verification rejection matrix:
    - missing token -> TOKEN_MISSING
    - forged/altered token -> TOKEN_BAD_SIGNATURE
    - expired token -> TOKEN_EXPIRED
    - replay -> TOKEN_REPLAYED
    - token scope mismatch -> TOKEN_SCOPE_MISMATCH (incident, action, target)
    """
    settings = get_settings()
    issuer = TokenIssuer(secret=settings.HMAC_SECRET, ttl_seconds=60)

    # 1. Missing token
    resp = mock_client.post(
        "/tool/execute",
        json={"token": None, "incident_id": "inc-1", "action_type": "lock_account", "target_id": "priya.rec"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": False, "reason_code": "TOKEN_MISSING"}

    # 2. Forged / Altered token
    valid_token, _ = issuer.issue_token("inc-1", "lock_account", "priya.rec")
    tampered_token = valid_token[:-4] + "abcd"
    resp = mock_client.post(
        "/tool/execute",
        json={"token": tampered_token, "incident_id": "inc-1", "action_type": "lock_account", "target_id": "priya.rec"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": False, "reason_code": "TOKEN_BAD_SIGNATURE"}

    # 3. Expired token (inject clock)
    custom_clock = [1000.0]
    expired_issuer = TokenIssuer(secret=settings.HMAC_SECRET, ttl_seconds=10, clock=lambda: custom_clock[0])
    exp_token, _ = expired_issuer.issue_token("inc-1", "lock_account", "priya.rec")
    # Advance time on verifier
    expired_verifier = TokenVerifier(secret=settings.HMAC_SECRET, clock=lambda: custom_clock[0] + 50.0)
    ok, code, _ = expired_verifier.verify_and_claim(exp_token, "inc-1", "lock_account", "priya.rec")
    assert ok is False
    assert code.value == "TOKEN_EXPIRED"

    # 4. Replay token
    fresh_token, _ = issuer.issue_token("inc-1", "lock_account", "front.desk")
    r1 = mock_client.post(
        "/tool/execute",
        json={"token": fresh_token, "incident_id": "inc-1", "action_type": "lock_account", "target_id": "front.desk"},
    )
    assert r1.status_code == 200
    assert r1.json()["ok"] is True
    # Second execution of same token is a replay
    r2 = mock_client.post(
        "/tool/execute",
        json={"token": fresh_token, "incident_id": "inc-1", "action_type": "lock_account", "target_id": "front.desk"},
    )
    assert r2.status_code == 200
    assert r2.json() == {"ok": False, "reason_code": "TOKEN_REPLAYED"}

    # 5. Token Scope Mismatch (3 cases)
    scope_token, _ = issuer.issue_token("inc-100", "lock_account", "svc-backup")
    # 5a. Mismatched incident_id
    r_inc = mock_client.post(
        "/tool/execute",
        json={"token": scope_token, "incident_id": "inc-OTHER", "action_type": "lock_account", "target_id": "svc-backup"},
    )
    assert r_inc.status_code == 200
    assert r_inc.json() == {"ok": False, "reason_code": "TOKEN_SCOPE_MISMATCH"}

    # 5b. Mismatched action_type
    r_act = mock_client.post(
        "/tool/execute",
        json={"token": scope_token, "incident_id": "inc-100", "action_type": "isolate_host", "target_id": "svc-backup"},
    )
    assert r_act.status_code == 200
    assert r_act.json() == {"ok": False, "reason_code": "TOKEN_SCOPE_MISMATCH"}

    # 5c. Mismatched target_id
    r_tgt = mock_client.post(
        "/tool/execute",
        json={"token": scope_token, "incident_id": "inc-100", "action_type": "lock_account", "target_id": "ceo"},
    )
    assert r_tgt.status_code == 200
    assert r_tgt.json() == {"ok": False, "reason_code": "TOKEN_SCOPE_MISMATCH"}


def test_10_tool_unavailable(client: TestClient, monkeypatch):
    """Test 10: Mock tool stopped or TOOL_URL wrong -> TOOL_UNAVAILABLE, audited, state unchanged."""
    seed_incident_1(client)

    prev_resp = client.post(
        "/api/incidents/inc-3f9a1c20/response-preview",
        json={
            "action_type": "lock_account",
            "target_id": "priya.rec",
            "requested_by": "analyst-1",
            "proposed_by": "human",
        },
        headers={"X-User": "analyst-1", "X-Role": "staff"},
    )
    assert prev_resp.status_code == 200
    resp_id = prev_resp.json()["response_id"]

    # Approve
    appr_resp = client.post(
        f"/api/responses/{resp_id}/approve",
        json={"decision": "approve", "reason": "Authorization approved."},
        headers={"X-User": "soc-approver", "X-Role": "approver"},
    )
    assert appr_resp.status_code == 200

    # Point TOOL_URL to unreachable port
    monkeypatch.setenv("TOOL_URL", "http://127.0.0.1:59999")

    exec_resp = client.post(
        f"/api/responses/{resp_id}/execute",
        headers={"X-User": "soc-approver", "X-Role": "approver"},
    )
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["execution_status"] == "failed"
    assert data["reason_code"] == "TOOL_UNAVAILABLE"
    assert data["plain_reason"] == "The action tool is not reachable, so nothing was changed."

    # Verify audit contains error record with TOOL_UNAVAILABLE
    audit_resp = client.get("/api/audit")
    assert audit_resp.status_code == 200
    records = audit_resp.json()
    err_records = [
        r for r in records
        if r["event_type"] == "error"
        and r["payload"].get("reason_code") == "TOOL_UNAVAILABLE"
    ]
    assert len(err_records) >= 1
