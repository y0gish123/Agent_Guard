"""Tests for Milestone M-E: complete end-to-end response lifecycle verification."""

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.incidents.demo_data import get_scenario_data


def test_15_end_to_end_verified_response_flow(client: TestClient):
    """Test 15: end-to-end: reset, seed, preview, approve, execute, audit verify ok."""
    # 1. Reset backend & mock tool
    reset_resp = client.post("/api/demo/reset")
    assert reset_resp.status_code == 200

    # 2. Seed events & incidents (account scenario: 10 events, 1 incident)
    events_raw, incidents_raw = get_scenario_data("account")

    ev_resp = client.post("/api/ingest/events", json=events_raw)
    assert ev_resp.status_code == 200
    assert ev_resp.json()["inserted"] == len(events_raw)

    inc_resp = client.post("/api/ingest/incident-candidates", json=incidents_raw)
    assert inc_resp.status_code == 200
    assert inc_resp.json()["created"] == len(incidents_raw)

    # Verify funnel
    funnel_resp = client.get("/api/funnel")
    assert funnel_resp.status_code == 200
    funnel = funnel_resp.json()
    assert funnel["raw_events"] == len(events_raw)
    assert funnel["incidents"] == len(incidents_raw)

    # 3. Preview action: lock_account priya.rec on inc-3f9a1c20
    preview_req = {
        "action_type": "lock_account",
        "target_id": "priya.rec",
        "requested_by": "analyst-lead",
        "proposed_by": "human",
    }
    prev_resp = client.post(
        "/api/incidents/inc-3f9a1c20/response-preview",
        json=preview_req,
        headers={"X-User": "analyst-lead", "X-Role": "staff"},
    )
    assert prev_resp.status_code == 200
    prev_data = prev_resp.json()
    assert prev_data["policy_decision"] == "REVIEW"
    assert prev_data["reason_code"] == "APPROVAL_REQUIRED"
    assert prev_data["approval_state"] == "pending"
    assert prev_data["execution_status"] == "not_started"
    resp_id = prev_data["response_id"]

    # 4. Approve action by authorized approver
    appr_resp = client.post(
        f"/api/responses/{resp_id}/approve",
        json={"decision": "approve", "reason": "Authorization approved by SOC Manager."},
        headers={"X-User": "soc-manager", "X-Role": "approver"},
    )
    assert appr_resp.status_code == 200
    appr_data = appr_resp.json()
    assert appr_data["approval_state"] == "approved"

    # 5. Execute action with verified token gateway
    exec_resp = client.post(
        f"/api/responses/{resp_id}/execute",
        headers={"X-User": "soc-manager", "X-Role": "approver"},
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["execution_status"] == "succeeded"
    assert exec_data["reason_code"] == "EXECUTED_OK"
    assert "token" not in str(exec_data)

    # 6. Verify mock tool state reflects the action
    with httpx.Client() as hc:
        mstate = hc.get("http://127.0.0.1:8001/tool/state").json()
    assert mstate["accounts"]["priya.rec"]["locked"] is True

    # 7. Verify full cryptographic audit chain integrity
    verify_resp = client.get("/api/audit/verify")
    assert verify_resp.status_code == 200
    chain_status = verify_resp.json()
    assert chain_status["ok"] is True
    assert chain_status["checked"] >= 4
    assert chain_status["first_bad_sequence_no"] is None
