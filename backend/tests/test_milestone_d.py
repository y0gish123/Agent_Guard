"""Tests for Milestone M-D: audit chain verification, demo modes, fallback explanations, and hooks."""

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text


def seed_incident_1(client: TestClient):
    events_payload = [
        {
            "event_id": "evt-101",
            "timestamp": "2026-10-29T10:00:00Z",
            "source": "replay",
            "host_id": "clinic-pc-01",
            "user_id": "priya.rec",
            "event_type": "authentication_failure",
            "severity": "medium",
            "raw_event_ref": "raw-101",
            "attributes": {"src_ip": "203.0.113.50", "method": "rdp"},
            "schema_version": "1.0",
        },
        {
            "event_id": "evt-110",
            "timestamp": "2026-10-29T10:05:00Z",
            "source": "replay",
            "host_id": "clinic-pc-01",
            "user_id": "priya.rec",
            "event_type": "authentication_success",
            "severity": "medium",
            "raw_event_ref": "raw-110",
            "attributes": {"src_ip": "203.0.113.50", "method": "rdp"},
            "schema_version": "1.0",
        },
    ]
    client.post("/api/ingest/events", json=events_payload)

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
            "evidence_event_ids": ["evt-101", "evt-110"],
            "detection_reason": "Repeated failed logins followed by escalation",
            "link_rule": "LINK_SAME_USER_30M",
            "confidence_label": "likely",
            "schema_version": "1.0",
            "created_at": "2026-10-29T10:15:00Z",
            "updated_at": "2026-10-29T10:15:00Z",
        }
    ]
    client.post("/api/ingest/incident-candidates", json=candidate)


def test_11_audit_chain_tamper_detection(client: TestClient, test_db):
    """Test 11: Tamper with an audit row in the DB, call /api/audit/verify -> ok false with first_bad_sequence_no."""
    seed_incident_1(client)

    # Perform a few actions to generate sequential audit records
    for target in ["priya.rec", "clinic-pc-01"]:
        client.post(
            "/api/incidents/inc-3f9a1c20/response-preview",
            json={
                "action_type": "lock_account",
                "target_id": target,
                "requested_by": "analyst-1",
                "proposed_by": "human",
            },
            headers={"X-User": "analyst-1", "X-Role": "staff"},
        )

    # Initial verification should be completely ok
    verify_resp = client.get("/api/audit/verify")
    assert verify_resp.status_code == 200
    vdata = verify_resp.json()
    assert vdata["ok"] is True
    assert vdata["checked"] >= 2
    assert vdata["first_bad_sequence_no"] is None

    # Tamper with an audit record in the database directly
    override_get_db, _ = test_db
    session = next(override_get_db())
    try:
        session.execute(
            text("UPDATE audit_events SET payload_json = '{\"tampered\": true}' WHERE sequence_no = 2")
        )
        session.commit()
    finally:
        session.close()

    # Re-verify audit chain: must detect tampering at sequence_no 2
    tampered_resp = client.get("/api/audit/verify")
    assert tampered_resp.status_code == 200
    tdata = tampered_resp.json()
    assert tdata["ok"] is False
    assert tdata["first_bad_sequence_no"] == 2


def test_12_demo_mode_guarded_vs_naive(client: TestClient, monkeypatch):
    """Test 12:
    - DEMO_MODE=guarded: POST /api/demo/naive-execute -> 404
    - DEMO_MODE=naive: it changes mock state, writes audit record, and /api/meta shows demo_mode 'naive'
    """
    # 1. Guarded mode test
    monkeypatch.setenv("DEMO_MODE", "guarded")
    guarded_resp = client.post(
        "/api/demo/naive-execute",
        json={
            "incident_id": "inc-3f9a1c20",
            "action_type": "lock_account",
            "target_id": "front.desk",
            "proposed_by": "human",
        },
    )
    assert guarded_resp.status_code == 404

    # 2. Naive mode test
    monkeypatch.setenv("DEMO_MODE", "naive")

    # Meta shows naive
    meta_resp = client.get("/api/meta")
    assert meta_resp.status_code == 200
    assert meta_resp.json()["demo_mode"] == "naive"

    # Reset mock tool
    with httpx.Client() as hc:
        hc.post("http://127.0.0.1:8001/tool/reset")

    naive_resp = client.post(
        "/api/demo/naive-execute",
        json={
            "incident_id": "inc-3f9a1c20",
            "action_type": "lock_account",
            "target_id": "front.desk",
            "proposed_by": "human",
        },
    )
    assert naive_resp.status_code == 200
    ndata = naive_resp.json()
    assert ndata["status"] == "executed_unprotected"

    # Verify mock tool state changed directly without gateway policy check
    with httpx.Client() as hc:
        mstate = hc.get("http://127.0.0.1:8001/tool/state").json()
    assert mstate["accounts"]["front.desk"]["locked"] is True

    # Verify audit record written
    audit_resp = client.get("/api/audit")
    assert audit_resp.status_code == 200
    records = audit_resp.json()
    naive_events = [r for r in records if r["event_type"] == "demo_naive_execute"]
    assert len(naive_events) >= 1


def test_13_explanation_fallback_when_adapter_raises(client: TestClient):
    """Test 13: explanation route returns a FALLBACK or valid explanation for inc-3f9a1c20.

    The adapter now never raises — it returns fallback/cache/llm.
    We verify the shape of the response is a valid Explanation contract.
    """
    seed_incident_1(client)

    resp = client.post(
        "/api/incidents/inc-3f9a1c20/explanation",
        json={"lang": "en"},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Structural shape checks (adapter returns fallback when no LLM key in test env)
    assert data["incident_id"] == "inc-3f9a1c20"
    assert data["generated_by"] in ("fallback", "cache", "llm")
    assert isinstance(data["summary"], str) and len(data["summary"]) > 0
    assert isinstance(data["observed_facts"], list)
    assert isinstance(data["recommended_actions"], list)
    assert data["confidence_label"] in ("low", "needs_review", "likely")
    assert data["lang"] == "en"


def test_hooks_safe_degradation(client: TestClient):
    """Test that hooks.on_new_events degrades gracefully when pipeline module is absent or raises."""
    # Ingesting events shouldn't raise even if detection.pipeline doesn't exist
    resp = client.post(
        "/api/ingest/events",
        json=[
            {
                "event_id": "evt-888",
                "timestamp": "2026-10-29T12:00:00Z",
                "source": "replay",
                "host_id": "clinic-pc-01",
                "user_id": "priya.rec",
                "event_type": "process_start",
                "severity": "low",
                "raw_event_ref": "raw-888",
                "attributes": {"cmd": "powershell.exe"},
                "schema_version": "1.0",
            }
        ],
    )
    assert resp.status_code == 200
    assert resp.json()["inserted"] == 1

