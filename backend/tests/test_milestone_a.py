"""Tests for Milestone M-A: contracts, ingest, incident queries, funnel, meta, phishing."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient


def test_1_ingest_and_candidate_and_schema(client: TestClient):
    """Test 1: Ingest events and a candidate; GET incident returns stable schema; re-ingest creates no duplicates."""
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

    # Ingest events
    resp = client.post("/api/ingest/events", json=events_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["inserted"] == 2
    assert data["skipped"] == 0

    # Re-ingest events (idempotent, skips existing)
    resp2 = client.post("/api/ingest/events", json=events_payload)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["inserted"] == 0
    assert data2["skipped"] == 2

    # Ingest candidate incident
    candidate_payload = [
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
    resp_cand = client.post("/api/ingest/incident-candidates", json=candidate_payload)
    assert resp_cand.status_code == 200
    assert resp_cand.json() == {"created": 1, "updated": 0}

    # Upsert same candidate with new severity (e.g., lower shouldn't downgrade, higher would upgrade)
    candidate_payload[0]["severity"] = "low"  # shouldn't downgrade high
    candidate_payload[0]["affected_hosts"] = ["clinic-pc-01", "clinic-pc-02"]
    resp_cand2 = client.post("/api/ingest/incident-candidates", json=candidate_payload)
    assert resp_cand2.status_code == 200
    assert resp_cand2.json() == {"created": 0, "updated": 1}

    # GET incident
    resp_inc = client.get("/api/incidents/inc-3f9a1c20")
    assert resp_inc.status_code == 200
    inc_data = resp_inc.json()
    incident = inc_data["incident"]
    events = inc_data["events"]

    assert incident["incident_id"] == "inc-3f9a1c20"
    assert incident["severity"] == "high"  # preserved, not downgraded
    assert set(incident["affected_hosts"]) == {"clinic-pc-01", "clinic-pc-02"}
    assert len(events) == 2
    # Check stable schema
    for key in [
        "incident_id", "title", "category", "severity", "status",
        "first_seen", "last_seen", "affected_hosts", "affected_users",
        "evidence_event_ids", "detection_reason", "link_rule",
        "confidence_label", "schema_version", "created_at", "updated_at"
    ]:
        assert key in incident

    # Events in time order
    assert events[0]["event_id"] == "evt-101"
    assert events[1]["event_id"] == "evt-110"


def test_14_phishing_check_stores_event(client: TestClient):
    """Test 14: Phishing check stores a phishing_check event and returns verdict, score, reasons and event_id."""
    payload = {
        "user_id": "priya.rec",
        "text": "Your account has been suspended! Please click here to confirm password.",
        "sender": "alert@malicious-sender.com",
        "reply_to": "attacker@evil.org",
    }
    resp = client.post("/api/phishing/check", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["verdict"] in ("red", "amber", "green")
    assert isinstance(data["score"], int)
    assert isinstance(data["reasons"], list)
    assert data["event_id"].startswith("evt-100")

    # Verify event stored in database
    funnel_resp = client.get("/api/funnel")
    assert funnel_resp.status_code == 200
    assert funnel_resp.json()["raw_events"] >= 1


def test_funnel_and_meta_and_reset(client: TestClient):
    """Verify /api/funnel, /api/meta, and /api/demo/reset."""
    meta_resp = client.get("/api/meta")
    assert meta_resp.status_code == 200
    meta = meta_resp.json()
    assert meta["simulation"] is True
    assert meta["schema_version"] == "1.0"
    assert meta["demo_mode"] in ("guarded", "naive")

    # Reset
    reset_resp = client.post("/api/demo/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["backend_reset"] is True

    # Funnel should now be zeroed
    funnel_resp = client.get("/api/funnel")
    assert funnel_resp.status_code == 200
    counts = funnel_resp.json()
    assert counts["raw_events"] == 0
    assert counts["alerts"] == 0
    assert counts["incidents"] == 0

