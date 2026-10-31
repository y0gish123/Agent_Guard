"""Tests for Phase 3: Site Adapter, Mapper, Stub Site, Mock Tool Portal Mode, and Attack Simulators."""

import os
from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from collector.mapper import map_log_line_to_event
from shared.contracts import EventType, Severity, Source
from testbed.stub_site.main import app as stub_site_app
from mock_tool.app import create_mock_app
from testbed.attack.takeover import verify_target as verify_takeover_target


# ---------------------------------------------------------------------------
# Mapper Tests
# ---------------------------------------------------------------------------

def test_mapper_auth_log():
    line = '{"ts":"2026-10-31T15:00:00Z","event":"login_failed","attempted_username":"priya.rec","username":null,"src_ip":"203.0.113.50","host_id":"clinic-web-01"}'
    ev = map_log_line_to_event("auth", line, "auth.log", 1)
    assert ev is not None
    assert ev.event_type == EventType.authentication_failure
    assert ev.user_id == "priya.rec"
    assert ev.source == Source.collector
    assert ev.attributes["src_ip"] == "203.0.113.50"
    assert ev.raw_event_ref == "auth.log#1"


def test_mapper_access_log():
    line = '{"ts":"2026-10-31T15:01:00Z","method":"GET","path":"/records","query":"id=1%20OR%201=1","status":200,"bytes":1024,"src_ip":"203.0.113.195","username":"priya.rec","host_id":"clinic-web-01"}'
    ev = map_log_line_to_event("access", line, "access.log", 5)
    assert ev is not None
    assert ev.event_type == EventType.web_request
    assert ev.user_id == "priya.rec"
    assert "1%20OR%201=1" in ev.attributes["query"]


def test_mapper_data_log():
    line = '{"ts":"2026-10-31T15:02:00Z","username":"front.desk","action":"export","record_count":150,"bytes":85000,"src_ip":"192.168.1.51","host_id":"clinic-web-01"}'
    ev = map_log_line_to_event("data", line, "data.log", 10)
    assert ev is not None
    assert ev.event_type == EventType.data_access
    assert ev.severity == Severity.high
    assert ev.attributes["record_count"] == 150


# ---------------------------------------------------------------------------
# Stub Site Integration Tests
# ---------------------------------------------------------------------------

def test_stub_site_auth_and_admin_lifecycle():
    client = TestClient(stub_site_app)

    # 1. Reset
    r_reset = client.post("/admin/reset", headers={"X-Admin-Key": "demo-admin-key-supersecret"})
    assert r_reset.status_code == 200

    # 2. Failed login
    r_fail = client.post("/login", json={"username": "priya.rec", "password": "WrongPassword"})
    assert r_fail.status_code == 401

    # 3. Successful login
    r_ok = client.post("/login", json={"username": "priya.rec", "password": "ClinicPass2026!"})
    assert r_ok.status_code == 200
    token = r_ok.json()["token"]

    # 4. View record
    r_rec = client.get("/records/P-1001", headers={"Authorization": f"Bearer {token}"})
    assert r_rec.status_code == 200

    # 5. Admin Lock via API
    r_lock = client.post("/admin/lock", json={"username": "priya.rec"}, headers={"X-Admin-Key": "demo-admin-key-supersecret"})
    assert r_lock.status_code == 200
    assert r_lock.json()["status"] == "locked"

    # 6. Login now returns 423 Locked
    r_locked_login = client.post("/login", json={"username": "priya.rec", "password": "ClinicPass2026!"})
    assert r_locked_login.status_code == 423

    # 7. Admin Isolate Host
    r_iso = client.post("/admin/isolate", json={"host_id": "clinic-web-01"}, headers={"X-Admin-Key": "demo-admin-key-supersecret"})
    assert r_iso.status_code == 200

    # 8. Login on isolated host returns 503
    r_iso_login = client.post("/login", json={"username": "front.desk", "password": "FrontDesk2026!"})
    assert r_iso_login.status_code == 503

    # Reset
    client.post("/admin/reset", headers={"X-Admin-Key": "demo-admin-key-supersecret"})


# ---------------------------------------------------------------------------
# Attack Simulator Safety Check Test
# ---------------------------------------------------------------------------

def test_simulator_refuses_external_hosts():
    # Localhost allowed
    verify_takeover_target("http://localhost:8002")
    verify_takeover_target("http://127.0.0.1:8002")

    # External targets forbidden
    with pytest.raises(SystemExit):
        verify_takeover_target("http://example.com:8002")
    with pytest.raises(SystemExit):
        verify_takeover_target("http://192.168.1.1:8002")
