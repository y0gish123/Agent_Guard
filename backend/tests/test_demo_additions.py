"""Test frontend-facing backend additions: health, demo seed, and tool-state proxy."""

import httpx
import pytest
from fastapi.testclient import TestClient


def test_health_check_endpoint(client: TestClient):
    """Verify GET /api/health -> {'status': 'ok'}."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_demo_tool_state_proxy(client: TestClient):
    """Verify GET /api/demo/tool-state proxies mock tool state."""
    resp = client.get("/api/demo/tool-state")
    assert resp.status_code == 200
    data = resp.json()
    assert "accounts" in data
    assert "hosts" in data
    assert "priya.rec" in data["accounts"]
    assert "clinic-pc-01" in data["hosts"]


def test_demo_seed_endpoint_scenarios(client: TestClient):
    """Verify POST /api/demo/seed?scenario=account|filebursts|poisoned|all."""
    # Reset first
    client.post("/api/demo/reset")

    # Seed account scenario
    r_acc = client.post("/api/demo/seed?scenario=account")
    assert r_acc.status_code == 200
    data_acc = r_acc.json()
    assert data_acc["scenario"] == "account"
    assert data_acc["events_inserted"] == 10
    assert data_acc["incidents_created"] == 1

    # Seed poisoned scenario
    r_poi = client.post("/api/demo/seed?scenario=poisoned")
    assert r_poi.status_code == 200
    assert r_poi.json()["incidents_created"] == 1

    # Check funnel reflects seeded data
    funnel = client.get("/api/funnel").json()
    assert funnel["incidents"] == 2
    assert funnel["raw_events"] >= 11

