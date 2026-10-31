"""Pytest test case for Phase 8 End-to-End Scenarios."""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from eval.e2e_demo import run_e2e_scenarios


def test_all_e2e_scenarios():
    """Run all 7 end-to-end hackathon scenarios in-process."""
    with TestClient(app) as client:
        results = run_e2e_scenarios(client)
        assert len(results) == 7
        assert all(results.values())

