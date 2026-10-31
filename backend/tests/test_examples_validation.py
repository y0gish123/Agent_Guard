"""Validate that all shared/examples JSON files comply with contracts and models."""

import json
import os
from typing import List
import pytest
from pydantic import TypeAdapter

from shared.contracts import (
    ApproveRequest,
    ErrorBody,
    Event,
    Explanation,
    FunnelCounts,
    Incident,
    Meta,
    PhishingCheckRequest,
    PhishingCheckResponse,
    PreviewRequest,
    ResponseRecord,
)

EXAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "shared", "examples"))


def test_validate_all_shared_examples():
    """Verify that every JSON example parses cleanly according to its schema."""
    files = [f for f in os.listdir(EXAMPLES_DIR) if f.endswith(".json")]
    assert len(files) >= 15, f"Expected comprehensive example coverage, found {len(files)}"

    for filename in sorted(files):
        filepath = os.path.join(EXAMPLES_DIR, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if filename == "events_ingest_request.json":
            TypeAdapter(List[Event]).validate_python(data)
        elif filename == "incident_candidate_request.json":
            TypeAdapter(List[Incident]).validate_python(data)
        elif filename == "preview_request.json":
            PreviewRequest.model_validate(data)
        elif filename in ("preview_response.json", "response_record.json", "approve_response.json"):
            ResponseRecord.model_validate(data)
        elif filename == "approve_request.json":
            ApproveRequest.model_validate(data)
        elif filename == "execute_response.json":
            assert "execution_status" in data and "reason_code" in data and "tool_result" in data
        elif filename == "execute_blocked_response.json":
            assert data["execution_status"] == "blocked" and "reason_code" in data
        elif filename == "phishing_check_request.json":
            PhishingCheckRequest.model_validate(data)
        elif filename == "phishing_check_response.json":
            PhishingCheckResponse.model_validate(data)
        elif filename == "explanation_request.json":
            assert "lang" in data
        elif filename == "explanation_response.json":
            Explanation.model_validate(data)
        elif filename == "funnel_response.json":
            FunnelCounts.model_validate(data)
        elif filename == "meta_response.json":
            Meta.model_validate(data)
        elif filename == "error_body.json":
            ErrorBody.model_validate(data)
        elif filename == "incident_list_response.json":
            assert "items" in data and "total" in data
            TypeAdapter(List[Incident]).validate_python(data["items"])
        elif filename == "incident_detail_response.json":
            Incident.model_validate(data["incident"])
            TypeAdapter(List[Event]).validate_python(data["events"])
        elif filename == "audit_list_response.json":
            assert isinstance(data, list)
            assert len(data) > 0 and "sequence_no" in data[0]
        elif filename == "audit_verify_response.json":
            assert "ok" in data and "checked" in data
        elif filename == "tool_state_response.json":
            assert "accounts" in data and "hosts" in data
        elif filename == "health_response.json":
            assert data == {"status": "ok"}
        elif filename == "seed_response.json":
            assert "scenario" in data and "events_inserted" in data
        elif filename == "naive_execute_request.json":
            assert "incident_id" in data and "action_type" in data
        else:
            # Any generic example must at least be valid json
            assert isinstance(data, (dict, list))

