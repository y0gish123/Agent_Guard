"""Demo endpoints for naive pipeline execution, state reset, demo seeding, and tool state proxy."""

from typing import Any, Dict, List, Literal, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
import httpx
from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.orm import Session

from backend.api.common import make_error_response
from backend.audit.service import AuditService
from backend.config import get_settings
from backend.db.models import (
    ApprovalModel,
    AuditEventModel,
    EventModel,
    EvidenceRefModel,
    IncidentModel,
    ResponseModel,
)
from backend.db.session import get_db
from backend.incidents.demo_data import get_scenario_data
from backend.incidents.service import IncidentService
from shared.contracts import ActionType, Event, Incident, ProposedBy, ReasonCode

router = APIRouter(prefix="/api/demo", tags=["demo"])


class NaiveExecuteRequest(BaseModel):
    incident_id: str
    action_type: ActionType
    target_id: str
    proposed_by: ProposedBy = ProposedBy.human


@router.post("/naive-execute")
def naive_execute(
    req: NaiveExecuteRequest,
    x_user: str = Header(default="anonymous", alias="X-User"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    settings = get_settings()
    if settings.DEMO_MODE != "naive":
        raise make_error_response(
            status_code=404,
            code="NOT_FOUND",
            message="Naive execution endpoint is disabled in guarded mode",
        )

    # Directly execute against mock tool with NO policy checks
    tool_url = f"{settings.TOOL_URL.rstrip('/')}/tool/demo-apply"
    payload = {
        "action_type": req.action_type.value,
        "target_id": req.target_id,
        "incident_id": req.incident_id,
    }

    tool_result: Dict[str, Any] = {}
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.post(tool_url, json=payload)
            tool_result = resp.json()
    except Exception as exc:
        tool_result = {"ok": False, "error": str(exc)}

    # Record audit event of type demo_naive_execute
    audit_service = AuditService(db)
    audit_entry = audit_service.record_event(
        actor=x_user,
        event_type="demo_naive_execute",
        incident_id=req.incident_id,
        payload={
            "incident_id": req.incident_id,
            "action_type": req.action_type.value,
            "target_id": req.target_id,
            "proposed_by": req.proposed_by.value,
            "decision": "unprotected_execution",
            "reason_code": "NAIVE_EXECUTE",
            "outcome": "Executed directly via demo endpoint with no policy boundary",
        },
    )

    return {
        "status": "executed_unprotected",
        "audit_event_id": audit_entry.sequence_no,
        "tool_result": tool_result,
    }


@router.post("/reset")
def reset_backend_and_tool(db: Session = Depends(get_db)) -> Dict[str, Any]:
    # Clear all backend database tables
    db.execute(delete(ApprovalModel))
    db.execute(delete(ResponseModel))
    db.execute(delete(EvidenceRefModel))
    db.execute(delete(IncidentModel))
    db.execute(delete(EventModel))
    db.execute(delete(AuditEventModel))
    db.commit()

    # Call mock tool reset
    settings = get_settings()
    tool_url = f"{settings.TOOL_URL.rstrip('/')}/tool/reset"
    tool_reset_result = {}
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.post(tool_url)
            tool_reset_result = resp.json()
    except Exception as exc:
        tool_reset_result = {"ok": False, "error": "Mock tool unavailable or not running"}

    return {
        "backend_reset": True,
        "mock_tool_reset": tool_reset_result,
    }


@router.post("/seed")
def seed_demo_scenario(
    scenario: Literal["account", "filebursts", "poisoned", "all"] = Query(default="all"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Load built-in demonstration data through the standard upsert paths."""
    events_raw: List[Dict] = []
    incidents_raw: List[Dict] = []

    # Check if teammate's detection/fixtures module is present
    try:
        import detection.fixtures  # type: ignore
        if hasattr(detection.fixtures, "get_scenario_data"):
            events_raw, incidents_raw = detection.fixtures.get_scenario_data(scenario)
    except Exception:
        pass

    if not events_raw and not incidents_raw:
        events_raw, incidents_raw = get_scenario_data(scenario)

    events = [Event(**e) for e in events_raw]
    incidents = [Incident(**i) for i in incidents_raw]

    service = IncidentService(db)
    inserted, skipped = service.ingest_events(events)
    created, updated = service.upsert_candidates(incidents)

    return {
        "scenario": scenario,
        "events_inserted": inserted,
        "events_skipped": skipped,
        "incidents_created": created,
        "incidents_updated": updated,
    }


@router.get("/tool-state")
def get_mock_tool_state() -> Dict[str, Any]:
    """Read-only proxy to mock tool GET /tool/state so frontend never communicates with tool directly."""
    settings = get_settings()
    tool_url = f"{settings.TOOL_URL.rstrip('/')}/tool/state"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(tool_url)
            return resp.json()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "TOOL_UNAVAILABLE",
                "plain_message": f"Could not reach mock tool at {settings.TOOL_URL}",
                "detail_id": "err-tool-state",
            },
        )
