"""Incident query, explanation, and response preview endpoints."""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
import uuid
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.api.common import make_error_response
from backend.audit.service import AuditService
from backend.config import get_settings
from backend.db.models import ResponseModel
from backend.db.session import get_db
from backend.incidents.service import IncidentService
from backend.policy.evaluator import PolicyEvaluator
from backend.policy.messages import get_plain_reason
from shared.contracts import (
    ApprovalState,
    Confidence,
    ErrorBody,
    Event,
    ExecutionStatus,
    Explanation,
    Incident,
    ObservedFact,
    PolicyDecision,
    PreviewRequest,
    ReasonCode,
    ResponseRecord,
    Role,
)

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class LangBody(BaseModel):
    lang: Literal["en", "hi", "kn"] = "en"


@router.get("")
def list_incidents(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    service = IncidentService(db)
    items, total = service.list_incidents(status=status, severity=severity, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/{id}")
def get_incident(
    id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    service = IncidentService(db)
    result = service.get_incident(id)
    if not result:
        raise make_error_response(
            status_code=404,
            code="INCIDENT_NOT_FOUND",
            message="Incident not found",
        )
    incident, events = result
    return {"incident": incident, "events": events}


@router.post("/{id}/explanation")
async def get_incident_explanation(
    id: str,
    body: LangBody,
    db: Session = Depends(get_db),
) -> Explanation:
    service = IncidentService(db)
    result = service.get_incident(id)
    if not result:
        raise make_error_response(
            status_code=404,
            code="INCIDENT_NOT_FOUND",
            message="Incident not found",
        )
    incident, events = result
    settings = get_settings()

    explanation: Optional[Explanation] = None

    # Attempt AI explanation with 10-second timeout
    try:
        from backend.ai import adapter  # type: ignore

        if hasattr(adapter, "explain"):
            explanation = await asyncio.wait_for(
                asyncio.to_thread(adapter.explain, incident, events, body.lang, settings.DEMO_MODE),
                timeout=10.0,
            )
    except Exception:
        explanation = None

    if explanation is not None and isinstance(explanation, Explanation):
        return explanation

    # Build fallback explanation from stored fields only
    summary = f"{incident.title}. {incident.detection_reason}".strip()
    observed_facts: List[ObservedFact] = []
    for ev in events[:6]:
        actor = ev.user_id or ev.host_id or "unknown"
        ts_str = ev.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if ev.timestamp.tzinfo else ev.timestamp.isoformat() + "Z"
        text = f"{ev.event_type.value} at {ts_str} for {actor}"
        observed_facts.append(ObservedFact(text=text, evidence_event_ids=[ev.event_id]))

    potential_impact: List[str] = []
    if incident.affected_hosts:
        potential_impact.append(f"Potential impact to hosts: {', '.join(incident.affected_hosts)}")
    if incident.affected_users:
        potential_impact.append(f"Potential impact to accounts: {', '.join(incident.affected_users)}")
    if not potential_impact:
        potential_impact.append("Potential unauthorized activity detected in environment")

    return Explanation(
        incident_id=incident.incident_id,
        lang=body.lang,
        summary=summary,
        observed_facts=observed_facts,
        interpretation="Needs review: this is an automatic summary of recorded events.",
        potential_impact=potential_impact,
        confidence_label=incident.confidence_label,
        recommended_next_steps=[
            "Verify authorization with account owner",
            "Review event logs for lateral movement",
        ],
        recommended_actions=[],
        generated_by="fallback",
        mode=settings.DEMO_MODE,
    )


@router.post("/{id}/response-preview")
def preview_response(
    id: str,
    req: PreviewRequest,
    x_user: str = Header(default="anonymous", alias="X-User"),
    x_role: str = Header(default="staff", alias="X-Role"),
    db: Session = Depends(get_db),
) -> ResponseRecord:
    service = IncidentService(db)
    result = service.get_incident(id)
    if not result:
        raise make_error_response(
            status_code=404,
            code="INCIDENT_NOT_FOUND",
            message="Incident not found",
        )
    incident, _ = result

    role_str = (x_role or "staff").strip().lower()
    try:
        role = Role(role_str)
    except ValueError:
        role = Role.staff

    decision, code, plain_reason = PolicyEvaluator.evaluate_preview(
        incident=incident,
        action_type=req.action_type,
        target_id=req.target_id,
        role=role,
    )

    if decision == PolicyDecision.BLOCK:
        approval_state = ApprovalState.not_required
        execution_status = ExecutionStatus.blocked
    elif decision == PolicyDecision.REVIEW:
        approval_state = ApprovalState.pending
        execution_status = ExecutionStatus.not_started
    else:
        approval_state = ApprovalState.not_required
        execution_status = ExecutionStatus.not_started

    resp_id = f"resp-{uuid.uuid4().hex[:8]}"
    now_utc = datetime.now(timezone.utc)

    audit_service = AuditService(db)
    # 1. Audit proposal
    audit_service.record_event(
        actor=x_user,
        event_type="proposal",
        incident_id=id,
        response_id=resp_id,
        payload={
            "incident_id": id,
            "response_id": resp_id,
            "action_type": req.action_type.value,
            "target_id": req.target_id,
            "proposed_by": req.proposed_by.value,
            "requested_by": req.requested_by,
        },
    )

    # 2. Audit policy_decision
    policy_audit = audit_service.record_event(
        actor="policy_gateway",
        event_type="policy_decision",
        incident_id=id,
        response_id=resp_id,
        payload={
            "incident_id": id,
            "response_id": resp_id,
            "action_type": req.action_type.value,
            "target_id": req.target_id,
            "decision": decision.value,
            "reason_code": code.value,
            "outcome": plain_reason,
        },
    )

    # Save ResponseModel to database
    resp_model = ResponseModel(
        response_id=resp_id,
        incident_id=id,
        action_type=req.action_type.value,
        target_id=req.target_id,
        requested_by=req.requested_by,
        proposed_by=req.proposed_by.value,
        policy_decision=decision.value,
        reason_code=code.value,
        plain_reason=plain_reason,
        approval_state=approval_state.value,
        execution_status=execution_status.value,
        audit_event_id=policy_audit.sequence_no,
        created_at=now_utc,
    )
    db.add(resp_model)
    db.commit()

    return ResponseRecord(
        response_id=resp_id,
        incident_id=id,
        action_type=req.action_type,
        target_id=req.target_id,
        requested_by=req.requested_by,
        proposed_by=req.proposed_by,
        policy_decision=decision,
        reason_code=code,
        plain_reason=plain_reason,
        approval_state=approval_state,
        execution_status=execution_status,
        audit_event_id=policy_audit.sequence_no,
        created_at=now_utc,
    )


class ConfirmIdentityRequest(BaseModel):
    user_id: str
    src_ip: str
    device: Optional[str] = None


@router.post("/identity/confirm")
def confirm_identity(
    req: ConfirmIdentityRequest,
    x_user: str = Header(default="analyst-lead"),
    x_role: str = Header(default="approver"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Approver confirms 'Was this you?' to add an IP/device to user's learned baseline."""
    if x_role not in ("approver", "admin"):
        raise make_error_response(
            status_code=403,
            code="ROLE_NOT_PERMITTED",
            message="Only approver or admin role can confirm user identity baselines.",
        )

    from detection.risk import identity_baseline_mgr
    identity_baseline_mgr.confirm_identity(req.user_id, req.src_ip, req.device)

    # Record tamper-evident audit record
    audit_service = AuditService(db)
    audit_entry = audit_service.record_event(
        actor=x_user,
        event_type="identity_confirmed",
        payload={
            "user_id": req.user_id,
            "confirmed_ip": req.src_ip,
            "device": req.device,
            "confirmed_by": x_user,
            "outcome": "Added to contextual learned baseline",
        },
    )

    return {
        "ok": True,
        "user_id": req.user_id,
        "src_ip": req.src_ip,
        "status": "baseline_updated",
        "audit_event_id": audit_entry.sequence_no,
    }
