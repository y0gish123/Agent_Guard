"""Response approval and verified execution endpoints."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.common import make_error_response
from backend.audit.service import AuditService
from backend.authorization.token_issuer import TokenIssuer
from backend.config import get_settings
from backend.db.models import ApprovalModel, IncidentModel, ResponseModel
from backend.db.session import get_db
from backend.incidents.service import model_to_incident
from backend.policy.evaluator import PolicyEvaluator
from backend.policy.messages import get_plain_reason
from shared.contracts import (
    ActionType,
    ApprovalState,
    ApproveRequest,
    ExecutionStatus,
    PolicyDecision,
    ReasonCode,
    ResponseRecord,
    Role,
)

router = APIRouter(prefix="/api/responses", tags=["responses"])


@router.post("/{id}/approve")
def approve_response(
    id: str,
    req: ApproveRequest,
    x_user: str = Header(default="anonymous", alias="X-User"),
    x_role: str = Header(default="staff", alias="X-Role"),
    db: Session = Depends(get_db),
) -> ResponseRecord:
    audit_service = AuditService(db)
    clean_role = (x_role or "staff").strip().lower()

    # Approver only
    if clean_role != Role.approver.value:
        audit_service.record_event(
            actor=x_user,
            event_type="error",
            response_id=id,
            payload={
                "response_id": id,
                "reason_code": ReasonCode.ROLE_NOT_PERMITTED.value,
                "outcome": get_plain_reason(ReasonCode.ROLE_NOT_PERMITTED),
            },
        )
        raise make_error_response(
            status_code=403,
            code=ReasonCode.ROLE_NOT_PERMITTED,
            message=get_plain_reason(ReasonCode.ROLE_NOT_PERMITTED),
        )

    # 1. Load response
    resp = db.execute(select(ResponseModel).where(ResponseModel.response_id == id)).scalar_one_or_none()
    if not resp:
        raise make_error_response(
            status_code=404,
            code="RESPONSE_NOT_FOUND",
            message="Response record not found",
        )

    # Must be REVIEW and pending
    if resp.policy_decision != PolicyDecision.REVIEW.value or resp.approval_state != ApprovalState.pending.value:
        raise make_error_response(
            status_code=400,
            code="INVALID_STATE",
            message="Response is not in a pending review state",
        )

    new_approval_state = ApprovalState.approved.value if req.decision == "approve" else ApprovalState.rejected.value
    now_utc = datetime.now(timezone.utc)

    # Store approval
    approval = ApprovalModel(
        response_id=id,
        approver_id=x_user,
        decision=req.decision,
        reason=req.reason,
        created_at=now_utc,
    )
    db.add(approval)

    resp.approval_state = new_approval_state
    db.commit()

    # Audit approval
    audit_event = audit_service.record_event(
        actor=x_user,
        event_type="approval",
        incident_id=resp.incident_id,
        response_id=id,
        payload={
            "incident_id": resp.incident_id,
            "response_id": id,
            "action_type": resp.action_type,
            "target_id": resp.target_id,
            "decision": req.decision,
            "reason_code": ReasonCode.APPROVAL_REQUIRED.value,
            "outcome": req.reason,
        },
    )
    try:
        from backend.api.stream import publish_event
        publish_event("response_updated", {
            "incident_id": resp.incident_id,
            "response_id": id,
            "status": resp.approval_state,
        })
    except Exception:
        pass

    created_dt = resp.created_at
    if created_dt and created_dt.tzinfo is None:
        created_dt = created_dt.replace(tzinfo=timezone.utc)

    return ResponseRecord(
        response_id=resp.response_id,
        incident_id=resp.incident_id,
        action_type=ActionType(resp.action_type),
        target_id=resp.target_id,
        requested_by=resp.requested_by,
        proposed_by=resp.proposed_by,
        policy_decision=resp.policy_decision,
        reason_code=resp.reason_code,
        plain_reason=resp.plain_reason,
        approval_state=ApprovalState(resp.approval_state),
        execution_status=resp.execution_status,
        audit_event_id=audit_event.sequence_no,
        created_at=created_dt,
    )


@router.post("/{id}/execute")
def execute_response(
    id: str,
    x_user: str = Header(default="anonymous", alias="X-User"),
    x_role: str = Header(default="staff", alias="X-Role"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    audit_service = AuditService(db)
    clean_role = (x_role or "staff").strip().lower()

    # Step 0: Approver role verification
    if clean_role != Role.approver.value:
        audit_service.record_event(
            actor=x_user,
            event_type="error",
            response_id=id,
            payload={
                "response_id": id,
                "reason_code": ReasonCode.ROLE_NOT_PERMITTED.value,
                "outcome": get_plain_reason(ReasonCode.ROLE_NOT_PERMITTED),
            },
        )
        raise make_error_response(
            status_code=403,
            code=ReasonCode.ROLE_NOT_PERMITTED,
            message=get_plain_reason(ReasonCode.ROLE_NOT_PERMITTED),
        )

    # Step 1: Load response, 404 if missing
    resp = db.execute(select(ResponseModel).where(ResponseModel.response_id == id)).scalar_one_or_none()
    if not resp:
        raise make_error_response(
            status_code=404,
            code="RESPONSE_NOT_FOUND",
            message="Response record not found",
        )

    # Step 2: If it already succeeded, return 409 with reason TOKEN_REPLAYED (approval is single-use)
    if resp.execution_status == ExecutionStatus.succeeded.value:
        raise make_error_response(
            status_code=409,
            code=ReasonCode.TOKEN_REPLAYED,
            message=get_plain_reason(ReasonCode.TOKEN_REPLAYED),
        )

    # Step 3: Re-run policy rules P1, P3, P4 now; if BLOCK, set execution_status blocked, audit, return
    inc_model = db.execute(select(IncidentModel).where(IncidentModel.incident_id == resp.incident_id)).scalar_one_or_none()
    if not inc_model:
        resp.execution_status = ExecutionStatus.blocked.value
        resp.reason_code = ReasonCode.INCIDENT_NOT_OPEN.value
        resp.plain_reason = get_plain_reason(ReasonCode.INCIDENT_NOT_OPEN)
        db.commit()
        audit_service.record_event(
            actor=x_user,
            event_type="policy_decision",
            incident_id=resp.incident_id,
            response_id=id,
            payload={
                "incident_id": resp.incident_id,
                "response_id": id,
                "action_type": resp.action_type,
                "target_id": resp.target_id,
                "decision": PolicyDecision.BLOCK.value,
                "reason_code": ReasonCode.INCIDENT_NOT_OPEN.value,
                "outcome": resp.plain_reason,
            },
        )
        return {
            "response_id": id,
            "execution_status": resp.execution_status,
            "reason_code": resp.reason_code,
            "plain_reason": resp.plain_reason,
            "audit_event_id": resp.audit_event_id,
            "tool_result": None,
        }

    incident_contract = model_to_incident(inc_model)
    exec_decision, exec_code, exec_reason = PolicyEvaluator.evaluate_execution(
        incident=incident_contract,
        action_type=resp.action_type,
        target_id=resp.target_id,
    )
    if exec_decision == PolicyDecision.BLOCK:
        resp.execution_status = ExecutionStatus.blocked.value
        resp.reason_code = exec_code.value
        resp.plain_reason = exec_reason
        db.commit()
        audit_event = audit_service.record_event(
            actor=x_user,
            event_type="policy_decision",
            incident_id=resp.incident_id,
            response_id=id,
            payload={
                "incident_id": resp.incident_id,
                "response_id": id,
                "action_type": resp.action_type,
                "target_id": resp.target_id,
                "decision": PolicyDecision.BLOCK.value,
                "reason_code": exec_code.value,
                "outcome": exec_reason,
            },
        )
        return {
            "response_id": id,
            "execution_status": resp.execution_status,
            "reason_code": resp.reason_code,
            "plain_reason": resp.plain_reason,
            "audit_event_id": audit_event.sequence_no,
            "tool_result": None,
        }

    # Step 4: Require approval_state approved for the exact tuple, else return 409 APPROVAL_NOT_RECORDED and issue no token
    if resp.approval_state != ApprovalState.approved.value:
        raise make_error_response(
            status_code=409,
            code=ReasonCode.APPROVAL_NOT_RECORDED,
            message=get_plain_reason(ReasonCode.APPROVAL_NOT_RECORDED),
        )

    # Verify that an approval record exists bound to response_id
    appr_record = db.execute(
        select(ApprovalModel).where(
            ApprovalModel.response_id == id,
            ApprovalModel.decision == "approve",
        )
    ).scalar_one_or_none()
    if not appr_record:
        raise make_error_response(
            status_code=409,
            code=ReasonCode.APPROVAL_NOT_RECORDED,
            message=get_plain_reason(ReasonCode.APPROVAL_NOT_RECORDED),
        )

    # Step 5: Issue a token and audit token_issued (token id only)
    settings = get_settings()
    issuer = TokenIssuer(secret=settings.HMAC_SECRET, ttl_seconds=settings.TOKEN_TTL_SECONDS)
    token, claims = issuer.issue_token(
        incident_id=resp.incident_id,
        action_type=resp.action_type,
        target_id=resp.target_id,
    )

    token_audit = audit_service.record_event(
        actor="token_issuer",
        event_type="token_issued",
        incident_id=resp.incident_id,
        response_id=id,
        payload={
            "incident_id": resp.incident_id,
            "response_id": id,
            "token_id": claims["tid"],
            "action_type": resp.action_type,
            "target_id": resp.target_id,
            "decision": "issued",
            "reason_code": "ISSUED",
            "outcome": "Token generated for verified policy execution",
        },
    )

    # Step 6: POST to the mock tool with a 3-second timeout
    tool_url = f"{settings.TOOL_URL.rstrip('/')}/tool/execute"
    payload = {
        "token": token,
        "incident_id": resp.incident_id,
        "action_type": resp.action_type,
        "target_id": resp.target_id,
    }

    try:
        with httpx.Client(timeout=3.0) as client:
            tool_resp = client.post(tool_url, json=payload)
            tool_resp_data = tool_resp.json()
    except Exception as exc:
        # Connection failure -> execution_status failed, reason TOOL_UNAVAILABLE, audit error, state unchanged
        resp.execution_status = ExecutionStatus.failed.value
        resp.reason_code = ReasonCode.TOOL_UNAVAILABLE.value
        resp.plain_reason = get_plain_reason(ReasonCode.TOOL_UNAVAILABLE)
        db.commit()

        err_audit = audit_service.record_event(
            actor="gateway",
            event_type="error",
            incident_id=resp.incident_id,
            response_id=id,
            payload={
                "incident_id": resp.incident_id,
                "response_id": id,
                "action_type": resp.action_type,
                "target_id": resp.target_id,
                "reason_code": ReasonCode.TOOL_UNAVAILABLE.value,
                "outcome": str(exc),
            },
        )
        return {
            "response_id": id,
            "execution_status": resp.execution_status,
            "reason_code": resp.reason_code,
            "plain_reason": resp.plain_reason,
            "audit_event_id": err_audit.sequence_no,
            "tool_result": None,
        }

    # Step 7: Map the tool result to execution_status (succeeded or rejected_by_tool)
    # and reason_code (EXECUTED_OK or the tool's code), audit tool_result.
    tool_ok = tool_resp_data.get("ok", False)
    tool_reason_code = tool_resp_data.get("reason_code", "UNKNOWN")

    if tool_ok:
        resp.execution_status = ExecutionStatus.succeeded.value
        resp.reason_code = ReasonCode.EXECUTED_OK.value
        resp.plain_reason = get_plain_reason(ReasonCode.EXECUTED_OK)
    else:
        resp.execution_status = ExecutionStatus.rejected_by_tool.value
        resp.reason_code = tool_reason_code
        resp.plain_reason = get_plain_reason(tool_reason_code)

    db.commit()

    tool_audit = audit_service.record_event(
        actor="mock_tool",
        event_type="tool_result",
        incident_id=resp.incident_id,
        response_id=id,
        payload={
            "incident_id": resp.incident_id,
            "response_id": id,
            "action_type": resp.action_type,
            "target_id": resp.target_id,
            "decision": "executed" if tool_ok else "rejected",
            "reason_code": resp.reason_code,
            "outcome": resp.plain_reason,
        },
    )

    resp.audit_event_id = tool_audit.sequence_no
    db.commit()
    try:
        from backend.api.stream import publish_event
        publish_event("response_updated", {
            "incident_id": resp.incident_id,
            "response_id": id,
            "status": resp.execution_status,
        })
    except Exception:
        pass

    return {
        "response_id": id,
        "execution_status": resp.execution_status,
        "reason_code": resp.reason_code,
        "plain_reason": resp.plain_reason,
        "audit_event_id": tool_audit.sequence_no,
        "tool_result": tool_resp_data,
    }

