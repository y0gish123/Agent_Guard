"""Phishing email check endpoint."""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models import EventModel
from backend.db.session import get_db
from backend.hooks import on_new_events
from shared.contracts import (
    Event,
    EventType,
    PhishingCheckRequest,
    PhishingCheckResponse,
    PhishingReasonItem,
    Severity,
    Source,
)

router = APIRouter(prefix="/api/phishing", tags=["phishing"])


def _get_next_phishing_event_id(db: Session) -> str:
    """Generate the next event_id starting from evt-1001."""
    records = db.execute(
        select(EventModel.event_id).where(EventModel.event_id.like("evt-%"))
    ).scalars().all()

    max_num = 1000
    for eid in records:
        match = re.match(r"^evt-(\d+)$", eid)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num

    return f"evt-{max_num + 1}"


@router.post("/check")
def check_phishing(
    req: PhishingCheckRequest,
    db: Session = Depends(get_db),
) -> PhishingCheckResponse:
    verdict = "amber"
    score = 30
    reasons = [
        PhishingReasonItem(
            code="R_STUB",
            text="Default heuristic: urgent language or external sender detected.",
            snippet=req.text[:200],
        )
    ]

    # Try importing detection.phishing.scorer if available
    try:
        import detection.phishing.scorer  # type: ignore

        if hasattr(detection.phishing.scorer, "score_message"):
            result = detection.phishing.scorer.score_message(req.text, req.sender, req.reply_to)
            if isinstance(result, dict):
                verdict = result.get("verdict", verdict)
                score = result.get("score", score)
                raw_reasons = result.get("reasons", [])
                reasons = [
                    PhishingReasonItem(
                        code=r.get("code", "UNKNOWN"),
                        text=r.get("text", ""),
                        snippet=r.get("snippet", ""),
                    )
                    for r in raw_reasons
                ]
    except Exception:
        pass

    # Severity mapping: red -> high, amber -> medium, green -> low
    sev_map = {
        "red": Severity.high,
        "amber": Severity.medium,
        "green": Severity.low,
    }
    severity = sev_map.get(verdict, Severity.medium)
    event_id = _get_next_phishing_event_id(db)

    now_utc = datetime.now(timezone.utc)
    reason_codes_joined = ",".join([r.code for r in reasons])
    snippet_200 = req.text[:200]

    event_model = EventModel(
        event_id=event_id,
        timestamp=now_utc,
        source=Source.phishing_check.value,
        host_id=None,
        user_id=req.user_id,
        event_type=EventType.phishing_check.value,
        severity=severity.value,
        raw_event_ref=f"phish-{event_id}",
        schema_version="1.0",
    )
    event_model.attributes = {
        "verdict": verdict,
        "score": score,
        "reason_codes": reason_codes_joined,
        "snippet": snippet_200,
    }
    db.add(event_model)
    db.commit()

    # Call downstream on_new_events hook
    stored_event = Event(
        event_id=event_id,
        timestamp=now_utc,
        source=Source.phishing_check,
        host_id=None,
        user_id=req.user_id,
        event_type=EventType.phishing_check,
        severity=severity,
        raw_event_ref=f"phish-{event_id}",
        attributes=event_model.attributes,
        schema_version="1.0",
    )
    on_new_events([stored_event], db=db)

    return PhishingCheckResponse(
        verdict=verdict,
        score=score,
        reasons=reasons,
        event_id=event_id,
    )

