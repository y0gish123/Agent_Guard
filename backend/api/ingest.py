"""Event and incident candidate ingestion endpoints."""

from typing import Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.hooks import on_new_events
from backend.incidents.service import IncidentService
from shared.contracts import Event, Incident

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


@router.post("/events")
def ingest_events(
    events: List[Event],
    db: Session = Depends(get_db),
) -> Dict[str, int]:
    from datetime import datetime, timezone
    now_utc = datetime.now(timezone.utc)
    for ev in events:
        if ev.ingested_at is None:
            ev.ingested_at = now_utc
    service = IncidentService(db)
    inserted, skipped = service.ingest_events(events)
    # Trigger downstream extension hook
    on_new_events(events, db=db)
    return {"inserted": inserted, "skipped": skipped}


@router.post("/incident-candidates")
def ingest_incident_candidates(
    candidates: List[Incident],
    db: Session = Depends(get_db),
) -> Dict[str, int]:
    service = IncidentService(db)
    created, updated = service.upsert_candidates(candidates)
    try:
        from backend.api.stream import publish_event
        for c in candidates:
            publish_event(
                "incident_created" if created > 0 else "incident_updated",
                {
                    "incident_id": c.incident_id,
                    "category": c.category.value if hasattr(c.category, "value") else str(c.category),
                    "severity": c.severity.value if hasattr(c.severity, "value") else str(c.severity),
                },
            )
    except Exception:
        pass
    return {"created": created, "updated": updated}

