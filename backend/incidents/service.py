"""Service layer for incidents and events."""

from datetime import timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.db.models import EventModel, IncidentModel
from backend.incidents.repository import IncidentRepository
from shared.contracts import (
    Category,
    Confidence,
    Event,
    EventType,
    Incident,
    IncidentStatus,
    LinkRule,
    Severity,
    Source,
)


def model_to_event(m: EventModel) -> Event:
    ts = m.timestamp
    if ts and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ingested = getattr(m, "ingested_at", None)
    if ingested and ingested.tzinfo is None:
        ingested = ingested.replace(tzinfo=timezone.utc)
    return Event(
        event_id=m.event_id,
        timestamp=ts,
        source=Source(m.source),
        host_id=m.host_id,
        user_id=m.user_id,
        event_type=EventType(m.event_type),
        severity=Severity(m.severity),
        raw_event_ref=m.raw_event_ref,
        attributes=m.attributes,
        trace_id=getattr(m, "trace_id", None),
        request_id=getattr(m, "request_id", None),
        span_id=getattr(m, "span_id", None),
        user_agent=getattr(m, "user_agent", None),
        session_id_hash=getattr(m, "session_id_hash", None),
        ingested_at=ingested,
        source_event_id=getattr(m, "source_event_id", None),
        schema_version="1.0",
    )


def model_to_incident(m: IncidentModel) -> Incident:
    fs = m.first_seen
    if fs and fs.tzinfo is None:
        fs = fs.replace(tzinfo=timezone.utc)
    ls = m.last_seen
    if ls and ls.tzinfo is None:
        ls = ls.replace(tzinfo=timezone.utc)
    ca = m.created_at
    if ca and ca.tzinfo is None:
        ca = ca.replace(tzinfo=timezone.utc)
    ua = m.updated_at
    if ua and ua.tzinfo is None:
        ua = ua.replace(tzinfo=timezone.utc)

    return Incident(
        incident_id=m.incident_id,
        title=m.title,
        category=Category(m.category),
        severity=Severity(m.severity),
        status=IncidentStatus(m.status),
        first_seen=fs,
        last_seen=ls,
        affected_hosts=m.affected_hosts,
        affected_users=m.affected_users,
        affected_ips=getattr(m, "affected_ips", []) or [],
        evidence_event_ids=m.evidence_event_ids,
        detection_reason=m.detection_reason,
        link_rule=LinkRule(m.link_rule),
        confidence_label=Confidence(m.confidence_label),
        schema_version="1.0",
        created_at=ca,
        updated_at=ua,
    )


class IncidentService:
    def __init__(self, db: Session):
        self.repo = IncidentRepository(db)

    def ingest_events(self, events: List[Event]) -> Tuple[int, int]:
        return self.repo.insert_events(events)

    def upsert_candidates(self, candidates: List[Incident]) -> Tuple[int, int]:
        return self.repo.upsert_candidates(candidates)

    def get_incident(self, incident_id: str) -> Optional[Tuple[Incident, List[Event]]]:
        model = self.repo.get_incident(incident_id)
        if not model:
            return None
        incident_contract = model_to_incident(model)
        events_models = self.repo.get_incident_events(model)
        events_contracts = [model_to_event(ev) for ev in events_models]
        return incident_contract, events_contracts

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Incident], int]:
        models, total = self.repo.list_incidents(
            status=status, severity=severity, limit=limit, offset=offset
        )
        return [model_to_incident(m) for m in models], total

    def get_funnel_counts(self) -> Tuple[int, int, int]:
        return self.repo.get_funnel_counts()

