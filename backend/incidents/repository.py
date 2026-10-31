"""Repository for incidents and events."""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import EventModel, IncidentModel, EvidenceRefModel
from shared.contracts import Event, Incident, Severity


SEVERITY_ORDER: Dict[str, int] = {
    Severity.low.value: 1,
    Severity.medium.value: 2,
    Severity.high.value: 3,
    Severity.critical.value: 4,
}


class IncidentRepository:
    def __init__(self, db: Session):
        self.db = db

    def insert_events(self, events: List[Event]) -> Tuple[int, int]:
        """Idempotently insert events by event_id. Returns (inserted_count, skipped_count)."""
        inserted = 0
        skipped = 0
        for ev in events:
            existing = self.db.execute(
                select(EventModel).where(EventModel.event_id == ev.event_id)
            ).scalar_one_or_none()
            if existing:
                skipped += 1
                continue

            model = EventModel(
                event_id=ev.event_id,
                timestamp=ev.timestamp if ev.timestamp.tzinfo else ev.timestamp.replace(tzinfo=timezone.utc),
                source=ev.source.value,
                host_id=ev.host_id,
                user_id=ev.user_id,
                event_type=ev.event_type.value,
                severity=ev.severity.value,
                raw_event_ref=ev.raw_event_ref,
                trace_id=ev.trace_id,
                request_id=ev.request_id,
                span_id=ev.span_id,
                user_agent=ev.user_agent,
                session_id_hash=ev.session_id_hash,
                ingested_at=ev.ingested_at or datetime.now(timezone.utc),
                source_event_id=ev.source_event_id,
                schema_version=ev.schema_version,
            )
            model.attributes = ev.attributes
            self.db.add(model)
            inserted += 1
        self.db.commit()
        return inserted, skipped

    def upsert_candidates(self, candidates: List[Incident]) -> Tuple[int, int]:
        """Upsert incident candidates. Returns (created_count, updated_count)."""
        created = 0
        updated = 0
        now_utc = datetime.now(timezone.utc)

        for cand in candidates:
            cand_first_seen = cand.first_seen if cand.first_seen.tzinfo else cand.first_seen.replace(tzinfo=timezone.utc)
            cand_last_seen = cand.last_seen if cand.last_seen.tzinfo else cand.last_seen.replace(tzinfo=timezone.utc)
            cand_created_at = cand.created_at if cand.created_at.tzinfo else cand.created_at.replace(tzinfo=timezone.utc)

            existing: Optional[IncidentModel] = self.db.execute(
                select(IncidentModel).where(IncidentModel.incident_id == cand.incident_id)
            ).scalar_one_or_none()

            if not existing:
                # Insert new incident
                new_model = IncidentModel(
                    incident_id=cand.incident_id,
                    title=cand.title,
                    category=cand.category.value,
                    severity=cand.severity.value,
                    status=cand.status.value,
                    first_seen=cand_first_seen,
                    last_seen=cand_last_seen,
                    detection_reason=cand.detection_reason,
                    link_rule=cand.link_rule.value,
                    confidence_label=cand.confidence_label.value,
                    schema_version=cand.schema_version,
                    created_at=cand_created_at,
                    updated_at=now_utc,
                )
                new_model.affected_hosts = sorted(list(set(cand.affected_hosts)))
                new_model.affected_users = sorted(list(set(cand.affected_users)))
                new_model.affected_ips = sorted(list(set(getattr(cand, "affected_ips", []) or [])))
                new_model.evidence_event_ids = sorted(list(set(cand.evidence_event_ids)))
                self.db.add(new_model)

                for eid in cand.evidence_event_ids:
                    ref_exists = self.db.execute(
                        select(EvidenceRefModel).where(
                            EvidenceRefModel.incident_id == cand.incident_id,
                            EvidenceRefModel.event_id == eid,
                        )
                    ).scalar_one_or_none()
                    if not ref_exists:
                        self.db.add(EvidenceRefModel(incident_id=cand.incident_id, event_id=eid))

                created += 1
            else:
                # Update existing incident:
                # union evidence_event_ids, affected_hosts, affected_users
                existing_hosts = set(existing.affected_hosts)
                existing_hosts.update(cand.affected_hosts)
                existing.affected_hosts = sorted(list(existing_hosts))

                existing_users = set(existing.affected_users)
                existing_users.update(cand.affected_users)
                existing.affected_users = sorted(list(existing_users))

                existing_ips = set(existing.affected_ips)
                existing_ips.update(getattr(cand, "affected_ips", []) or [])
                existing.affected_ips = sorted(list(existing_ips))

                existing_evidence = set(existing.evidence_event_ids)
                existing_evidence.update(cand.evidence_event_ids)
                existing.evidence_event_ids = sorted(list(existing_evidence))

                # first_seen=min, last_seen=max
                existing_first = existing.first_seen if existing.first_seen.tzinfo else existing.first_seen.replace(tzinfo=timezone.utc)
                existing_last = existing.last_seen if existing.last_seen.tzinfo else existing.last_seen.replace(tzinfo=timezone.utc)
                existing.first_seen = min(existing_first, cand_first_seen)
                existing.last_seen = max(existing_last, cand_last_seen)

                # update category, link_rule, detection_reason, confidence
                existing.title = cand.title
                existing.category = cand.category.value
                existing.link_rule = cand.link_rule.value
                existing.detection_reason = cand.detection_reason
                existing.confidence_label = cand.confidence_label.value

                # severity may only increase
                curr_sev_rank = SEVERITY_ORDER.get(existing.severity, 1)
                new_sev_rank = SEVERITY_ORDER.get(cand.severity.value, 1)
                if new_sev_rank > curr_sev_rank:
                    existing.severity = cand.severity.value

                # update updated_at
                existing.updated_at = now_utc

                for eid in cand.evidence_event_ids:
                    ref_exists = self.db.execute(
                        select(EvidenceRefModel).where(
                            EvidenceRefModel.incident_id == cand.incident_id,
                            EvidenceRefModel.event_id == eid,
                        )
                    ).scalar_one_or_none()
                    if not ref_exists:
                        self.db.add(EvidenceRefModel(incident_id=cand.incident_id, event_id=eid))

                updated += 1

        self.db.commit()
        return created, updated

    def get_incident(self, incident_id: str) -> Optional[IncidentModel]:
        return self.db.execute(
            select(IncidentModel).where(IncidentModel.incident_id == incident_id)
        ).scalar_one_or_none()

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[IncidentModel], int]:
        stmt = select(IncidentModel)
        if status:
            stmt = stmt.where(IncidentModel.status == status)
        if severity:
            stmt = stmt.where(IncidentModel.severity == severity)

        total = self.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        stmt = stmt.order_by(IncidentModel.created_at.desc()).offset(offset).limit(limit)
        items = list(self.db.execute(stmt).scalars().all())
        return items, total

    def get_incident_events(self, incident: IncidentModel) -> List[EventModel]:
        """Return evidence events in time order."""
        evidence_ids = incident.evidence_event_ids
        if not evidence_ids:
            return []
        stmt = (
            select(EventModel)
            .where(EventModel.event_id.in_(evidence_ids))
            .order_by(EventModel.timestamp.asc())
        )
        return list(self.db.execute(stmt).scalars().all())

    def get_funnel_counts(self) -> Tuple[int, int, int]:
        raw_events = self.db.execute(select(func.count(EventModel.event_id))).scalar_one()
        alerts = self.db.execute(
            select(func.count(func.distinct(EvidenceRefModel.event_id)))
        ).scalar_one()
        incidents = self.db.execute(select(func.count(IncidentModel.incident_id))).scalar_one()
        return raw_events, alerts, incidents

