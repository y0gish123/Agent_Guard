"""Audit logging service for tamper-evident event chains."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.audit.hashing import GENESIS_PREVIOUS_HASH, canonical_json, compute_event_hash
from backend.db.models import AuditEventModel


class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def record_event(
        self,
        actor: str,
        event_type: str,
        payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        response_id: Optional[str] = None,
    ) -> AuditEventModel:
        """Atomically record an audit event appending to the hash chain."""
        # Sanitize payload: NEVER include tokens or raw secrets
        safe_payload = {
            k: v for k, v in payload.items()
            if not any(secret_key in k.lower() for secret_key in ("token", "secret", "password", "key"))
            or k == "token_id"  # token_id/tid (e.g. tok-001) is allowed and required by prompt for token_issued
        }

        # Query latest audit event to find previous_hash
        latest = self.db.execute(
            select(AuditEventModel).order_by(AuditEventModel.sequence_no.desc()).limit(1)
        ).scalar_one_or_none()

        previous_hash = latest.event_hash if latest else GENESIS_PREVIOUS_HASH
        event_hash = compute_event_hash(previous_hash, safe_payload)

        audit_entry = AuditEventModel(
            created_at=datetime.now(timezone.utc),
            actor=actor,
            event_type=event_type,
            incident_id=incident_id,
            response_id=response_id,
            payload_json=canonical_json(safe_payload),
            previous_hash=previous_hash,
            event_hash=event_hash,
        )
        self.db.add(audit_entry)
        self.db.commit()
        self.db.refresh(audit_entry)
        try:
            from backend.api.stream import publish_event
            publish_event("audit_appended", {"incident_id": incident_id})
        except Exception:
            pass
        return audit_entry

    def list_events(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Return audit records, newest last (ascending sequence order)."""
        stmt = (
            select(AuditEventModel)
            .order_by(AuditEventModel.sequence_no.asc())
            .offset(offset)
            .limit(limit)
        )
        records = self.db.execute(stmt).scalars().all()
        return [
            {
                "sequence_no": r.sequence_no,
                "created_at": r.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if r.created_at.tzinfo else r.created_at.isoformat() + "Z",
                "actor": r.actor,
                "event_type": r.event_type,
                "incident_id": r.incident_id,
                "response_id": r.response_id,
                "payload": json.loads(r.payload_json),
                "previous_hash": r.previous_hash,
                "event_hash": r.event_hash,
            }
            for r in records
        ]

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the cryptographic integrity of the entire audit chain."""
        records = list(
            self.db.execute(
                select(AuditEventModel).order_by(AuditEventModel.sequence_no.asc())
            ).scalars().all()
        )

        expected_previous_hash = GENESIS_PREVIOUS_HASH
        checked = 0

        for record in records:
            if record.previous_hash != expected_previous_hash:
                return {
                    "ok": False,
                    "checked": checked,
                    "first_bad_sequence_no": record.sequence_no,
                }

            try:
                payload = json.loads(record.payload_json)
            except Exception:
                return {
                    "ok": False,
                    "checked": checked,
                    "first_bad_sequence_no": record.sequence_no,
                }

            computed_hash = compute_event_hash(record.previous_hash, payload)
            if computed_hash != record.event_hash:
                return {
                    "ok": False,
                    "checked": checked,
                    "first_bad_sequence_no": record.sequence_no,
                }

            expected_previous_hash = record.event_hash
            checked += 1

        return {
            "ok": True,
            "checked": checked,
            "first_bad_sequence_no": None,
        }

