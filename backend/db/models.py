"""SQLAlchemy ORM models for AgentGuard AI SOC."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class EventModel(Base):
    __tablename__ = "events"

    event_id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    source = Column(String(32), nullable=False)
    host_id = Column(String(128), nullable=True)
    user_id = Column(String(128), nullable=True)
    event_type = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)
    raw_event_ref = Column(String(256), nullable=False)
    attributes_json = Column(Text, nullable=False, default="{}")
    trace_id = Column(String(128), nullable=True)
    request_id = Column(String(128), nullable=True)
    span_id = Column(String(128), nullable=True)
    user_agent = Column(String(512), nullable=True)
    session_id_hash = Column(String(128), nullable=True)
    ingested_at = Column(DateTime(timezone=True), nullable=True)
    source_event_id = Column(String(128), nullable=True)
    schema_version = Column(String(16), nullable=False, default="1.0")

    @property
    def attributes(self) -> Dict[str, Any]:
        try:
            return json.loads(self.attributes_json) if self.attributes_json else {}
        except Exception:
            return {}

    @attributes.setter
    def attributes(self, val: Dict[str, Any]):
        self.attributes_json = json.dumps(val, separators=(",", ":"))


class IncidentModel(Base):
    __tablename__ = "incidents"

    incident_id = Column(String(64), primary_key=True)
    title = Column(String(256), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    affected_hosts_json = Column(Text, nullable=False, default="[]")
    affected_users_json = Column(Text, nullable=False, default="[]")
    affected_ips_json = Column(Text, nullable=False, default="[]")
    evidence_event_ids_json = Column(Text, nullable=False, default="[]")
    detection_reason = Column(Text, nullable=False)
    link_rule = Column(String(64), nullable=False)
    confidence_label = Column(String(32), nullable=False)
    schema_version = Column(String(16), nullable=False, default="1.0")
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)

    @property
    def affected_hosts(self) -> List[str]:
        try:
            return json.loads(self.affected_hosts_json) if self.affected_hosts_json else []
        except Exception:
            return []

    @affected_hosts.setter
    def affected_hosts(self, val: List[str]):
        self.affected_hosts_json = json.dumps(val, separators=(",", ":"))

    @property
    def affected_users(self) -> List[str]:
        try:
            return json.loads(self.affected_users_json) if self.affected_users_json else []
        except Exception:
            return []

    @affected_users.setter
    def affected_users(self, val: List[str]):
        self.affected_users_json = json.dumps(val, separators=(",", ":"))

    @property
    def affected_ips(self) -> List[str]:
        try:
            return json.loads(self.affected_ips_json) if self.affected_ips_json else []
        except Exception:
            return []

    @affected_ips.setter
    def affected_ips(self, val: List[str]):
        self.affected_ips_json = json.dumps(val, separators=(",", ":"))

    @property
    def evidence_event_ids(self) -> List[str]:
        try:
            return json.loads(self.evidence_event_ids_json) if self.evidence_event_ids_json else []
        except Exception:
            return []

    @evidence_event_ids.setter
    def evidence_event_ids(self, val: List[str]):
        self.evidence_event_ids_json = json.dumps(val, separators=(",", ":"))


class EvidenceRefModel(Base):
    __tablename__ = "evidence_refs"

    incident_id = Column(String(64), primary_key=True)
    event_id = Column(String(64), primary_key=True)


class ResponseModel(Base):
    __tablename__ = "responses"

    response_id = Column(String(64), primary_key=True)
    incident_id = Column(String(64), nullable=False, index=True)
    action_type = Column(String(64), nullable=False)
    target_id = Column(String(256), nullable=False)
    requested_by = Column(String(128), nullable=False)
    proposed_by = Column(String(32), nullable=False)
    policy_decision = Column(String(32), nullable=False)
    reason_code = Column(String(64), nullable=False)
    plain_reason = Column(Text, nullable=False)
    approval_state = Column(String(32), nullable=False)
    execution_status = Column(String(32), nullable=False)
    audit_event_id = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)


class ApprovalModel(Base):
    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    response_id = Column(String(64), nullable=False, index=True)
    approver_id = Column(String(128), nullable=False)
    decision = Column(String(32), nullable=False)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    sequence_no = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    actor = Column(String(128), nullable=False)
    event_type = Column(String(64), nullable=False)
    incident_id = Column(String(64), nullable=True)
    response_id = Column(String(64), nullable=True)
    payload_json = Column(Text, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False)

