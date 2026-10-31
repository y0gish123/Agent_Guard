"""Shared contracts, enums, and Pydantic models for AgentGuard AI SOC."""

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator


# Enums (string values identical to names)
class Source(str, Enum):
    replay = "replay"
    wazuh = "wazuh"
    collector = "collector"
    phishing_check = "phishing_check"
    simulator = "simulator"


class EventType(str, Enum):
    authentication_failure = "authentication_failure"
    authentication_success = "authentication_success"
    privilege_change = "privilege_change"
    scheduled_task_created = "scheduled_task_created"
    process_start = "process_start"
    backup_tampering = "backup_tampering"
    file_change_burst = "file_change_burst"
    file_created = "file_created"
    phishing_check = "phishing_check"
    web_request = "web_request"
    data_access = "data_access"
    dns_query = "dns_query"
    network_connection = "network_connection"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Category(str, Enum):
    phishing_attempt = "phishing_attempt"
    account_takeover = "account_takeover"
    ransomware_like_activity = "ransomware_like_activity"
    multi_stage = "multi_stage"
    web_attack = "web_attack"
    data_exfiltration_suspected = "data_exfiltration_suspected"


class IncidentStatus(str, Enum):
    open = "open"
    contained = "contained"
    closed = "closed"


class LinkRule(str, Enum):
    LINK_SAME_USER_30M = "LINK_SAME_USER_30M"
    LINK_SAME_HOST_30M = "LINK_SAME_HOST_30M"
    NONE = "NONE"


class Confidence(str, Enum):
    low = "low"
    needs_review = "needs_review"
    likely = "likely"


class ActionType(str, Enum):
    lock_account = "lock_account"
    revoke_session = "revoke_session"
    isolate_host = "isolate_host"
    block_ip = "block_ip"


class ProposedBy(str, Enum):
    human = "human"
    ai = "ai"


class Role(str, Enum):
    staff = "staff"
    approver = "approver"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ApprovalState(str, Enum):
    not_required = "not_required"
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


class ExecutionStatus(str, Enum):
    not_started = "not_started"
    succeeded = "succeeded"
    rejected_by_tool = "rejected_by_tool"
    blocked = "blocked"
    failed = "failed"


class ReasonCode(str, Enum):
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    TARGET_OUT_OF_SCOPE = "TARGET_OUT_OF_SCOPE"
    ACTION_NOT_ALLOWED_FOR_CATEGORY = "ACTION_NOT_ALLOWED_FOR_CATEGORY"
    INCIDENT_NOT_OPEN = "INCIDENT_NOT_OPEN"
    ROLE_NOT_PERMITTED = "ROLE_NOT_PERMITTED"
    APPROVAL_NOT_RECORDED = "APPROVAL_NOT_RECORDED"
    EXECUTED_OK = "EXECUTED_OK"
    TOKEN_MISSING = "TOKEN_MISSING"
    TOKEN_BAD_SIGNATURE = "TOKEN_BAD_SIGNATURE"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_REPLAYED = "TOKEN_REPLAYED"
    TOKEN_SCOPE_MISMATCH = "TOKEN_SCOPE_MISMATCH"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"


def format_datetime_utc(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# Pydantic Models
SafeString = Annotated[str, Field(max_length=2000)]


class Event(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    event_id: Annotated[str, Field(pattern=r"^evt-[A-Za-z0-9_\-]+$", max_length=64)]
    timestamp: datetime
    source: Source
    host_id: Optional[SafeString] = None
    user_id: Optional[SafeString] = None
    event_type: EventType
    severity: Severity
    raw_event_ref: SafeString
    attributes: Dict[str, str | int | float | bool] = Field(default_factory=dict)
    trace_id: Optional[SafeString] = None
    request_id: Optional[SafeString] = None
    span_id: Optional[SafeString] = None
    user_agent: Optional[SafeString] = None
    session_id_hash: Optional[SafeString] = None
    ingested_at: Optional[datetime] = None
    source_event_id: Optional[SafeString] = None
    schema_version: Literal["1.0"] = "1.0"

    @field_serializer("timestamp", "ingested_at", when_used="json")
    def serialize_timestamp(self, dt: Optional[datetime]) -> Optional[str]:
        return format_datetime_utc(dt) if dt else None


class Incident(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    incident_id: Annotated[str, Field(pattern=r"^inc-[0-9a-fA-F]{8}$", max_length=64)]
    title: SafeString
    category: Category
    severity: Severity
    status: IncidentStatus
    first_seen: datetime
    last_seen: datetime
    affected_hosts: List[SafeString] = Field(default_factory=list)
    affected_users: List[SafeString] = Field(default_factory=list)
    affected_ips: List[SafeString] = Field(default_factory=list)
    evidence_event_ids: List[Annotated[str, Field(max_length=64)]] = Field(default_factory=list)
    detection_reason: SafeString
    link_rule: LinkRule
    confidence_label: Confidence
    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    updated_at: datetime

    @field_serializer("first_seen", "last_seen", "created_at", "updated_at", when_used="json")
    def serialize_datetimes(self, dt: datetime) -> str:
        return format_datetime_utc(dt) or ""


class ActionProposal(BaseModel):
    action_type: ActionType
    target_id: SafeString
    reason: SafeString


class PreviewRequest(BaseModel):
    action_type: ActionType
    target_id: SafeString
    requested_by: SafeString
    proposed_by: ProposedBy


class ResponseRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    response_id: Annotated[str, Field(pattern=r"^resp-[A-Za-z0-9_\-]+$", max_length=64)]
    incident_id: Annotated[str, Field(max_length=64)]
    action_type: ActionType
    target_id: SafeString
    requested_by: SafeString
    proposed_by: ProposedBy
    policy_decision: PolicyDecision
    reason_code: ReasonCode
    plain_reason: SafeString
    approval_state: ApprovalState
    execution_status: ExecutionStatus
    audit_event_id: Optional[int] = None
    created_at: datetime

    @field_serializer("created_at", when_used="json")
    def serialize_created_at(self, dt: datetime) -> str:
        return format_datetime_utc(dt) or ""


class ApproveRequest(BaseModel):
    decision: Literal["approve", "reject"]
    reason: SafeString


class ErrorBody(BaseModel):
    code: str
    plain_message: str
    detail_id: str


class ObservedFact(BaseModel):
    text: SafeString
    evidence_event_ids: List[str] = Field(default_factory=list)


class Explanation(BaseModel):
    incident_id: str
    lang: Literal["en", "hi", "kn"]
    summary: SafeString
    observed_facts: List[ObservedFact] = Field(default_factory=list)
    interpretation: SafeString
    potential_impact: List[SafeString] = Field(default_factory=list)
    confidence_label: Confidence
    recommended_next_steps: List[SafeString] = Field(default_factory=list)
    recommended_actions: List[ActionProposal] = Field(default_factory=list)
    generated_by: Literal["llm", "cache", "fallback"]
    mode: Literal["guarded", "naive"]


class PhishingCheckRequest(BaseModel):
    user_id: SafeString
    text: Annotated[str, Field(max_length=100000)]
    sender: Optional[SafeString] = None
    reply_to: Optional[SafeString] = None


class PhishingReasonItem(BaseModel):
    code: str
    text: str
    snippet: str


class PhishingCheckResponse(BaseModel):
    verdict: Literal["red", "amber", "green"]
    score: int
    reasons: List[PhishingReasonItem] = Field(default_factory=list)
    event_id: str


class FunnelCounts(BaseModel):
    raw_events: int
    alerts: int
    incidents: int


class Meta(BaseModel):
    demo_mode: str
    simulation: bool = True
    schema_version: str = "1.0"
    ai_available: bool

