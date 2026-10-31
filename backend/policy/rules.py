"""Deterministic policy rules P1 through P6."""

from typing import Optional, Set, Tuple
from shared.contracts import (
    ActionType,
    Category,
    Incident,
    IncidentStatus,
    PolicyDecision,
    ReasonCode,
    Role,
)

CATEGORY_ALLOWED_ACTIONS: dict[Category, Set[ActionType]] = {
    Category.phishing_attempt: {ActionType.lock_account},
    Category.account_takeover: {ActionType.lock_account, ActionType.revoke_session},
    Category.ransomware_like_activity: {ActionType.isolate_host},
    Category.web_attack: {ActionType.isolate_host, ActionType.revoke_session, ActionType.block_ip},
    Category.data_exfiltration_suspected: {ActionType.lock_account, ActionType.revoke_session},
    Category.multi_stage: {
        ActionType.lock_account,
        ActionType.revoke_session,
        ActionType.isolate_host,
        ActionType.block_ip,
    },
}


class PolicyRuleViolation(Exception):
    def __init__(self, decision: PolicyDecision, code: ReasonCode):
        self.decision = decision
        self.code = code
        super().__init__(f"{decision.value}: {code.value}")


def evaluate_p1_incident_open(incident: Incident) -> None:
    """P1: incident exists and status == open else BLOCK INCIDENT_NOT_OPEN."""
    if incident.status != IncidentStatus.open:
        raise PolicyRuleViolation(PolicyDecision.BLOCK, ReasonCode.INCIDENT_NOT_OPEN)


def evaluate_p2_action_valid(action_type: ActionType | str) -> ActionType:
    """P2: action_type in the closed enum else HTTP 422."""
    if isinstance(action_type, ActionType):
        return action_type
    try:
        return ActionType(action_type)
    except ValueError:
        raise ValueError(f"Invalid action_type: {action_type}")


def evaluate_p3_category_allowlist(incident: Incident, action: ActionType) -> None:
    """P3: category allowlist check."""
    allowed = CATEGORY_ALLOWED_ACTIONS.get(incident.category, set())
    if action not in allowed:
        raise PolicyRuleViolation(
            PolicyDecision.BLOCK, ReasonCode.ACTION_NOT_ALLOWED_FOR_CATEGORY
        )


def evaluate_p4_scope(incident: Incident, action: ActionType, target_id: str) -> None:
    """P4: scope check. lock_account & revoke_session require target in affected_users;
    isolate_host requires target in affected_hosts.
    Exact string comparison after trimming whitespace and lowercasing.
    """
    clean_target = (target_id or "").strip().lower()
    if not clean_target:
        raise PolicyRuleViolation(PolicyDecision.BLOCK, ReasonCode.TARGET_OUT_OF_SCOPE)

    if action in (ActionType.lock_account, ActionType.revoke_session):
        users = [u.strip().lower() for u in incident.affected_users]
        if clean_target not in users:
            raise PolicyRuleViolation(PolicyDecision.BLOCK, ReasonCode.TARGET_OUT_OF_SCOPE)
    elif action == ActionType.isolate_host:
        hosts = [h.strip().lower() for h in incident.affected_hosts]
        if clean_target not in hosts:
            raise PolicyRuleViolation(PolicyDecision.BLOCK, ReasonCode.TARGET_OUT_OF_SCOPE)
    elif action == ActionType.block_ip:
        ips = [ip.strip().lower() for ip in (getattr(incident, "affected_ips", []) or [])]
        if clean_target not in ips:
            raise PolicyRuleViolation(PolicyDecision.BLOCK, ReasonCode.TARGET_OUT_OF_SCOPE)
    else:
        raise PolicyRuleViolation(PolicyDecision.BLOCK, ReasonCode.TARGET_OUT_OF_SCOPE)


def evaluate_p5_role(role: Role) -> None:
    """P5: preview requires role staff or approver."""
    if role not in (Role.staff, Role.approver):
        raise PolicyRuleViolation(PolicyDecision.BLOCK, ReasonCode.ROLE_NOT_PERMITTED)

