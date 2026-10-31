"""Policy evaluator coordinating rules P1 through P6."""

from typing import Tuple
from backend.policy.messages import get_plain_reason
from backend.policy.rules import (
    PolicyRuleViolation,
    evaluate_p1_incident_open,
    evaluate_p2_action_valid,
    evaluate_p3_category_allowlist,
    evaluate_p4_scope,
    evaluate_p5_role,
)
from shared.contracts import (
    ActionType,
    Incident,
    PolicyDecision,
    ReasonCode,
    Role,
)


class PolicyEvaluator:
    @staticmethod
    def evaluate_preview(
        incident: Incident,
        action_type: ActionType | str,
        target_id: str,
        role: Role,
    ) -> Tuple[PolicyDecision, ReasonCode, str]:
        """Evaluate full preview policy (P1 through P6 in order).
        Returns (PolicyDecision, ReasonCode, plain_reason).
        """
        try:
            # P1: Incident open
            evaluate_p1_incident_open(incident)

            # P2: Action type valid
            action = evaluate_p2_action_valid(action_type)

            # P3: Category allowlist
            evaluate_p3_category_allowlist(incident, action)

            # P4: Scope check
            evaluate_p4_scope(incident, action, target_id)

            # P5: Role check
            evaluate_p5_role(role)

            # P6: In MVP, in-scope actions require human approval
            decision = PolicyDecision.REVIEW
            code = ReasonCode.APPROVAL_REQUIRED
            return decision, code, get_plain_reason(code)

        except PolicyRuleViolation as violation:
            return violation.decision, violation.code, get_plain_reason(violation.code)

    @staticmethod
    def evaluate_execution(
        incident: Incident,
        action_type: ActionType | str,
        target_id: str,
    ) -> Tuple[PolicyDecision, ReasonCode, str]:
        """Re-evaluate rules P1, P3, P4 immediately prior to execution.
        Returns (PolicyDecision, ReasonCode, plain_reason).
        """
        try:
            evaluate_p1_incident_open(incident)
            action = evaluate_p2_action_valid(action_type)
            evaluate_p3_category_allowlist(incident, action)
            evaluate_p4_scope(incident, action, target_id)

            # Passed execution policy check
            return PolicyDecision.ALLOW, ReasonCode.APPROVAL_REQUIRED, ""

        except PolicyRuleViolation as violation:
            return violation.decision, violation.code, get_plain_reason(violation.code)

