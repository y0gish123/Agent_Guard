"""Plain language explanations for policy reason codes."""

from shared.contracts import ReasonCode

PLAIN_REASONS = {
    ReasonCode.APPROVAL_REQUIRED: "This action is allowed for this incident but a person must approve it first.",
    ReasonCode.TARGET_OUT_OF_SCOPE: "This account or computer is not part of this incident, so the action was refused.",
    ReasonCode.ACTION_NOT_ALLOWED_FOR_CATEGORY: "This type of action is not allowed for this kind of incident.",
    ReasonCode.INCIDENT_NOT_OPEN: "This incident is already contained or closed.",
    ReasonCode.ROLE_NOT_PERMITTED: "Only an approver can do this.",
    ReasonCode.APPROVAL_NOT_RECORDED: "This action has not been approved yet.",
    ReasonCode.EXECUTED_OK: "The action was carried out in the simulation.",
    ReasonCode.TOKEN_MISSING: "The action tool did not receive a permission token.",
    ReasonCode.TOKEN_BAD_SIGNATURE: "The permission token was not valid.",
    ReasonCode.TOKEN_EXPIRED: "The permission token expired, so nothing was changed.",
    ReasonCode.TOKEN_REPLAYED: "This permission was already used, so nothing was changed.",
    ReasonCode.TOKEN_SCOPE_MISMATCH: "The permission does not match this exact action, so nothing was changed.",
    ReasonCode.TOOL_UNAVAILABLE: "The action tool is not reachable, so nothing was changed.",
}


def get_plain_reason(code: ReasonCode | str) -> str:
    if isinstance(code, str):
        try:
            code = ReasonCode(code)
        except ValueError:
            return "Policy evaluation outcome."
    return PLAIN_REASONS.get(code, "Policy evaluation outcome.")

