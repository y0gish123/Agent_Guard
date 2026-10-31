"""GET /api/posture endpoint."""

from fastapi import APIRouter
from typing import Any, Dict

from backend.posture.service import run_all_checks

router = APIRouter(prefix="/api/posture", tags=["posture"])


@router.get("")
def get_posture() -> Dict[str, Any]:
    """Return security posture assessment.

    Checks: HTTPS/HSTS, cookie flags, security headers, MFA coverage,
    RDP exposure, backup health, outdated software (CISA KEV match).

    All checks target ONLY the configured localhost SITE_URL.
    SIMULATION: posture checks inspect only this machine and localhost site.
    """
    return run_all_checks()

