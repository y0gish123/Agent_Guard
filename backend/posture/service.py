"""Posture assessment service: aggregates all posture checks."""

from typing import Any, Dict, List

from backend.config import get_settings
from backend.posture.checks import (
    check_backup_health,
    check_cookie_flags,
    check_exposed_rdp,
    check_https_hsts,
    check_mfa_coverage,
    check_outdated_software,
    check_security_headers,
)


def run_all_checks() -> Dict[str, Any]:
    """Run all posture checks and return aggregated result."""
    settings = get_settings()
    site_url = settings.SITE_URL
    backup_status_path = getattr(settings, "BACKUP_STATUS_PATH", "data/backup_status.json")
    kev_snapshot_path = "data/kev_snapshot.json"

    checks: List[Dict[str, str]] = [
        check_https_hsts(site_url),
        check_cookie_flags(site_url),
        check_security_headers(site_url),
        check_mfa_coverage(site_url),
        check_exposed_rdp(),
        check_backup_health(backup_status_path),
        check_outdated_software(site_url, kev_snapshot_path),
    ]

    # Summary counts
    status_counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}
    for c in checks:
        s = c.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1

    overall = "pass"
    if status_counts["fail"] > 0:
        overall = "fail"
    elif status_counts["warn"] > 0:
        overall = "warn"
    elif status_counts["unknown"] == len(checks):
        overall = "unknown"

    return {
        "overall": overall,
        "summary": status_counts,
        "checks": checks,
        "site_url": site_url,
        "note": "SIMULATION — posture checks inspect only this machine and the configured localhost site.",
    }

