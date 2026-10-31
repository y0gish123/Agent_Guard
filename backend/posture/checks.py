"""Security posture check implementations for AgentGuard.

Each check returns a dict:
  {
    "name": str,
    "status": "pass" | "warn" | "fail" | "unknown",
    "evidence": str,
    "checked_at": str (ISO8601),
    "recommendation": str
  }

All checks target ONLY localhost / the configured SITE_URL (must be localhost).
Refuses non-localhost targets.
"""

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

# Optional import for psutil (RDP check)
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

# Optional import for requests (HTTP checks)
try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_localhost(url: str) -> bool:
    """Return True only if the URL targets localhost / 127.x.x.x."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip("[]")
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        # Allow 127.x.x.x range
        if host.startswith("127."):
            return True
    except Exception:
        pass
    return False


def _make_check(name: str, status: str, evidence: str, recommendation: str) -> Dict[str, str]:
    return {
        "name": name,
        "status": status,
        "evidence": evidence[:500],
        "checked_at": _now_str(),
        "recommendation": recommendation[:300],
    }


def check_https_hsts(site_url: str) -> Dict[str, str]:
    """Check HTTPS/TLS and HSTS header on configured localhost site."""
    if not _is_localhost(site_url):
        return _make_check("HTTPS/HSTS", "unknown", "Refusing non-localhost target.", "Only localhost targets are supported.")

    if not _REQUESTS_AVAILABLE:
        return _make_check("HTTPS/HSTS", "unknown", "requests library not available.", "Install requests to enable this check.")

    parsed = urlparse(site_url)
    is_https = parsed.scheme == "https"
    hsts_present = False
    hsts_value = ""

    try:
        resp = _requests.get(site_url, timeout=3, verify=False, allow_redirects=True)
        hsts_value = resp.headers.get("Strict-Transport-Security", "")
        hsts_present = bool(hsts_value)
    except Exception as e:
        return _make_check("HTTPS/HSTS", "unknown", f"Could not connect to site: {str(e)[:100]}", "Ensure the site is running.")

    if is_https and hsts_present:
        return _make_check("HTTPS/HSTS", "pass", f"HTTPS enabled. HSTS: {hsts_value[:100]}", "No action needed.")
    elif is_https and not hsts_present:
        return _make_check("HTTPS/HSTS", "warn", "HTTPS enabled but no HSTS header found.", "Add Strict-Transport-Security header with max-age >= 31536000.")
    else:
        return _make_check("HTTPS/HSTS", "warn", f"Site is using HTTP only ({site_url}). Note: only HTTP exists.", "Consider enabling HTTPS with a valid TLS certificate.")


def check_cookie_flags(site_url: str) -> Dict[str, str]:
    """Check Set-Cookie flags: Secure, HttpOnly, SameSite from login response."""
    if not _is_localhost(site_url):
        return _make_check("Cookie Flags", "unknown", "Refusing non-localhost target.", "Only localhost targets are supported.")

    if not _REQUESTS_AVAILABLE:
        return _make_check("Cookie Flags", "unknown", "requests library not available.", "Install requests to enable this check.")

    try:
        login_url = site_url.rstrip("/") + "/login"
        resp = _requests.post(login_url, json={"username": "health_check", "password": "probe"}, timeout=3, verify=False)
        set_cookie = resp.headers.get("Set-Cookie", "")
        cookies = resp.cookies
    except Exception as e:
        return _make_check("Cookie Flags", "unknown", f"Could not reach login endpoint: {str(e)[:100]}", "Ensure the site is running.")

    if not set_cookie:
        return _make_check("Cookie Flags", "unknown", "No Set-Cookie header in login response.", "Login endpoint may not set cookies or requires different credentials.")

    issues = []
    sc_lower = set_cookie.lower()
    if "secure" not in sc_lower:
        issues.append("Secure flag missing")
    if "httponly" not in sc_lower:
        issues.append("HttpOnly flag missing")
    if "samesite" not in sc_lower:
        issues.append("SameSite flag missing")

    if issues:
        return _make_check("Cookie Flags", "fail", f"Cookie issues: {', '.join(issues)}. Raw: {set_cookie[:100]}", "Add Secure, HttpOnly, and SameSite=Strict flags to session cookies.")
    return _make_check("Cookie Flags", "pass", "Secure, HttpOnly, and SameSite flags present.", "No action needed.")


def check_security_headers(site_url: str) -> Dict[str, str]:
    """Check CSP, X-Frame-Options, X-Content-Type-Options headers."""
    if not _is_localhost(site_url):
        return _make_check("Security Headers", "unknown", "Refusing non-localhost target.", "Only localhost targets are supported.")

    if not _REQUESTS_AVAILABLE:
        return _make_check("Security Headers", "unknown", "requests library not available.", "Install requests to enable this check.")

    try:
        resp = _requests.get(site_url, timeout=3, verify=False)
        headers = resp.headers
    except Exception as e:
        return _make_check("Security Headers", "unknown", f"Could not connect: {str(e)[:100]}", "Ensure the site is running.")

    missing = []
    present = []

    csp = headers.get("Content-Security-Policy", "")
    if csp:
        present.append(f"CSP: {csp[:60]}")
    else:
        missing.append("Content-Security-Policy")

    xfo = headers.get("X-Frame-Options", "")
    if xfo:
        present.append(f"X-Frame-Options: {xfo}")
    else:
        missing.append("X-Frame-Options")

    xcto = headers.get("X-Content-Type-Options", "")
    if xcto:
        present.append(f"X-Content-Type-Options: {xcto}")
    else:
        missing.append("X-Content-Type-Options")

    if missing:
        return _make_check("Security Headers", "warn", f"Missing: {', '.join(missing)}. Present: {'; '.join(present)}", f"Add missing headers: {', '.join(missing)}.")
    return _make_check("Security Headers", "pass", f"All required headers present. {'; '.join(present)}", "No action needed.")


def check_mfa_coverage(site_url: str) -> Dict[str, str]:
    """Check MFA coverage from /admin/state mfa_enabled field."""
    if not _is_localhost(site_url):
        return _make_check("MFA Coverage", "unknown", "Refusing non-localhost target.", "Only localhost targets are supported.")

    if not _REQUESTS_AVAILABLE:
        return _make_check("MFA Coverage", "unknown", "requests library not available.", "Install requests to enable this check.")

    try:
        resp = _requests.get(site_url.rstrip("/") + "/admin/state", timeout=3, verify=False)
        data = resp.json()
    except Exception as e:
        return _make_check("MFA Coverage", "unknown", f"Could not reach /admin/state: {str(e)[:100]}", "Ensure /admin/state is available with mfa_enabled per user.")

    users = data.get("users", [])
    if not users:
        return _make_check("MFA Coverage", "unknown", "No users found in /admin/state or mfa_enabled field absent.", "Implement mfa_enabled per user in /admin/state.")

    mfa_on = [u for u in users if u.get("mfa_enabled")]
    mfa_off = [u for u in users if not u.get("mfa_enabled")]
    total = len(users)
    pct = int(100 * len(mfa_on) / total) if total else 0

    if pct == 100:
        return _make_check("MFA Coverage", "pass", f"All {total} users have MFA enabled.", "No action needed.")
    elif pct >= 80:
        return _make_check("MFA Coverage", "warn", f"MFA coverage: {pct}% ({len(mfa_on)}/{total}). Missing for {len(mfa_off)} user(s).", "Enable MFA for all remaining users.")
    else:
        return _make_check("MFA Coverage", "fail", f"MFA coverage: {pct}% ({len(mfa_on)}/{total}). Many users lack MFA.", "Enable MFA for all users immediately.")


def check_exposed_rdp() -> Dict[str, str]:
    """Check if TCP 3389 (RDP) is listening on this machine."""
    if not _PSUTIL_AVAILABLE:
        # Fallback: attempt socket connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(("127.0.0.1", 3389))
            sock.close()
            if result == 0:
                return _make_check("Exposed RDP", "fail", "TCP 3389 is OPEN on 127.0.0.1 (RDP may be exposed).", "Disable RDP if not required, or restrict with firewall rules.")
            return _make_check("Exposed RDP", "pass", "TCP 3389 appears closed on localhost.", "No action needed.")
        except Exception:
            return _make_check("Exposed RDP", "unknown", "psutil not available and socket probe failed.", "Install psutil for accurate RDP check.")

    try:
        listening_on = []
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == "LISTEN" and conn.laddr.port == 3389:
                listening_on.append(str(conn.laddr))

        if listening_on:
            interfaces = ", ".join(listening_on[:5])
            return _make_check("Exposed RDP", "fail", f"RDP (TCP 3389) listening on: {interfaces}", "Disable RDP or restrict access via firewall. RDP should not be exposed externally.")
        return _make_check("Exposed RDP", "pass", "RDP (TCP 3389) not listening.", "No action needed.")
    except Exception as e:
        return _make_check("Exposed RDP", "unknown", f"psutil probe failed: {str(e)[:100]}", "Run with appropriate permissions for network checks.")


def check_backup_health(backup_status_path: str) -> Dict[str, str]:
    """Check backup health from BACKUP_STATUS_PATH JSON file."""
    path = Path(backup_status_path)
    if not path.exists():
        return _make_check("Backup Health", "unknown", f"Backup status file not found: {backup_status_path}", "Create a backup status JSON at BACKUP_STATUS_PATH with last_success, offline_copy, last_restore_test fields.")

    try:
        data: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return _make_check("Backup Health", "unknown", f"Failed to parse backup status file: {str(e)[:100]}", "Fix JSON format in backup status file.")

    issues = []
    info = []

    last_success = data.get("last_success", "")
    offline_copy = data.get("offline_copy", False)
    last_restore_test = data.get("last_restore_test", "")

    if not last_success:
        issues.append("last_success missing or empty")
    else:
        info.append(f"last_success={last_success}")
        # Check if stale (> 48 hours)
        try:
            ts = datetime.fromisoformat(last_success.replace("Z", "+00:00"))
            age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
            if age_h > 48:
                issues.append(f"Last backup is {int(age_h)}h old (> 48h threshold)")
        except Exception:
            issues.append("Could not parse last_success timestamp")

    if not offline_copy:
        issues.append("offline_copy=false (no offline backup)")

    if not last_restore_test:
        issues.append("last_restore_test missing")
    else:
        info.append(f"last_restore_test={last_restore_test}")
        try:
            ts = datetime.fromisoformat(last_restore_test.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - ts).total_seconds() / 86400
            if age_days > 90:
                issues.append(f"Restore test is {int(age_days)} days old (> 90 days)")
        except Exception:
            pass

    evidence = "; ".join(info + issues) if (info or issues) else "No data"
    if issues:
        return _make_check("Backup Health", "fail" if len(issues) >= 2 else "warn", evidence, "Address backup issues: ensure daily backups, offline copy, and quarterly restore tests.")
    return _make_check("Backup Health", "pass", evidence, "No action needed.")


def check_outdated_software(site_url: str, kev_snapshot_path: str) -> Dict[str, str]:
    """Check inventory against CISA KEV snapshot.

    Label: known exploited vulnerabilities list match, not a full scan.
    Snapshot date is included in evidence.
    """
    kev_path = Path(kev_snapshot_path)
    if not kev_path.exists():
        return _make_check("Outdated Software", "unknown", "KEV snapshot not found.", "Provide data/kev_snapshot.json with CISA KEV entries.")

    try:
        kev_data = json.loads(kev_path.read_text(encoding="utf-8"))
        snapshot_date = kev_data.get("snapshot_date", "unknown")
        kev_entries = kev_data.get("entries", [])
    except Exception as e:
        return _make_check("Outdated Software", "unknown", f"Failed to parse KEV snapshot: {str(e)[:100]}", "Fix JSON format in KEV snapshot.")

    inventory = []

    # Try to get inventory from site /admin/inventory
    if _REQUESTS_AVAILABLE and _is_localhost(site_url):
        try:
            resp = _requests.get(site_url.rstrip("/") + "/admin/inventory", timeout=3, verify=False)
            data = resp.json()
            inventory = data.get("components", [])
        except Exception:
            pass

    if not inventory:
        return _make_check("Outdated Software", "unknown", "Could not retrieve /admin/inventory or no components listed.", "Implement GET /admin/inventory returning components with name and version.")

    # Match inventory against KEV entries by product name (case-insensitive substring)
    matches = []
    for component in inventory:
        name = str(component.get("name", "")).lower()
        version = str(component.get("version", ""))
        for entry in kev_entries:
            product = str(entry.get("product", "")).lower()
            if product and product in name:
                cve = entry.get("cve_id", "unknown")
                matches.append(f"{component['name']} v{version} matches KEV entry {cve} ({entry.get('product', '')})")

    evidence = f"Snapshot date: {snapshot_date}. Components checked: {len(inventory)}. "
    note = "Note: known exploited vulnerabilities list match, not a full scan."

    if matches:
        evidence += f"Matches found: {'; '.join(matches[:5])}. {note}"
        return _make_check("Outdated Software", "fail", evidence, "Review and update software matching known exploited vulnerabilities.")

    evidence += f"No KEV matches found. {note}"
    return _make_check("Outdated Software", "pass", evidence, "Continue monitoring for new KEV entries.")

