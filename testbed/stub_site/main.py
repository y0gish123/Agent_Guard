"""Stub victim clinic website implementing docs/SITE_INTEGRATION.md contract.

Runs on port 8002.
Logs to ./site_logs/auth.log, ./site_logs/access.log, ./site_logs/data.log in JSON-Lines format.
Admin API protected by X-Admin-Key.
Demo endpoints enabled when SITE_DEMO=true.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Victim Clinic Portal (Stub Site)", version="1.0.0")

# Log file paths
LOG_DIR = Path(os.getenv("SITE_LOG_DIR", "./site_logs"))
LOG_DIR.mkdir(exist_ok=True, parents=True)
AUTH_LOG_PATH = LOG_DIR / "auth.log"
ACCESS_LOG_PATH = LOG_DIR / "access.log"
DATA_LOG_PATH = LOG_DIR / "data.log"

SITE_ADMIN_KEY = os.getenv("SITE_ADMIN_KEY", "demo-admin-key-supersecret")
SITE_DEMO = os.getenv("SITE_DEMO", "true").lower() == "true"
HOST_ID = os.getenv("HOST_ID", "clinic-web-01")

# In-memory database of accounts & state for the demo
INITIAL_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    "priya.rec": {
        "password_hash": hashlib.sha256("ClinicPass2026!".encode()).hexdigest(),
        "role": "receptionist",
        "locked": False,
        "mfa_enabled": False,
    },
    "front.desk": {
        "password_hash": hashlib.sha256("FrontDesk2026!".encode()).hexdigest(),
        "role": "receptionist",
        "locked": False,
        "mfa_enabled": False,
    },
    "admin": {
        "password_hash": hashlib.sha256("AdminSecure2026!".encode()).hexdigest(),
        "role": "administrator",
        "locked": False,
        "mfa_enabled": True,
    },
    "ceo": {
        "password_hash": hashlib.sha256("Executive2026!".encode()).hexdigest(),
        "role": "executive",
        "locked": False,
        "mfa_enabled": True,
    },
}

ACCOUNTS: Dict[str, Dict[str, Any]] = dict(INITIAL_ACCOUNTS)
ACTIVE_SESSIONS: Dict[str, str] = {}  # session_token -> username
ISOLATED_HOSTS: Set[str] = set()
BLOCKED_IPS: Dict[str, Optional[float]] = {}  # ip -> unblock_timestamp or None (indefinite)

# Component Inventory (Software manifest for vulnerability posture)
COMPONENTS_INVENTORY: List[Dict[str, str]] = [
    {"name": "openssl", "version": "1.1.1t"},
    {"name": "apache_http_server", "version": "2.4.49"},
    {"name": "log4j", "version": "2.14.1"},
    {"name": "python_fastapi", "version": "0.115.0"},
]

# Synthetic patient records for demonstration
PATIENTS: List[Dict[str, Any]] = [
    {"id": f"P-{1000 + i}", "name": f"Patient {i}", "dob": "1980-01-01", "condition": "Routine Checkup"}
    for i in range(1, 101)
]


def _now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_client_ip(request: Request) -> str:
    if SITE_DEMO:
        demo_ip = request.headers.get("X-Demo-Source-IP")
        if demo_ip:
            return demo_ip
    client = request.client
    return client.host if client else "127.0.0.1"


def _append_json_log(path: Path, data: Dict[str, Any]) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as exc:
        print(f"Error writing to {path}: {exc}")


# ---------------------------------------------------------------------------
# Middleware: Log all web requests to access.log
# ---------------------------------------------------------------------------

@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    src_ip = _get_client_ip(request)

    # Check if IP is blocked (unless accessing reset or admin routes with key)
    now_ts = datetime.now(timezone.utc).timestamp()
    if src_ip in BLOCKED_IPS:
        ttl = BLOCKED_IPS[src_ip]
        if ttl is None or now_ts < ttl:
            if not request.url.path.startswith("/admin"):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "IP address is blocked by security gateway policy."},
                )
        else:
            del BLOCKED_IPS[src_ip]

    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    user_agent = request.headers.get("User-Agent")
    auth_header = request.headers.get("Authorization", "")
    session_token = auth_header.replace("Bearer ", "").strip() if auth_header else None
    session_user = ACTIVE_SESSIONS.get(session_token) if session_token else None
    session_id_hash = hashlib.sha256(session_token.encode()).hexdigest()[:16] if session_token else None

    response = await call_next(request)

    # Do not log health/admin requests to avoid noise
    if not request.url.path.startswith("/admin") and not request.url.path.startswith("/docs"):
        access_entry = {
            "ts": _now_utc_str(),
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "status": response.status_code,
            "bytes": int(response.headers.get("content-length", 512)),
            "src_ip": src_ip,
            "username": session_user,
            "host_id": HOST_ID,
            "trace_id": trace_id,
            "user_agent": user_agent[:200] if user_agent else None,
            "session_id_hash": session_id_hash,
        }
        _append_json_log(ACCESS_LOG_PATH, access_entry)

    return response


# ---------------------------------------------------------------------------
# Public Web Routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "site": "Victim Clinic Portal (Stub)",
        "status": "online",
        "host_id": HOST_ID,
        "isolated": HOST_ID in ISOLATED_HOSTS,
    }


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(req: LoginRequest, request: Request):
    src_ip = _get_client_ip(request)

    # 1. Check host isolation mode
    if HOST_ID in ISOLATED_HOSTS:
        _append_json_log(AUTH_LOG_PATH, {
            "ts": _now_utc_str(),
            "event": "access_denied",
            "attempted_username": req.username[:300],
            "username": None,
            "src_ip": src_ip,
            "host_id": HOST_ID,
            "session_id_hash": None,
            "detail": {"reason": "host_isolated"},
        })
        raise HTTPException(status_code=503, detail="Host is in isolation / maintenance mode.")

    account = ACCOUNTS.get(req.username)

    # 2. Check account locked
    if account and account.get("locked"):
        _append_json_log(AUTH_LOG_PATH, {
            "ts": _now_utc_str(),
            "event": "account_locked",
            "attempted_username": req.username[:300],
            "username": req.username,
            "src_ip": src_ip,
            "host_id": HOST_ID,
            "session_id_hash": None,
            "detail": {"reason": "account_locked_by_policy"},
        })
        raise HTTPException(status_code=423, detail="Account is locked by SOC policy.")

    # 3. Check password hash
    p_hash = hashlib.sha256(req.password.encode()).hexdigest()
    if not account or account.get("password_hash") != p_hash:
        _append_json_log(AUTH_LOG_PATH, {
            "ts": _now_utc_str(),
            "event": "login_failed",
            "attempted_username": req.username[:300],
            "username": None,
            "src_ip": src_ip,
            "host_id": HOST_ID,
            "session_id_hash": None,
            "detail": {"reason": "bad_credentials"},
        })
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    # Successful login
    token = f"sess-{hashlib.sha256((req.username + _now_utc_str()).encode()).hexdigest()[:16]}"
    ACTIVE_SESSIONS[token] = req.username
    sess_hash = hashlib.sha256(token.encode()).hexdigest()[:16]

    _append_json_log(AUTH_LOG_PATH, {
        "ts": _now_utc_str(),
        "event": "login_success",
        "attempted_username": req.username[:300],
        "username": req.username,
        "src_ip": src_ip,
        "host_id": HOST_ID,
        "session_id_hash": sess_hash,
        "detail": {"role": account.get("role")},
    })

    return {"ok": True, "token": token, "username": req.username, "role": account.get("role")}


@app.get("/records/{record_id}")
def view_record(record_id: str, request: Request):
    src_ip = _get_client_ip(request)
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    username = ACTIVE_SESSIONS.get(token, "anonymous")

    # Log to data.log
    _append_json_log(DATA_LOG_PATH, {
        "ts": _now_utc_str(),
        "username": username,
        "action": "view_record",
        "record_count": 1,
        "bytes": 250,
        "src_ip": src_ip,
        "host_id": HOST_ID,
    })

    return {"record_id": record_id, "data": "Patient details..."}


class ExportRequest(BaseModel):
    record_count: int = 100


@app.post("/export")
def export_records(req: ExportRequest, request: Request):
    src_ip = _get_client_ip(request)
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    username = ACTIVE_SESSIONS.get(token, "anonymous")

    _append_json_log(DATA_LOG_PATH, {
        "ts": _now_utc_str(),
        "username": username,
        "action": "export",
        "record_count": req.record_count,
        "bytes": req.record_count * 500,
        "src_ip": src_ip,
        "host_id": HOST_ID,
    })

    return {"ok": True, "exported_count": req.record_count}


# ---------------------------------------------------------------------------
# Demo Simulation Endpoints (only active when SITE_DEMO=true)
# ---------------------------------------------------------------------------

class EscalateRequest(BaseModel):
    username: str = "priya.rec"


@app.post("/demo/escalate")
def demo_escalate(req: EscalateRequest, request: Request):
    if not SITE_DEMO:
        raise HTTPException(status_code=403, detail="Demo endpoints disabled.")

    src_ip = _get_client_ip(request)
    account = ACCOUNTS.get(req.username)
    if account:
        account["role"] = "administrator"

    _append_json_log(AUTH_LOG_PATH, {
        "ts": _now_utc_str(),
        "event": "role_changed",
        "attempted_username": req.username[:300],
        "username": req.username,
        "src_ip": src_ip,
        "host_id": HOST_ID,
        "session_id_hash": None,
        "detail": {"new_role": "administrator", "granted_by": "SYSTEM"},
    })

    return {"ok": True, "username": req.username, "new_role": "administrator"}


# ---------------------------------------------------------------------------
# Protected Admin API (Port 8002, Header X-Admin-Key)
# ---------------------------------------------------------------------------

def _verify_admin_key(x_admin_key: Optional[str] = Header(None)) -> None:
    if not x_admin_key or x_admin_key != SITE_ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid X-Admin-Key.")


class TargetUserRequest(BaseModel):
    username: str


class TargetHostRequest(BaseModel):
    host_id: str


class BlockIpRequest(BaseModel):
    ip: str
    ttl_seconds: Optional[int] = None


class UnblockIpRequest(BaseModel):
    ip: str


@app.post("/admin/block-ip")
def admin_block_ip(req: BlockIpRequest, x_admin_key: Optional[str] = Header(None)):
    _verify_admin_key(x_admin_key)
    now_ts = datetime.now(timezone.utc).timestamp()
    expire_at = (now_ts + req.ttl_seconds) if req.ttl_seconds else None
    BLOCKED_IPS[req.ip] = expire_at
    return {"ok": True, "action": "block_ip", "ip": req.ip, "ttl_seconds": req.ttl_seconds}


@app.post("/admin/unblock-ip")
def admin_unblock_ip(req: UnblockIpRequest, x_admin_key: Optional[str] = Header(None)):
    _verify_admin_key(x_admin_key)
    if req.ip in BLOCKED_IPS:
        del BLOCKED_IPS[req.ip]
    return {"ok": True, "action": "unblock_ip", "ip": req.ip}


@app.get("/admin/inventory")
def admin_inventory(x_admin_key: Optional[str] = Header(None)):
    _verify_admin_key(x_admin_key)
    return {"components": COMPONENTS_INVENTORY, "host_id": HOST_ID}


@app.post("/admin/lock")
def admin_lock(req: TargetUserRequest, x_admin_key: Optional[str] = Header(None)):
    _verify_admin_key(x_admin_key)
    if req.username in ACCOUNTS:
        ACCOUNTS[req.username]["locked"] = True
    else:
        ACCOUNTS[req.username] = {"locked": True, "role": "unknown"}

    _append_json_log(AUTH_LOG_PATH, {
        "ts": _now_utc_str(),
        "event": "account_locked",
        "attempted_username": req.username,
        "username": req.username,
        "src_ip": "127.0.0.1",
        "host_id": HOST_ID,
        "session_id_hash": None,
        "detail": {"locked_by": "AgentGuard_SOC_Gateway"},
    })
    return {"ok": True, "action": "lock", "target": req.username, "status": "locked"}


@app.post("/admin/unlock")
def admin_unlock(req: TargetUserRequest, x_admin_key: Optional[str] = Header(None)):
    _verify_admin_key(x_admin_key)
    if req.username in ACCOUNTS:
        ACCOUNTS[req.username]["locked"] = False
    return {"ok": True, "action": "unlock", "target": req.username, "status": "active"}


@app.post("/admin/revoke-sessions")
def admin_revoke_sessions(req: TargetUserRequest, x_admin_key: Optional[str] = Header(None)):
    _verify_admin_key(x_admin_key)
    revoked_count = 0
    tokens_to_del = [t for t, u in ACTIVE_SESSIONS.items() if u == req.username]
    for t in tokens_to_del:
        del ACTIVE_SESSIONS[t]
        revoked_count += 1

    _append_json_log(AUTH_LOG_PATH, {
        "ts": _now_utc_str(),
        "event": "sessions_revoked",
        "attempted_username": req.username,
        "username": req.username,
        "src_ip": "127.0.0.1",
        "host_id": HOST_ID,
        "session_id_hash": None,
        "detail": {"revoked_sessions": revoked_count},
    })
    return {"ok": True, "action": "revoke_session", "target": req.username, "revoked_count": revoked_count}


@app.post("/admin/isolate")
def admin_isolate(req: TargetHostRequest, x_admin_key: Optional[str] = Header(None)):
    _verify_admin_key(x_admin_key)
    ISOLATED_HOSTS.add(req.host_id)
    return {"ok": True, "action": "isolate_host", "target": req.host_id, "status": "isolated"}


@app.post("/admin/unisolate")
def admin_unisolate(req: TargetHostRequest, x_admin_key: Optional[str] = Header(None)):
    _verify_admin_key(x_admin_key)
    ISOLATED_HOSTS.discard(req.host_id)
    return {"ok": True, "action": "unisolate_host", "target": req.host_id, "status": "active"}


@app.get("/admin/state")
def admin_state():
    return {
        "host_id": HOST_ID,
        "accounts": ACCOUNTS,
        "active_sessions_count": len(ACTIVE_SESSIONS),
        "isolated_hosts": sorted(list(ISOLATED_HOSTS)),
        "blocked_ips": sorted(list(BLOCKED_IPS.keys())),
    }


@app.post("/admin/reset")
def admin_reset():
    global ACCOUNTS, ACTIVE_SESSIONS, ISOLATED_HOSTS
    ACCOUNTS = {
        "priya.rec": {
            "password_hash": hashlib.sha256("ClinicPass2026!".encode()).hexdigest(),
            "role": "receptionist",
            "locked": False,
            "mfa_enabled": False,
        },
        "front.desk": {
            "password_hash": hashlib.sha256("FrontDesk2026!".encode()).hexdigest(),
            "role": "receptionist",
            "locked": False,
            "mfa_enabled": False,
        },
        "admin": {
            "password_hash": hashlib.sha256("AdminSecure2026!".encode()).hexdigest(),
            "role": "administrator",
            "locked": False,
            "mfa_enabled": True,
        },
        "ceo": {
            "password_hash": hashlib.sha256("Executive2026!".encode()).hexdigest(),
            "role": "executive",
            "locked": False,
            "mfa_enabled": True,
        },
    }
    ACTIVE_SESSIONS.clear()
    ISOLATED_HOSTS.clear()
    BLOCKED_IPS.clear()
    return {"ok": True, "status": "reset"}
