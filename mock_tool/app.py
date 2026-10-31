"""FastAPI application for the protected mock response tool."""

from contextlib import asynccontextmanager
import os
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, status
import httpx
from pydantic import BaseModel

from mock_tool.state import MockStateManager
from mock_tool.verifier import TokenVerifier
from shared.contracts import ReasonCode


class ExecuteRequest(BaseModel):
    token: Optional[str] = None
    incident_id: str
    action_type: str
    target_id: str


class DemoApplyRequest(BaseModel):
    action_type: str
    target_id: str
    incident_id: Optional[str] = None


state_manager = MockStateManager()
_verifier: Optional[TokenVerifier] = None


def get_verifier() -> TokenVerifier:
    global _verifier
    if _verifier is None:
        secret = os.getenv("HMAC_SECRET", "")
        if not secret:
            raise RuntimeError("HMAC_SECRET is required for mock tool.")
        _verifier = TokenVerifier(secret=secret)
    return _verifier


def _execute_portal_action(action_type: str, target_id: str) -> Optional[Dict[str, Any]]:
    """Execute action on live victim site Admin API (port 8002).

    Returns result dict, or raises httpx.RequestError if unreachable.
    """
    site_url = os.getenv("SITE_URL", "http://localhost:8002").rstrip("/")
    admin_key = os.getenv("SITE_ADMIN_KEY", "demo-admin-key-supersecret")
    headers = {"X-Admin-Key": admin_key}

    if action_type == "lock_account":
        endpoint = f"{site_url}/admin/lock"
        payload = {"username": target_id}
    elif action_type == "revoke_session":
        endpoint = f"{site_url}/admin/revoke-sessions"
        payload = {"username": target_id}
    elif action_type == "isolate_host":
        endpoint = f"{site_url}/admin/isolate"
        payload = {"host_id": target_id}
    elif action_type == "block_ip":
        endpoint = f"{site_url}/admin/block-ip"
        payload = {"ip": target_id}
    else:
        return None

    with httpx.Client(timeout=4.0) as client:
        resp = client.post(endpoint, json=payload, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        return None


def _get_portal_state() -> Optional[Dict[str, Any]]:
    site_url = os.getenv("SITE_URL", "http://localhost:8002").rstrip("/")
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{site_url}/admin/state")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    sim = os.getenv("SIMULATION", "").lower()
    if sim != "true":
        raise RuntimeError("Refusing to start mock tool: SIMULATION must be true.")
    get_verifier()
    yield


def create_mock_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard Mock Tool",
        description="Protected mock response tool with cryptographic verification gateway",
        version="1.0.0",
        lifespan=lifespan,
    )

    @app.get("/tool/state")
    def get_state() -> Dict[str, Any]:
        backend_mode = os.getenv("TOOL_BACKEND", "mock").lower()
        state = dict(state_manager.get_state())
        state["backend"] = backend_mode
        if backend_mode == "portal":
            site_state = _get_portal_state()
            state["site_state"] = site_state
        return state

    @app.post("/tool/reset")
    def reset_tool() -> Dict[str, Any]:
        sim = os.getenv("SIMULATION", "").lower()
        if sim != "true":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Reset only allowed when SIMULATION=true",
            )
        verifier = get_verifier()
        verifier.reset_nonces()
        restored_state = state_manager.reset()

        # If portal backend, also reset site
        if os.getenv("TOOL_BACKEND", "mock").lower() == "portal":
            site_url = os.getenv("SITE_URL", "http://localhost:8002").rstrip("/")
            try:
                with httpx.Client(timeout=2.0) as client:
                    client.post(f"{site_url}/admin/reset")
            except Exception:
                pass

        return {"ok": True, "state": restored_state}

    @app.post("/tool/execute")
    def execute_action(req: ExecuteRequest) -> Dict[str, Any]:
        verifier = get_verifier()
        ok, reason_code, _ = verifier.verify_and_claim(
            token=req.token,
            incident_id=req.incident_id,
            action_type=req.action_type,
            target_id=req.target_id,
        )

        if not ok:
            return {"ok": False, "reason_code": reason_code.value}

        backend_mode = os.getenv("TOOL_BACKEND", "mock").lower()

        # In portal mode, call victim site admin API
        if backend_mode == "portal":
            try:
                portal_res = _execute_portal_action(req.action_type, req.target_id)
            except (httpx.RequestError, httpx.HTTPError) as exc:
                return {
                    "ok": False,
                    "reason_code": ReasonCode.TOOL_UNAVAILABLE.value,
                    "error": f"Victim site unreachable: {exc}",
                }

        # Apply state changes strictly within simulation shadow state
        try:
            result = state_manager.apply_action(req.action_type, req.target_id)
            return {
                "ok": True,
                "reason_code": ReasonCode.EXECUTED_OK.value,
                "result": result,
                "backend": backend_mode,
            }
        except ValueError as exc:
            return {"ok": False, "reason_code": "INVALID_ACTION", "error": str(exc)}

    # POST /tool/demo-apply exists ONLY if DEMO_MODE=naive
    @app.post("/tool/demo-apply")
    def demo_apply(req: DemoApplyRequest) -> Dict[str, Any]:
        if os.getenv("DEMO_MODE", "guarded").lower() != "naive":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Endpoint not found in guarded mode",
            )

        backend_mode = os.getenv("TOOL_BACKEND", "mock").lower()
        if backend_mode == "portal":
            try:
                _execute_portal_action(req.action_type, req.target_id)
            except Exception:
                pass

        try:
            result = state_manager.apply_action(req.action_type, req.target_id)
            return {"ok": True, "result": result, "mode": "naive_unprotected", "backend": backend_mode}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    return app


app = create_mock_app()
