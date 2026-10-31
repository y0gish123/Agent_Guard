"""Token issuer for cryptographically verified policy authorization."""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Callable, Dict, Optional, Tuple
from shared.contracts import ActionType

_seq = 0


def _get_next_tid() -> str:
    global _seq
    _seq += 1
    return f"tok-{_seq:04d}"


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


class TokenIssuer:
    def __init__(
        self,
        secret: str,
        ttl_seconds: int = 60,
        clock: Optional[Callable[[], float]] = None,
    ):
        if not secret:
            raise ValueError("HMAC secret cannot be empty")
        self.secret = secret
        self.ttl_seconds = ttl_seconds
        self.clock = clock or time.time

    def issue_token(
        self,
        incident_id: str,
        action_type: ActionType | str,
        target_id: str,
        tid: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Issue a tamper-proof authorization token bound to an exact incident, action, and target."""
        now = int(self.clock())
        token_tid = tid or _get_next_tid()
        nonce = secrets.token_hex(16)
        action_val = action_type.value if isinstance(action_type, ActionType) else str(action_type)

        claims = {
            "iss": "agentguard-gateway",
            "aud": "mock-tool",
            "tid": token_tid,
            "nonce": nonce,
            "incident_id": incident_id,
            "action_type": action_val,
            "target_id": target_id,
            "iat": now,
            "nbf": now,
            "exp": now + self.ttl_seconds,
        }

        claims_json = canonical_json(claims)
        part1 = base64url_encode(claims_json.encode("utf-8"))

        sig = hmac.new(
            self.secret.encode("utf-8"),
            part1.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        part2 = base64url_encode(sig)

        token = f"{part1}.{part2}"
        return token, claims
