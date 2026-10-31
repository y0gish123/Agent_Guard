"""Token verification and nonce replay tracking for mock tool."""

import base64
import hashlib
import hmac
import json
import sqlite3
import time
from typing import Any, Callable, Dict, Optional, Tuple

from shared.contracts import ReasonCode


def base64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


class TokenVerifier:
    def __init__(
        self,
        secret: str,
        db_path: str = "mock_tool.db",
        clock: Optional[Callable[[], float]] = None,
    ):
        self.secret = secret
        self.db_path = db_path
        self.clock = clock or time.time
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce TEXT PRIMARY KEY,
                    tid TEXT,
                    used_at REAL
                )
                """
            )
            conn.commit()

    def reset_nonces(self):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM used_nonces")
            conn.commit()

    def verify_and_claim(
        self,
        token: Optional[str],
        incident_id: str,
        action_type: str,
        target_id: str,
    ) -> Tuple[bool, ReasonCode, Dict[str, Any]]:
        """Verify token according to strict order:
        1. Token present (TOKEN_MISSING)
        2. Signature valid and iss/aud correct (TOKEN_BAD_SIGNATURE)
        3. nbf/exp valid (TOKEN_EXPIRED)
        4. Claims equal body fields exactly (TOKEN_SCOPE_MISMATCH)
        5. Claim nonce with INSERT on UNIQUE column (TOKEN_REPLAYED)
        """
        # 1. Token present
        if not token or not token.strip():
            return False, ReasonCode.TOKEN_MISSING, {}

        # 2. Signature valid and iss/aud correct
        parts = token.strip().split(".")
        if len(parts) != 2:
            return False, ReasonCode.TOKEN_BAD_SIGNATURE, {}

        part1, part2 = parts[0], parts[1]
        try:
            expected_sig = hmac.new(
                self.secret.encode("utf-8"),
                part1.encode("utf-8"),
                hashlib.sha256,
            ).digest()
            expected_part2 = base64url_encode(expected_sig)
            if not hmac.compare_digest(part2, expected_part2):
                return False, ReasonCode.TOKEN_BAD_SIGNATURE, {}

            claims_raw = base64url_decode(part1).decode("utf-8")
            claims = json.loads(claims_raw)
        except Exception:
            return False, ReasonCode.TOKEN_BAD_SIGNATURE, {}

        if claims.get("iss") != "agentguard-gateway" or claims.get("aud") != "mock-tool":
            return False, ReasonCode.TOKEN_BAD_SIGNATURE, {}

        # 3. nbf/exp valid
        now = self.clock()
        nbf = claims.get("nbf", 0)
        exp = claims.get("exp", 0)
        if now < nbf or now > exp:
            return False, ReasonCode.TOKEN_EXPIRED, claims

        # 4. Claims equal body fields exactly
        if (
            claims.get("incident_id") != incident_id
            or claims.get("action_type") != action_type
            or claims.get("target_id") != target_id
        ):
            return False, ReasonCode.TOKEN_SCOPE_MISMATCH, claims

        # 5. Claim nonce with INSERT on UNIQUE column
        nonce = claims.get("nonce")
        tid = claims.get("tid", "")
        if not nonce:
            return False, ReasonCode.TOKEN_BAD_SIGNATURE, claims

        try:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO used_nonces (nonce, tid, used_at) VALUES (?, ?, ?)",
                    (nonce, tid, now),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            return False, ReasonCode.TOKEN_REPLAYED, claims
        except Exception:
            return False, ReasonCode.TOKEN_BAD_SIGNATURE, claims

        return True, ReasonCode.EXECUTED_OK, claims

