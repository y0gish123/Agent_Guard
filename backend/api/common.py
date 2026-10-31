"""Common API helpers and error responses."""

import uuid
from typing import Optional
from fastapi import HTTPException
from backend.policy.messages import get_plain_reason
from shared.contracts import ErrorBody, ReasonCode


def make_error_response(
    status_code: int,
    code: ReasonCode | str,
    message: Optional[str] = None,
    detail_id: Optional[str] = None,
) -> HTTPException:
    code_str = code.value if isinstance(code, ReasonCode) else str(code)
    plain_msg = message or get_plain_reason(code_str)
    err_id = detail_id or f"err-{uuid.uuid4().hex[:8]}"
    return HTTPException(
        status_code=status_code,
        detail={
            "code": code_str,
            "plain_message": plain_msg,
            "detail_id": err_id,
        },
    )

