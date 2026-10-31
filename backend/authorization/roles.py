"""Role-based access control and identity parsing from headers."""

from typing import Tuple
from fastapi import Header, HTTPException, Request, status
from shared.contracts import ReasonCode, Role


def parse_identity(
    x_user: str = Header(default="anonymous", alias="X-User"),
    x_role: str = Header(default="staff", alias="X-Role"),
) -> Tuple[str, Role]:
    """Extract identity and role from headers with defaults."""
    clean_role_str = (x_role or "staff").strip().lower()
    try:
        role = Role(clean_role_str)
    except ValueError:
        role = Role.staff
    user = (x_user or "anonymous").strip()
    return user, role

