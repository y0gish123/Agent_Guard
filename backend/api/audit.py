"""Audit query and cryptographic verification endpoints."""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.audit.service import AuditService
from backend.db.session import get_db

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    audit_service = AuditService(db)
    return audit_service.list_events(limit=limit, offset=offset)


@router.get("/verify")
@router.post("/verify")
def verify_audit_chain(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    audit_service = AuditService(db)
    return audit_service.verify_chain()

