"""Funnel metrics and metadata endpoints."""

import os
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.db.session import get_db
from backend.incidents.service import IncidentService
from shared.contracts import FunnelCounts, Meta

router = APIRouter(tags=["meta"])


@router.get("/api/funnel")
def get_funnel(db: Session = Depends(get_db)) -> FunnelCounts:
    service = IncidentService(db)
    raw_events, alerts, incidents = service.get_funnel_counts()
    return FunnelCounts(
        raw_events=raw_events,
        alerts=alerts,
        incidents=incidents,
    )


@router.get("/api/meta")
def get_meta() -> Meta:
    settings = get_settings()

    ai_available = False
    try:
        import backend.ai.adapter  # type: ignore

        has_key = bool(settings.LLM_API_KEY and settings.LLM_API_KEY.strip())
        has_cache = os.path.isdir("cache") or os.path.isdir(".cache") or os.path.isdir("backend/ai/cache")
        ai_available = has_key or has_cache
    except Exception:
        ai_available = False

    return Meta(
        demo_mode=settings.DEMO_MODE,
        simulation=True,
        schema_version="1.0",
        ai_available=ai_available,
    )

