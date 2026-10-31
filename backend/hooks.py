"""Integration hooks for pipeline extension and auto-explanation."""

import logging
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.db.session import get_session_factory
from backend.incidents.service import IncidentService
from shared.contracts import Event, Explanation, Incident

logger = logging.getLogger(__name__)


def _trigger_auto_explain(candidates: List[Incident], events: List[Event]) -> List[Explanation]:
    """Trigger background explanation caching for newly created/escalated candidates.

    Returns a list of Explanation objects (one per candidate). Fallbacks are returned
    when LLM_PROVIDER=none or on any error; fallbacks are NOT cached so that a future
    real LLM call can write the cache.
    """
    results: List[Explanation] = []
    try:
        from backend.ai import adapter  # type: ignore

        if hasattr(adapter, "explain"):
            for cand in candidates:
                # Find matching evidence events
                evidence_set = set(cand.evidence_event_ids)
                matching = [e for e in events if e.event_id in evidence_set]
                expl = adapter.explain(cand, matching, lang="en", mode="guarded")
                results.append(expl)
    except Exception as exc:
        logger.debug("Auto-explain skipped: %s", exc)
    return results


def on_new_events(events: List[Event], db: Optional[Session] = None) -> None:
    """Invoked when new events are ingested.
    If module detection.pipeline is importable and has process_events(events) -> list[Incident],
    upsert them like the candidates route; otherwise do nothing.
    Wrap in try/except so ingest never fails because of it.
    """
    try:
        import detection.pipeline  # type: ignore
        candidates = []
        if hasattr(detection.pipeline, "process_events"):
            candidates.extend(detection.pipeline.process_events(events) or [])

        # Integrate RiskEngine detectors (Session Hijack, Password Spray, Mass Deletion)
        try:
            from detection.risk import RiskEngine
            risk_engine = RiskEngine()
            risk_candidates = risk_engine.evaluate_signals(events)
            if risk_candidates:
                candidates.extend(risk_candidates)
        except Exception as r_exc:
            logger.debug("Risk engine evaluation skipped: %s", r_exc)

        if candidates and isinstance(candidates, list):
                if db is not None:
                    service = IncidentService(db)
                    service.upsert_candidates(candidates)
                else:
                    factory = get_session_factory()
                    with factory() as session:
                        service = IncidentService(session)
                        service.upsert_candidates(candidates)

                # Auto-explain newly created/escalated candidates (results logged but not awaited)
                _trigger_auto_explain(candidates, events)
                try:
                    from backend.api.stream import publish_event
                    for c in candidates:
                        publish_event("incident_created", {
                            "incident_id": c.incident_id,
                            "category": c.category.value if hasattr(c.category, "value") else str(c.category),
                            "severity": c.severity.value if hasattr(c.severity, "value") else str(c.severity),
                        })
                except Exception:
                    pass
    except Exception as exc:
        # Gracefully degrade and do not disrupt ingestion
        logger.debug("on_new_events hook execution skipped or failed: %s", exc)
