"""Server-Sent Events (SSE) endpoint for AgentGuard live updates.

Publishes lightweight notification events to connected browser clients.
Events carry only IDs and types — never raw event text or incident titles,
so XSS risk is minimal. The frontend re-fetches full data via REST.

Event types:
  - incident_created  {incident_id, category, severity}
  - incident_updated  {incident_id, severity}
  - response_updated  {incident_id, response_id, status}
  - audit_appended    {incident_id}
  - heartbeat         {} (every 15 s to keep connections alive)

Usage:
  from backend.api.stream import publish_event, router
  publish_event("incident_created", {"incident_id": "inc-12345678", ...})
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["stream"])

# In-process queue per connected client
_CLIENTS: List[asyncio.Queue] = []
_HEARTBEAT_INTERVAL = 15  # seconds


def publish_event(event_type: str, data: Dict[str, Any]) -> None:
    """Publish a live update to all connected SSE clients.

    Safe to call from sync code (non-async). Skips disconnected clients.
    """
    payload = {
        "type": event_type,
        "ts": int(time.time()),
        **data,
    }
    dead: List[asyncio.Queue] = []
    for q in list(_CLIENTS):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        try:
            _CLIENTS.remove(q)
        except ValueError:
            pass


async def _event_generator(queue: asyncio.Queue):
    """Async generator: yields SSE-formatted strings for one client."""
    last_heartbeat = time.monotonic()
    try:
        while True:
            now = time.monotonic()
            timeout = max(0.1, _HEARTBEAT_INTERVAL - (now - last_heartbeat))
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=timeout)
                eid = uuid.uuid4().hex[:8]
                yield f"id: {eid}\nevent: {payload['type']}\ndata: {json.dumps(payload)}\n\n"
            except asyncio.TimeoutError:
                # Send heartbeat comment to keep connection alive
                yield f": heartbeat {int(time.time())}\n\n"
                last_heartbeat = time.monotonic()
    except asyncio.CancelledError:
        pass
    finally:
        try:
            _CLIENTS.remove(queue)
        except ValueError:
            pass


@router.get("/stream")
async def stream_events():
    """SSE endpoint. Connect with EventSource('/api/stream') in the browser.

    Returns live update events. Falls back to 5s polling if EventSource is
    unavailable (see frontend useLiveUpdates hook).
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    _CLIENTS.append(queue)
    logger.debug("SSE client connected; total=%d", len(_CLIENTS))

    return StreamingResponse(
        _event_generator(queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

