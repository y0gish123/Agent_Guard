"""Trace ID and request ID correlation helpers for AgentGuard detection.

Links events by:
1. Same trace_id / request_id (strongest – within the same HTTP request)
2. Same user/session within 30 minutes (weaker – correlated by time)

The linking basis is reported in the incident detection_reason.
"""

from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from shared.contracts import Event


def _utc(dt):
    from datetime import timezone
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def group_by_trace(events: List[Event]) -> Dict[str, List[Event]]:
    """Group events that share a trace_id or request_id. Returns dict keyed by trace/request id."""
    groups: Dict[str, List[Event]] = {}
    for ev in events:
        key = ev.trace_id or ev.request_id
        if key:
            groups.setdefault(key, []).append(ev)
    return {k: v for k, v in groups.items() if len(v) >= 2}


def group_by_user_window(events: List[Event], window_seconds: int = 1800) -> Dict[str, List[Event]]:
    """Group events by user_id within rolling time window."""
    by_user: Dict[str, List[Event]] = {}
    for ev in events:
        if ev.user_id:
            by_user.setdefault(ev.user_id, []).append(ev)

    result: Dict[str, List[Event]] = {}
    for user_id, user_events in by_user.items():
        sorted_evs = sorted(user_events, key=lambda e: _utc(e.timestamp))
        # Build windows
        windows: List[List[Event]] = []
        current: List[Event] = [sorted_evs[0]]
        for i in range(1, len(sorted_evs)):
            t_start = _utc(sorted_evs[current[0].__class__ and 0 or 0].timestamp if False else current[0].timestamp)
            t_curr = _utc(sorted_evs[i].timestamp)
            if (t_curr - t_start).total_seconds() <= window_seconds:
                current.append(sorted_evs[i])
            else:
                if len(current) >= 2:
                    windows.append(current)
                current = [sorted_evs[i]]
        if len(current) >= 2:
            windows.append(current)

        if windows:
            # Return the largest window for the user
            best = max(windows, key=len)
            result[f"user:{user_id}"] = best

    return result


def correlation_basis(events: List[Event]) -> str:
    """Return human-readable basis of correlation for a list of events.

    Used in detection_reason field of Incident.
    """
    if not events:
        return "no linking basis"

    trace_ids = {ev.trace_id for ev in events if ev.trace_id}
    request_ids = {ev.request_id for ev in events if ev.request_id}
    user_ids = {ev.user_id for ev in events if ev.user_id}
    session_hashes = {ev.session_id_hash for ev in events if ev.session_id_hash}

    parts = []
    if trace_ids:
        parts.append(f"Linked by trace_id ({', '.join(sorted(trace_ids)[:2])})")
    elif request_ids:
        parts.append(f"Linked by request_id ({', '.join(sorted(request_ids)[:2])})")
    elif session_hashes:
        parts.append(f"Linked by session_id_hash ({', '.join(sorted(str(s) for s in session_hashes)[:2])})")
    elif user_ids:
        parts.append(f"Linked by same user within 30 min ({', '.join(sorted(u for u in user_ids if u)[:2])})")

    return "; ".join(parts) if parts else "Linked by temporal proximity"

