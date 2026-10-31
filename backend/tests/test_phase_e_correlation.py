"""Tests for Phase E: Trace ID correlation."""

import pytest
from datetime import datetime, timezone, timedelta
from detection.correlation import group_by_trace, group_by_user_window, correlation_basis
from shared.contracts import Event, EventType, Severity, Source


def _make_event(eid, etype=EventType.web_request, user="alice", trace_id=None, request_id=None,
                session_id_hash=None, ts_offset=0):
    return Event(
        event_id=f"evt-{eid}",
        timestamp=datetime.now(timezone.utc) + timedelta(seconds=ts_offset),
        source=Source.simulator,
        host_id="test-host",
        user_id=user,
        event_type=etype,
        severity=Severity.low,
        raw_event_ref=f"test:{eid}",
        attributes={},
        trace_id=trace_id,
        request_id=request_id,
        session_id_hash=session_id_hash,
        schema_version="1.0",
    )


class TestTraceCorrelation:
    def test_group_by_trace_links_same_trace(self):
        e1 = _make_event("evt-e1", trace_id="trace-xyz")
        e2 = _make_event("evt-e2", trace_id="trace-xyz", ts_offset=1)
        e3 = _make_event("evt-e3", trace_id="trace-abc")
        groups = group_by_trace([e1, e2, e3])
        assert "trace-xyz" in groups
        assert len(groups["trace-xyz"]) == 2
        assert "trace-abc" not in groups  # only 1 event, not linked

    def test_group_by_trace_uses_request_id_fallback(self):
        e1 = _make_event("evt-e1", request_id="req-001")
        e2 = _make_event("evt-e2", request_id="req-001", ts_offset=1)
        groups = group_by_trace([e1, e2])
        assert "req-001" in groups

    def test_group_by_trace_no_trace_returns_empty(self):
        e1 = _make_event("evt-e1")
        e2 = _make_event("evt-e2", ts_offset=5)
        groups = group_by_trace([e1, e2])
        assert len(groups) == 0

    def test_group_by_user_window_same_user_within_window(self):
        e1 = _make_event("evt-e1", user="alice", ts_offset=0)
        e2 = _make_event("evt-e2", user="alice", ts_offset=100)
        e3 = _make_event("evt-e3", user="alice", ts_offset=200)
        groups = group_by_user_window([e1, e2, e3], window_seconds=1800)
        assert "user:alice" in groups
        assert len(groups["user:alice"]) == 3

    def test_correlation_basis_trace_id_wins(self):
        e1 = _make_event("evt-e1", trace_id="trace-123", user="alice")
        e2 = _make_event("evt-e2", trace_id="trace-123", user="alice")
        basis = correlation_basis([e1, e2])
        assert "trace_id" in basis.lower()
        assert "trace-123" in basis

    def test_correlation_basis_session_id_hash(self):
        e1 = _make_event("evt-e1", session_id_hash="sess-abc", user="bob")
        e2 = _make_event("evt-e2", session_id_hash="sess-abc", user="bob")
        basis = correlation_basis([e1, e2])
        assert "session" in basis.lower() or "sess-abc" in basis

    def test_correlation_basis_user_fallback(self):
        e1 = _make_event("evt-e1", user="carol", ts_offset=0)
        e2 = _make_event("evt-e2", user="carol", ts_offset=60)
        basis = correlation_basis([e1, e2])
        assert "carol" in basis or "user" in basis.lower()

    def test_correlation_basis_empty(self):
        basis = correlation_basis([])
        assert basis  # always returns a string
