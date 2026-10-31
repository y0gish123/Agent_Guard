"""Tests for Phase D: WAF/ModSecurity adapter and block_ip end-to-end."""

import pytest
from collector.mappers.modsecurity import map_modsecurity_line, waf_outcome_label
from shared.contracts import EventType, Severity


def _waf_line(action="blocked", rule_id="941100", client_ip="203.0.113.42",
              uri="/admin/login", unique_id="uid-001", status=403):
    import json
    return json.dumps({
        "unique_id": unique_id,
        "timestamp": "2026-10-31T08:00:00Z",
        "client_ip": client_ip,
        "uri": uri,
        "method": "POST",
        "status": status,
        "action": action,
        "rule_id": rule_id,
        "rule_message": "Test Rule",
        "bytes": 512,
        "host_id": "clinic-web-01",
        "user_agent": "Mozilla/5.0",
    })


class TestModSecurityMapper:
    def test_blocked_request_maps_to_web_request(self):
        ev = map_modsecurity_line(_waf_line(action="blocked"), "test.jsonl", 1)
        assert ev is not None
        assert ev.event_type == EventType.web_request
        assert ev.attributes["waf_action"] == "blocked"
        assert ev.attributes["rule_id"] == "941100"
        assert ev.severity == Severity.high

    def test_allowed_request_maps_with_medium_severity(self):
        ev = map_modsecurity_line(_waf_line(action="allowed", status=200), "test.jsonl", 1)
        assert ev is not None
        assert ev.attributes["waf_action"] == "allowed"
        assert ev.severity == Severity.medium

    def test_unique_id_becomes_trace_and_request_id(self):
        ev = map_modsecurity_line(_waf_line(unique_id="trace-abc"), "test.jsonl", 1)
        assert ev.trace_id == "trace-abc"
        assert ev.request_id == "trace-abc"
        assert ev.source_event_id == "trace-abc"

    def test_empty_line_returns_none(self):
        assert map_modsecurity_line("", "test.jsonl", 1) is None
        assert map_modsecurity_line("   ", "test.jsonl", 1) is None

    def test_invalid_json_returns_none(self):
        assert map_modsecurity_line("not json {{{{", "test.jsonl", 1) is None

    def test_rule_id_bounded_to_32_chars(self):
        long_rule_id = "X" * 100
        ev = map_modsecurity_line(_waf_line(rule_id=long_rule_id), "test.jsonl", 1)
        assert ev is not None
        assert len(ev.attributes.get("rule_id", "")) <= 32

    def test_waf_outcome_label_blocked(self):
        ev = map_modsecurity_line(_waf_line(action="blocked"), "test.jsonl", 1)
        label = waf_outcome_label(ev)
        assert "blocked" in label.lower()

    def test_waf_outcome_label_allowed(self):
        ev = map_modsecurity_line(_waf_line(action="allowed"), "test.jsonl", 1)
        label = waf_outcome_label(ev)
        assert "unconfirmed" in label.lower() or "allowed" in label.lower()

    def test_deterministic_event_id(self):
        line = _waf_line()
        ev1 = map_modsecurity_line(line, "test.jsonl", 5)
        ev2 = map_modsecurity_line(line, "test.jsonl", 5)
        assert ev1.event_id == ev2.event_id

    def test_different_lines_different_event_ids(self):
        ev1 = map_modsecurity_line(_waf_line(unique_id="uid-001"), "test.jsonl", 1)
        ev2 = map_modsecurity_line(_waf_line(unique_id="uid-002"), "test.jsonl", 2)
        assert ev1.event_id != ev2.event_id


class TestBlockIpScope:
    """Phase A block_ip scope tests (P4 policy rule)."""

    def test_block_ip_in_scope(self):
        from shared.contracts import ActionType, Category, Incident, IncidentStatus, Severity, LinkRule, Confidence
        from backend.policy.rules import evaluate_p4_scope
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        incident = Incident(
            incident_id="inc-deadbeef",
            title="Test",
            category=Category.web_attack,
            severity=Severity.high,
            status=IncidentStatus.open,
            first_seen=now,
            last_seen=now,
            affected_ips=["203.0.113.42"],
            affected_hosts=[],
            affected_users=[],
            evidence_event_ids=[],
            detection_reason="test",
            link_rule=LinkRule.NONE,
            confidence_label=Confidence.likely,
            created_at=now,
            updated_at=now,
        )
        # Should NOT raise for in-scope IP
        evaluate_p4_scope(incident, ActionType.block_ip, "203.0.113.42")

    def test_block_ip_out_of_scope(self):
        from shared.contracts import ActionType, Category, Incident, IncidentStatus, Severity, LinkRule, Confidence, ReasonCode
        from backend.policy.rules import evaluate_p4_scope, PolicyRuleViolation
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        incident = Incident(
            incident_id="inc-deadbeef",
            title="Test",
            category=Category.web_attack,
            severity=Severity.high,
            status=IncidentStatus.open,
            first_seen=now,
            last_seen=now,
            affected_ips=["203.0.113.42"],
            affected_hosts=[],
            affected_users=[],
            evidence_event_ids=[],
            detection_reason="test",
            link_rule=LinkRule.NONE,
            confidence_label=Confidence.likely,
            created_at=now,
            updated_at=now,
        )
        with pytest.raises(PolicyRuleViolation) as exc_info:
            evaluate_p4_scope(incident, ActionType.block_ip, "10.0.0.1")
        assert exc_info.value.code.value == "TARGET_OUT_OF_SCOPE"

