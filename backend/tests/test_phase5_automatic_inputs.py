"""Tests for Phase 5: Automatic Inputs (Mail Watcher, DNS Watcher, Telegram Bot, Auto-Explain)."""

from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from integrations.mail_watcher import parse_eml_bytes, resolve_recipient_user
from integrations.dns_watcher import DnsWatcher
from integrations.telegram_bot import format_phishing_reply, handle_user_message
from detection.phishing.scorer import score_domain, score_message
from backend.hooks import _trigger_auto_explain
from shared.contracts import Event, EventType, Incident, IncidentStatus, Category, Severity, LinkRule, Confidence, Source


# ---------------------------------------------------------------------------
# Mail Watcher Tests
# ---------------------------------------------------------------------------

def test_mail_watcher_eml_parsing():
    raw_eml = (
        b"From: security-update@fakelogin-portal.org\r\n"
        b"To: priya.rec@clinic.org\r\n"
        b"Subject: Action Required: Reset Password Immediately\r\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n"
        b"\r\n"
        b"--boundary123\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Your account is suspended. Click here: https://fakelogin-portal.org/login to verify.\r\n"
        b"--boundary123\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=\"payload.exe\"\r\n"
        b"\r\n"
        b"FAKE_BINARY_BYTES_NEVER_EXECUTED\r\n"
        b"--boundary123--\r\n"
    )

    parsed = parse_eml_bytes(raw_eml)
    assert "Reset Password" in parsed["subject"]
    assert "security-update@fakelogin-portal.org" in parsed["sender"]
    assert "payload.exe" in parsed["attachment_names"]
    assert "https://fakelogin-portal.org/login" in parsed["links"]
    assert "payload.exe" in parsed["combined_text"]

    mapping = {"priya.rec@clinic.org": "priya.rec"}
    user_id = resolve_recipient_user(parsed["to_addr"], mapping)
    assert user_id == "priya.rec"


# ---------------------------------------------------------------------------
# DNS Watcher & Lookalike Scoring Tests
# ---------------------------------------------------------------------------

def test_dns_lookalike_scoring():
    # Phishing domain
    is_phish, score, reasons = score_domain("fakelogin-clinic-portal.org")
    assert is_phish is True
    assert score >= 40

    # Legit domain
    is_legit, score2, _ = score_domain("clinic.org")
    assert is_legit is False
    assert score2 == 0


def test_dns_watcher_parsing():
    watcher = DnsWatcher()
    line = "2026-10-31T15:00:00Z 192.168.1.50 portal-update-fakelogin.org"
    ev = watcher.parse_dns_line(line, 1)

    assert ev is not None
    assert ev.event_type == EventType.dns_query
    assert ev.attributes["domain"] == "portal-update-fakelogin.org"
    assert ev.attributes["rule_flag"] == "R_LOOKALIKE"
    assert ev.severity == Severity.high


# ---------------------------------------------------------------------------
# Telegram Bot Tests
# ---------------------------------------------------------------------------

def test_telegram_phishing_formatting():
    # Red
    red_msg = format_phishing_reply("red", 85, [{"text": "High pressure language"}])
    assert "🔴 RED" in red_msg
    assert "DO NOT click" in red_msg

    # Amber
    amber_msg = format_phishing_reply("amber", 45, [{"text": "External sender"}])
    assert "🟡 AMBER" in amber_msg

    # Green
    green_msg = format_phishing_reply("green", 10, [])
    assert "🟢 GREEN" in green_msg
    assert "This is not a guarantee" in green_msg


def test_telegram_input_truncation():
    """Telegram message handler must truncate input to 2000 chars and not crash."""
    long_input = "A" * 5000
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "verdict": "green",
            "score": 5,
            "reasons": [],
            "event_id": "evt-test",
        }
        reply = handle_user_message("12345", long_input, "http://localhost:8000")
        assert "GREEN" in reply
        # Verify call used <= 2000 chars
        called_payload = mock_post.call_args[1]["json"]
        assert len(called_payload["text"]) <= 2000


# ---------------------------------------------------------------------------
# Auto-Explain Hook Test
# ---------------------------------------------------------------------------

def test_auto_explain_hook(tmp_path, monkeypatch):
    import backend.ai.adapter as adapter

    monkeypatch.setattr(adapter, "_CACHE_DIR", tmp_path)
    monkeypatch.setenv("LLM_PROVIDER", "none")

    now = datetime(2026, 10, 31, 15, 0, 0, tzinfo=timezone.utc)
    cand = Incident(
        incident_id="inc-12345678",
        title="Test Incident",
        category=Category.account_takeover,
        severity=Severity.high,
        status=IncidentStatus.open,
        first_seen=now,
        last_seen=now,
        affected_hosts=["pc-1"],
        affected_users=["user-1"],
        evidence_event_ids=["evt-1"],
        detection_reason="R1",
        link_rule=LinkRule.NONE,
        confidence_label=Confidence.likely,
        schema_version="1.0",
        created_at=now,
        updated_at=now,
    )
    events = [
        Event(
            event_id="evt-1",
            timestamp=now,
            source=Source.collector,
            host_id="pc-1",
            user_id="user-1",
            event_type=EventType.authentication_failure,
            severity=Severity.medium,
            raw_event_ref="raw-1",
            attributes={},
            schema_version="1.0",
        )
    ]

    result = _trigger_auto_explain([cand], events)
    # When LLM_PROVIDER=none and no cache exists, the hook returns a fallback.
    # We verify the hook ran without error and returned a valid Explanation.
    # Fallbacks are intentionally NOT cached so that a future real LLM call can write.
    from shared.contracts import Explanation
    assert isinstance(result, list)
    assert len(result) == 1
    expl = result[0]
    assert isinstance(expl, Explanation)
    assert expl.generated_by == "fallback"
    assert expl.incident_id == "inc-12345678"
