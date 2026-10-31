"""Unit tests for Phase B: Raw Evidence Archive."""

from datetime import datetime, timezone, timedelta
import json
import pytest
from collector.raw_archive import RawArchiveManager, redact_sensitive_data


def test_redact_sensitive_keys():
    """Verify passwords, tokens, cookies, secrets are cleanly redacted."""
    sample = {
        "user": "priya.rec",
        "password": "SuperSecretPassword123!",
        "api_key": "AIzaSyD-dummyKeyHere",
        "nested": {
            "auth_token": "Bearer abcdef123456",
            "session_cookie": "sess_987654",
            "normal_field": "visible_value",
        },
    }
    redacted = redact_sensitive_data(sample)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["auth_token"] == "[REDACTED]"
    assert redacted["nested"]["session_cookie"] == "[REDACTED]"
    assert redacted["nested"]["normal_field"] == "visible_value"


def test_raw_archive_append_and_verify(tmp_path):
    """Verify archiving lines, index checksum creation, and tamper detection."""
    manager = RawArchiveManager(archive_dir=tmp_path)
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # 1. Archive two lines
    line1 = json.dumps({"event": "login_failed", "user": "priya.rec", "password": "secret_pwd"})
    line2 = json.dumps({"event": "access", "path": "/dashboard", "status": 200})

    ref1, ck1 = manager.archive_line(line1)
    ref2, ck2 = manager.archive_line(line2)

    assert ref1 == f"archive://{today_str}.jsonl#1"
    assert ref2 == f"archive://{today_str}.jsonl#2"
    assert len(ck1) == 64
    assert len(ck2) == 64

    # Verify password was redacted in stored file
    archive_file = tmp_path / f"{today_str}.jsonl"
    with open(archive_file, "r", encoding="utf-8") as f:
        stored_lines = f.readlines()
    assert len(stored_lines) == 2
    assert "secret_pwd" not in stored_lines[0]
    assert "[REDACTED]" in stored_lines[0]

    # Verify checksums
    verify_res = manager.verify_archive(today_str)
    assert verify_res["ok"] is True
    assert verify_res["checked_lines"] == 2

    # Tamper with file and check detection
    with open(archive_file, "a", encoding="utf-8") as f:
        f.write('{"tampered": true}\n')

    tampered_res = manager.verify_archive(today_str)
    # Missing index entry or mismatch
    assert tampered_res["ok"] is False


def test_retention_cleanup_preserves_recent(tmp_path):
    """Cleanup removes archives older than retention cutoff and leaves recent ones."""
    manager = RawArchiveManager(archive_dir=tmp_path)
    now = datetime.now(timezone.utc)

    # Old date (10 days ago)
    old_date = now - timedelta(days=10)
    manager.archive_line('{"old": true}', dt=old_date)

    # Recent date (today)
    manager.archive_line('{"recent": true}', dt=now)

    # 7-day retention cleanup
    removed = manager.cleanup_old_archives(retention_days=7)
    assert removed == 1

    remaining = list(tmp_path.glob("*.jsonl"))
    assert len(remaining) == 1
    assert remaining[0].name == f"{now.strftime('%Y-%m-%d')}.jsonl"

