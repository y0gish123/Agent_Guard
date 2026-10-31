"""Tests for Phase F: Security Posture Assessment."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from backend.posture.checks import (
    check_backup_health,
    check_exposed_rdp,
    check_https_hsts,
    check_mfa_coverage,
    check_outdated_software,
    check_security_headers,
    _is_localhost,
)


class TestIsLocalhost:
    def test_localhost_accepted(self):
        assert _is_localhost("http://localhost:8002")
        assert _is_localhost("http://127.0.0.1:8002")
        assert _is_localhost("https://localhost:443")
        assert _is_localhost("http://127.0.0.5:8080")

    def test_non_localhost_rejected(self):
        assert not _is_localhost("https://example.com")
        assert not _is_localhost("http://192.168.1.1:8002")
        assert not _is_localhost("http://10.0.0.1")


class TestCheckBackupHealth:
    def test_missing_file_returns_unknown(self, tmp_path):
        result = check_backup_health(str(tmp_path / "nonexistent.json"))
        assert result["status"] == "unknown"

    def test_valid_backup_passes(self, tmp_path):
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        restore = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = {"last_success": recent, "offline_copy": True, "last_restore_test": restore}
        p = tmp_path / "backup.json"
        p.write_text(json.dumps(data))
        result = check_backup_health(str(p))
        assert result["status"] == "pass"

    def test_stale_backup_warns_or_fails(self, tmp_path):
        from datetime import datetime, timezone, timedelta
        stale = (datetime.now(timezone.utc) - timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ")
        restore = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = {"last_success": stale, "offline_copy": True, "last_restore_test": restore}
        p = tmp_path / "backup.json"
        p.write_text(json.dumps(data))
        result = check_backup_health(str(p))
        assert result["status"] in ("warn", "fail")

    def test_no_offline_copy_fails(self, tmp_path):
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        restore = recent
        data = {"last_success": recent, "offline_copy": False, "last_restore_test": restore}
        p = tmp_path / "backup.json"
        p.write_text(json.dumps(data))
        result = check_backup_health(str(p))
        assert result["status"] in ("warn", "fail")


class TestCheckOutdatedSoftware:
    def test_missing_kev_returns_unknown(self, tmp_path):
        result = check_outdated_software("http://localhost:8002", str(tmp_path / "no_kev.json"))
        assert result["status"] == "unknown"

    def test_match_found_fails(self, tmp_path):
        kev = {
            "snapshot_date": "2026-10-01",
            "entries": [{"cve_id": "CVE-2021-44228", "product": "log4j", "vendor": "Apache"}]
        }
        kev_path = tmp_path / "kev.json"
        kev_path.write_text(json.dumps(kev))

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"components": [{"name": "apache-log4j", "version": "2.14.0"}]}

        with patch("backend.posture.checks._REQUESTS_AVAILABLE", True):
            with patch("backend.posture.checks._requests") as mock_req:
                mock_req.get.return_value = mock_resp
                result = check_outdated_software("http://localhost:8002", str(kev_path))
        assert result["status"] == "fail"
        assert "CVE-2021-44228" in result["evidence"]

    def test_no_match_passes(self, tmp_path):
        kev = {"snapshot_date": "2026-10-01", "entries": [{"cve_id": "CVE-2021-44228", "product": "log4j", "vendor": "Apache"}]}
        kev_path = tmp_path / "kev.json"
        kev_path.write_text(json.dumps(kev))

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"components": [{"name": "nginx", "version": "1.24.0"}]}

        with patch("backend.posture.checks._REQUESTS_AVAILABLE", True):
            with patch("backend.posture.checks._requests") as mock_req:
                mock_req.get.return_value = mock_resp
                result = check_outdated_software("http://localhost:8002", str(kev_path))
        assert result["status"] == "pass"


class TestCheckExposedRdp:
    def test_rdp_check_returns_valid_status(self):
        result = check_exposed_rdp()
        assert result["status"] in ("pass", "fail", "unknown")
        assert result["name"] == "Exposed RDP"


class TestRefuseNonLocalhost:
    def test_https_check_refuses_non_localhost(self):
        result = check_https_hsts("https://example.com")
        assert result["status"] == "unknown"
        assert "Refusing" in result["evidence"] or "non-localhost" in result["evidence"]

    def test_mfa_check_refuses_non_localhost(self):
        result = check_mfa_coverage("https://example.com")
        assert result["status"] == "unknown"

    def test_security_headers_refuses_non_localhost(self):
        result = check_security_headers("https://example.com")
        assert result["status"] == "unknown"

