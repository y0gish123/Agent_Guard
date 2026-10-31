"""Tests for Phase I: Sample-based connectors (BigQuery Audit, Sysmon)."""

import json
import pytest
from pathlib import Path
from collector.mappers.bigquery_audit import map_bigquery_audit_entry, map_bigquery_audit_file
from collector.mappers.sysmon import map_sysmon_line, map_sysmon_file
from shared.contracts import EventType, Severity


class TestBigQueryAuditMapper:
    def _entry(self, method="google.bigquery.v2.TableDataService.list",
               principal="user@test.com", bytes_processed="4096",
               caller_ip="127.0.0.1", insert_id="bq-001"):
        return {
            "insertId": insert_id,
            "timestamp": "2026-10-31T08:00:00Z",
            "protoPayload": {
                "authenticationInfo": {"principalEmail": principal},
                "methodName": method,
                "resourceName": "projects/p/datasets/d/tables/t",
                "requestMetadata": {"callerIp": caller_ip},
            },
            "resource": {"type": "bigquery_dataset"},
            "labels": {"bytes_processed": bytes_processed},
        }

    def test_read_method_maps_to_data_access(self):
        ev = map_bigquery_audit_entry(self._entry())
        assert ev is not None
        assert ev.event_type == EventType.data_access
        assert ev.attributes["action"] == "read"

    def test_export_method_maps_to_export(self):
        ev = map_bigquery_audit_entry(self._entry(method="google.bigquery.v2.JobService.export"))
        assert ev.attributes["action"] == "export"

    def test_delete_method_high_severity(self):
        ev = map_bigquery_audit_entry(self._entry(method="google.bigquery.v2.TableService.delete"))
        assert ev.attributes["action"] == "delete"
        assert ev.severity == Severity.high

    def test_large_bytes_high_severity(self):
        ev = map_bigquery_audit_entry(self._entry(bytes_processed="100000"))
        assert ev.severity == Severity.high

    def test_insert_id_becomes_trace_id(self):
        ev = map_bigquery_audit_entry(self._entry(insert_id="bq-trace-xyz"))
        assert ev.trace_id == "bq-trace-xyz"
        assert ev.source_event_id == "bq-trace-xyz"

    def test_principal_becomes_user_id(self):
        ev = map_bigquery_audit_entry(self._entry(principal="dr.priya@clinic.local"))
        assert ev.user_id == "dr.priya@clinic.local"

    def test_sample_file_parsed(self):
        sample_path = Path("docs/samples/bigquery_audit_sample.json")
        if not sample_path.exists():
            pytest.skip("Sample file not found")
        events = map_bigquery_audit_file(str(sample_path))
        assert len(events) >= 1
        for ev in events:
            assert ev.event_type == EventType.data_access


class TestSysmonMapper:
    def _sysmon_line(self, event_id=1, image="C:\\Windows\\cmd.exe",
                     parent="C:\\Program Files\\Microsoft Office\\winword.exe",
                     dest_ip="203.0.113.50", computer="CLINIC-PC-01",
                     file_path="C:\\temp\\file.txt"):
        import json
        if event_id == 1:
            return json.dumps({"EventID": event_id, "UtcTime": "2026-10-31T08:00:00Z",
                               "Computer": computer, "User": "CLINIC\\user",
                               "ProcessGuid": "guid-test", "Image": image, "ParentImage": parent,
                               "CommandLine": "cmd.exe /c something"})
        elif event_id == 3:
            return json.dumps({"EventID": event_id, "UtcTime": "2026-10-31T08:00:00Z",
                               "Computer": computer, "User": "CLINIC\\user",
                               "ProcessGuid": "guid-test", "Image": image, "ParentImage": parent,
                               "SourceIp": "192.168.1.1", "DestinationIp": dest_ip, "DestinationPort": 443})
        elif event_id == 11:
            return json.dumps({"EventID": event_id, "UtcTime": "2026-10-31T08:00:00Z",
                               "Computer": computer, "TargetFilename": file_path,
                               "ProcessGuid": "guid-test", "Image": image})
        return json.dumps({"EventID": event_id})

    def test_process_create_maps_to_process_start(self):
        ev = map_sysmon_line(self._sysmon_line(1), "test.jsonl", 1)
        assert ev is not None
        assert ev.event_type == EventType.process_start

    def test_office_spawning_shell_is_suspicious(self):
        ev = map_sysmon_line(self._sysmon_line(1,
            image="C:\\Windows\\System32\\cmd.exe",
            parent="C:\\Program Files\\Microsoft Office\\winword.exe"), "test.jsonl", 1)
        assert ev.severity == Severity.high
        assert "suspicious_chain" in ev.attributes

    def test_normal_process_not_suspicious(self):
        ev = map_sysmon_line(self._sysmon_line(1,
            image="C:\\Windows\\notepad.exe",
            parent="C:\\Windows\\explorer.exe"), "test.jsonl", 1)
        assert ev.severity == Severity.low
        assert "suspicious_chain" not in ev.attributes

    def test_network_connection_maps(self):
        ev = map_sysmon_line(self._sysmon_line(3, dest_ip="203.0.113.50"), "test.jsonl", 1)
        assert ev is not None
        assert ev.event_type == EventType.network_connection
        assert ev.attributes["external"] is True

    def test_private_ip_network_not_external(self):
        ev = map_sysmon_line(self._sysmon_line(3, dest_ip="192.168.1.100"), "test.jsonl", 1)
        assert ev.attributes["external"] is False
        assert ev.severity == Severity.low

    def test_file_create_maps(self):
        ev = map_sysmon_line(self._sysmon_line(11, file_path="C:\\temp\\doc.txt"), "test.jsonl", 1)
        assert ev is not None
        assert ev.event_type == EventType.file_created

    def test_unknown_event_id_returns_none(self):
        import json
        line = json.dumps({"EventID": 99, "UtcTime": "2026-10-31T08:00:00Z"})
        ev = map_sysmon_line(line, "test.jsonl", 1)
        assert ev is None

    def test_empty_line_returns_none(self):
        assert map_sysmon_line("", "test.jsonl", 1) is None

    def test_sample_file_parsed(self):
        sample_path = Path("docs/samples/sysmon_sample.jsonl")
        if not sample_path.exists():
            pytest.skip("Sample file not found")
        events = map_sysmon_file(str(sample_path))
        assert len(events) >= 1

