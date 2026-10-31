"""Tests for Phase G: Validation matrix and load test."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestValidationMatrix:
    """Ensure the validation matrix runs and produces expected TP/TN counts."""

    def test_benign_zero_incidents_one_wrong_password(self):
        from eval.validation_matrix import scenario_benign_one_wrong_password
        from detection.pipeline import process_events
        from detection.risk import RiskEngine
        _, events = scenario_benign_one_wrong_password()
        incidents = process_events(events) + RiskEngine().evaluate_signals(events)
        assert len(incidents) == 0, f"Benign scenario produced incidents: {[i.category.value for i in incidents]}"

    def test_benign_zero_incidents_new_ip_owner(self):
        from eval.validation_matrix import scenario_benign_new_ip_owner
        from detection.pipeline import process_events
        from detection.risk import RiskEngine
        _, events = scenario_benign_new_ip_owner()
        incidents = process_events(events) + RiskEngine().evaluate_signals(events)
        assert len(incidents) == 0

    def test_benign_zero_incidents_normal_shopping(self):
        from eval.validation_matrix import scenario_benign_normal_shopping_day
        from detection.pipeline import process_events
        from detection.risk import RiskEngine
        _, events = scenario_benign_normal_shopping_day()
        incidents = process_events(events) + RiskEngine().evaluate_signals(events)
        assert len(incidents) == 0

    def test_benign_zero_incidents_scheduled_backup(self):
        from eval.validation_matrix import scenario_benign_scheduled_backup
        from detection.pipeline import process_events
        from detection.risk import RiskEngine
        _, events = scenario_benign_scheduled_backup()
        incidents = process_events(events) + RiskEngine().evaluate_signals(events)
        assert len(incidents) == 0

    def test_benign_zero_incidents_staff_export_10(self):
        from eval.validation_matrix import scenario_benign_staff_export_10
        from detection.pipeline import process_events
        from detection.risk import RiskEngine
        _, events = scenario_benign_staff_export_10()
        incidents = process_events(events) + RiskEngine().evaluate_signals(events)
        assert len(incidents) == 0

    def test_attack_brute_force_detected(self):
        from eval.validation_matrix import scenario_attack_brute_force
        from detection.pipeline import process_events
        _, events, expected_cat = scenario_attack_brute_force()
        incidents = process_events(events)
        assert any(i.category.value == expected_cat for i in incidents), \
            f"Expected {expected_cat}, got: {[i.category.value for i in incidents]}"

    def test_attack_session_hijack_detected(self):
        from eval.validation_matrix import scenario_attack_session_hijack
        from detection.risk import RiskEngine
        _, events, expected_cat = scenario_attack_session_hijack()
        incidents = RiskEngine().evaluate_signals(events)
        assert any(i.category.value == expected_cat for i in incidents), \
            f"Expected {expected_cat}, got: {[i.category.value for i in incidents]}"

    def test_attack_password_spray_detected(self):
        from eval.validation_matrix import scenario_attack_password_spray
        from detection.risk import RiskEngine
        _, events, expected_cat = scenario_attack_password_spray()
        incidents = RiskEngine().evaluate_signals(events)
        assert any(i.category.value == expected_cat for i in incidents)

    def test_attack_mass_delete_detected(self):
        from eval.validation_matrix import scenario_attack_mass_delete
        from detection.risk import RiskEngine
        _, events, expected_cat = scenario_attack_mass_delete()
        incidents = RiskEngine().evaluate_signals(events)
        assert any(i.category.value == expected_cat for i in incidents)

    def test_attack_file_burst_detected(self):
        from eval.validation_matrix import scenario_attack_file_burst
        from detection.pipeline import process_events
        _, events, expected_cat = scenario_attack_file_burst()
        incidents = process_events(events)
        assert any(i.category.value == expected_cat for i in incidents)


class TestLoadTest:
    def test_load_test_runs_small(self):
        from eval.load_test import run_load_test
        metrics = run_load_test(count=100, batch_size=50)
        assert metrics["total_events"] == 100
        assert metrics["parse_errors"] == 0
        assert metrics["ingest_rate_per_s"] > 0
        assert metrics["total_time_s"] > 0

    def test_load_test_writes_report(self, tmp_path):
        from eval.load_test import run_load_test, write_report
        metrics = run_load_test(count=50, batch_size=25)
        out = str(tmp_path / "perf.md")
        write_report(metrics, out)
        content = Path(out).read_text()
        assert "Ingest rate" in content
        assert "SIMULATION" in content

