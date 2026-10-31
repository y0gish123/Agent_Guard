"""Unit and integration tests for Phase 4: Live File Monitoring, Burst Aggregator, and Simulators."""

import os
from pathlib import Path
import pytest

from testbed.attack.file_burst_sim import verify_sandbox_path, run_file_burst, EXPECTED_SANDBOX_DIR
from testbed.attack.restore import restore_sandbox
from testbed.filemon.watcher import FileBurstAggregator
from detection.pipeline import detect_file_burst, process_events
from shared.contracts import Category, EventType, Severity


# ---------------------------------------------------------------------------
# Path Escape Refusal Test
# ---------------------------------------------------------------------------

def test_path_escape_refusal():
    """Simulator must refuse any path resolving outside demo_sandbox."""
    EXPECTED_SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    # Subpath inside sandbox is allowed
    valid_subpath = EXPECTED_SANDBOX_DIR / "subdir"
    valid_subpath.mkdir(exist_ok=True)
    assert verify_sandbox_path(valid_subpath) == valid_subpath

    # Path escaping sandbox must exit
    escape_path = EXPECTED_SANDBOX_DIR / ".." / "outside"
    with pytest.raises(SystemExit):
        verify_sandbox_path(escape_path)


# ---------------------------------------------------------------------------
# File Burst Aggregator Tests
# ---------------------------------------------------------------------------

def test_file_burst_aggregator():
    """Aggregator collects multiple changes and flushes a single file_change_burst Event."""
    aggregator = FileBurstAggregator(window_sec=5.0)

    # Record 120 changes with .locked extension
    for i in range(120):
        aggregator.record_change(f"/sandbox/file_{i}.locked")

    # Record 1 note file
    aggregator.record_change("/sandbox/README_RESTORE_FILES.txt")

    events = aggregator.flush_window()
    assert len(events) == 2  # 1 burst event + 1 note event

    burst_ev = [e for e in events if e.event_type == EventType.file_change_burst][0]
    assert burst_ev.attributes["files_changed"] == 121
    assert burst_ev.attributes["new_extension"] == ".locked"
    assert burst_ev.attributes["window_sec"] == 5.0
    assert burst_ev.event_id.startswith("evt-3")

    note_ev = [e for e in events if e.event_type == EventType.file_created][0]
    assert "README_RESTORE" in note_ev.attributes["file_path"]


# ---------------------------------------------------------------------------
# Benign .bak vs Malicious .locked Detection Tests
# ---------------------------------------------------------------------------

def test_benign_bak_burst_produces_no_incident():
    """Renaming files to .bak (backup scenario) must NOT trigger ransomware detection."""
    aggregator = FileBurstAggregator(window_sec=5.0)
    for i in range(120):
        aggregator.record_change(f"/sandbox/file_{i}.bak")

    events = aggregator.flush_window()
    assert len(events) == 1

    # Feed events to detection pipeline
    incidents = detect_file_burst(events)
    assert len(incidents) == 0


def test_malicious_locked_burst_triggers_ransomware():
    """Renaming files to .locked with a ransom note triggers ransomware_like_activity."""
    aggregator = FileBurstAggregator(window_sec=5.0)
    for i in range(120):
        aggregator.record_change(f"/sandbox/file_{i}.locked")
    aggregator.record_change("/sandbox/HOW_TO_DECRYPT_FILES.txt")

    events = aggregator.flush_window()
    incidents = detect_file_burst(events)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == Category.ransomware_like_activity
    assert inc.severity in (Severity.high, Severity.critical)
    assert "F1" in inc.detection_reason
    assert "F3" in inc.detection_reason
