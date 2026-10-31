"""Validation matrix for AgentGuard detection pipeline.

Evaluates TP/FP/TN/FN for benign and attack scenarios and writes docs/validation-results.md.

Usage:
    python eval/validation_matrix.py

Outputs: docs/validation-results.md
"""

import json
import sys
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.contracts import (
    Event, EventType, Severity, Source, Category
)
from detection.pipeline import process_events
from detection.risk import RiskEngine


def _ts(offset_seconds: int = 0) -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=offset_seconds)


def _evt(eid: str, etype: EventType, sev: Severity, user: str = None, host: str = "clinic-web-01",
         attrs: dict = None, ts_offset: int = 0, session_hash: str = None, src_ip: str = "127.0.0.1",
         trace_id: str = None, user_agent: str = None) -> Event:
    valid_eid = eid if eid.startswith("evt-") else f"evt-{eid}"
    return Event(
        event_id=valid_eid,
        timestamp=_ts(ts_offset),
        source=Source.simulator,
        host_id=host,
        user_id=user,
        event_type=etype,
        severity=sev,
        raw_event_ref=f"validation:{valid_eid}",
        attributes={**(attrs or {}), "src_ip": src_ip},
        session_id_hash=session_hash,
        trace_id=trace_id,
        user_agent=user_agent,
        schema_version="1.0",
    )


# ── BENIGN SCENARIOS ──────────────────────────────────────────────────────────

def scenario_benign_one_wrong_password() -> Tuple[str, List[Event]]:
    """One wrong password then correct login. MUST produce zero incidents."""
    return "Benign: one wrong password then correct login", [
        _evt("evt-b1-f1", EventType.authentication_failure, Severity.medium, user="alice", attrs={"event_action": "login_failed"}, src_ip="192.168.1.10"),
        _evt("evt-b1-s1", EventType.authentication_success, Severity.low, user="alice", attrs={"event_action": "login_success"}, ts_offset=5, src_ip="192.168.1.10"),
    ]


def scenario_benign_new_ip_owner() -> Tuple[str, List[Event]]:
    """Owner login from a new IP (R3 fires but alone ≠ incident). MUST produce zero incidents."""
    return "Benign: owner login from new IP (single R3, no multi-signal)", [
        _evt("evt-b2-s1", EventType.authentication_success, Severity.medium, user="priya.rec", attrs={"event_action": "login_success"}, src_ip="10.20.30.40"),
    ]


def scenario_benign_normal_shopping_day() -> Tuple[str, List[Event]]:
    """Normal shopping day with regular data access. MUST produce zero incidents."""
    events = []
    for i in range(10):
        events.append(_evt(f"evt-b3-da{i}", EventType.data_access, Severity.low, user="front.desk",
                           attrs={"action": "view_record", "record_count": 1, "bytes": 512}, ts_offset=i * 30,
                           src_ip="192.168.1.11"))
    return "Benign: normal shopping day (10 sequential data reads)", events


def scenario_benign_scheduled_backup() -> Tuple[str, List[Event]]:
    """Scheduled backup - allowlisted. MUST produce zero incidents."""
    return "Benign: scheduled backup by backup_agent.exe", [
        _evt("evt-b4-p1", EventType.process_start, Severity.low, user="backup_svc",
             attrs={"image": "backup_agent.exe", "process_name": "backup_agent.exe", "scheduled": "true"},
             src_ip="192.168.1.20"),
        _evt("evt-b4-fc1", EventType.file_change_burst, Severity.low,
             attrs={"files_changed": 200, "new_extension": ".bak", "image": "backup_agent.exe", "scheduled": "true"},
             ts_offset=5, src_ip="192.168.1.20"),
    ]


def scenario_benign_staff_export_10() -> Tuple[str, List[Event]]:
    """Staff export of 10 records. MUST produce zero incidents."""
    return "Benign: staff export of 10 records (below threshold)", [
        _evt("evt-b5-da1", EventType.data_access, Severity.low, user="front.desk",
             attrs={"action": "export", "record_count": 10, "bytes": 10240}, src_ip="192.168.1.11"),
    ]


def scenario_benign_new_staff_device() -> Tuple[str, List[Event]]:
    """New staff device login (single auth success from new IP). MUST produce zero incidents."""
    return "Benign: new staff device (single auth success, no burst)", [
        _evt("evt-b6-s1", EventType.authentication_success, Severity.medium, user="new.staff",
             attrs={"event_action": "login_success"}, src_ip="172.16.0.5"),
    ]


# ── ATTACK SCENARIOS ──────────────────────────────────────────────────────────

def scenario_attack_brute_force() -> Tuple[str, List[Event], str]:
    """Account takeover: brute force (R1) + success (R2). MUST trigger account_takeover."""
    events = []
    for i in range(6):
        events.append(_evt(f"a1-f{i}", EventType.authentication_failure, Severity.medium,
                           user="admin", attrs={"event_action": "login_failed"}, ts_offset=i * 10, src_ip="203.0.113.42"))
    events.append(_evt("a1-s1", EventType.authentication_success, Severity.high, user="admin",
                        attrs={"event_action": "login_success"}, ts_offset=70, src_ip="203.0.113.42"))
    return "Attack: brute force + login success (R1+R2)", events, "account_takeover"


def scenario_attack_session_hijack() -> Tuple[str, List[Event], str]:
    """Session hijack: same session token, two IPs. MUST trigger account_takeover."""
    events = [
        _evt("a2-r1", EventType.web_request, Severity.low, user="alice",
             attrs={"path": "/dashboard"}, session_hash="sess-abc123", src_ip="192.168.1.10", ts_offset=0),
        _evt("a2-r2", EventType.web_request, Severity.low, user="alice",
             attrs={"path": "/patients/records"}, session_hash="sess-abc123", src_ip="203.0.113.99", ts_offset=30),
    ]
    return "Attack: session hijack (same session_id_hash, two IPs)", events, "account_takeover"


def scenario_attack_password_spray() -> Tuple[str, List[Event], str]:
    """Password spray: one IP → 5+ distinct accounts failing. MUST trigger account_takeover."""
    events = []
    users = ["alice", "bob", "carol", "dave", "eve", "frank"]
    for i, u in enumerate(users):
        events.append(_evt(f"a3-f{i}", EventType.authentication_failure, Severity.medium,
                           user=u, attrs={"event_action": "login_failed"}, ts_offset=i * 30, src_ip="10.99.0.1"))
    return "Attack: password spray (1 IP, 6 distinct accounts)", events, "account_takeover"


def scenario_attack_sqli_probe() -> Tuple[str, List[Event], str]:
    """SQLi probe. MUST trigger web_attack."""
    events = [
        _evt(f"a4-w{i}", EventType.web_request, Severity.medium,
             attrs={"path": "/patients/search", "query": f"q=1' OR '1'='1 #{i}", "src_ip": "203.0.113.42"},
             ts_offset=i * 5, src_ip="203.0.113.42")
        for i in range(5)
    ]
    return "Attack: SQLi probe (W1 + W2 threshold)", events, "web_attack"


def scenario_attack_mass_delete() -> Tuple[str, List[Event], str]:
    """Mass delete (D3 > 30 delete events). MUST trigger data_exfiltration_suspected."""
    events = []
    for i in range(35):
        events.append(_evt(f"a5-d{i}", EventType.data_access, Severity.high,
                           user="rogue.admin", attrs={"action": "delete", "record_count": 1, "bytes": 0},
                           ts_offset=i * 2, src_ip="192.168.1.100"))
    return "Attack: D3 mass delete (35 delete events)", events, "data_exfiltration_suspected"


def scenario_attack_file_burst() -> Tuple[str, List[Event], str]:
    """File change burst ransomware-like. MUST trigger ransomware_like_activity."""
    events = [
        _evt("a6-fb1", EventType.file_change_burst, Severity.high,
             attrs={"files_changed": 150, "new_extension": ".enc"}, ts_offset=0),
        _evt("a6-bt1", EventType.backup_tampering, Severity.high, ts_offset=60),
    ]
    return "Attack: file burst + backup tampering (F1+F2)", events, "ransomware_like_activity"


def scenario_attack_bulk_export() -> Tuple[str, List[Event], str]:
    """Bulk data export exceeding threshold. MUST trigger data_exfiltration_suspected."""
    return "Attack: bulk data export (D1, 1000 records)", [
        _evt("a7-da1", EventType.data_access, Severity.high, user="exfil.user",
             attrs={"action": "export", "record_count": 1000, "bytes": 200000}, src_ip="10.0.0.99"),
    ], "data_exfiltration_suspected"


def scenario_attack_phishing_multistage() -> Tuple[str, List[Event], str]:
    """Phishing check + account takeover → multi_stage."""
    events = [
        _evt("a8-pc1", EventType.phishing_check, Severity.high, user="victim.user",
             attrs={"verdict": "red", "score": 80}, ts_offset=0),
    ] + [
        _evt(f"a8-f{i}", EventType.authentication_failure, Severity.medium, user="victim.user",
             attrs={"event_action": "login_failed"}, ts_offset=60 + i * 10, src_ip="203.0.113.42")
        for i in range(6)
    ] + [
        _evt("a8-s1", EventType.authentication_success, Severity.high, user="victim.user",
             attrs={"event_action": "login_success"}, ts_offset=130, src_ip="203.0.113.42")
    ]
    return "Attack: phishing + brute force (multi_stage)", events, "multi_stage"


def run_validation() -> Dict:
    risk_engine = RiskEngine()
    results = []
    tp = tn = fp = fn = 0

    # BENIGN SCENARIOS (expected: 0 incidents)
    benign_scenarios = [
        scenario_benign_one_wrong_password(),
        scenario_benign_new_ip_owner(),
        scenario_benign_normal_shopping_day(),
        scenario_benign_scheduled_backup(),
        scenario_benign_staff_export_10(),
        scenario_benign_new_staff_device(),
    ]
    for name, events in benign_scenarios:
        pipeline_incidents = process_events(events)
        risk_incidents = risk_engine.evaluate_signals(events)
        all_incidents = pipeline_incidents + risk_incidents
        # Benign: any incident = FP
        if all_incidents:
            fp += len(all_incidents)
            results.append({"scenario": name, "expected": "TN", "actual": f"FP ({len(all_incidents)} incident(s))",
                            "categories": [i.category.value for i in all_incidents], "result": "FP"})
        else:
            tn += 1
            results.append({"scenario": name, "expected": "TN", "actual": "TN (0 incidents)", "result": "TN"})

    # ATTACK SCENARIOS (expected: at least 1 incident of given category)
    attack_scenarios = [
        scenario_attack_brute_force(),
        scenario_attack_session_hijack(),
        scenario_attack_password_spray(),
        scenario_attack_sqli_probe(),
        scenario_attack_mass_delete(),
        scenario_attack_file_burst(),
        scenario_attack_bulk_export(),
        scenario_attack_phishing_multistage(),
    ]
    for name, events, expected_cat in attack_scenarios:
        pipeline_incidents = process_events(events)
        risk_incidents = risk_engine.evaluate_signals(events)
        all_incidents = pipeline_incidents + risk_incidents
        found_cat = any(i.category.value == expected_cat for i in all_incidents)
        if all_incidents and found_cat:
            tp += 1
            results.append({"scenario": name, "expected": f"TP ({expected_cat})", "actual": f"TP ({len(all_incidents)} incident(s))",
                            "categories": [i.category.value for i in all_incidents], "result": "TP"})
        elif all_incidents and not found_cat:
            # Got incidents but wrong category - count as partial TP (FP in category)
            fp += 1
            results.append({"scenario": name, "expected": f"TP ({expected_cat})", "actual": f"Wrong category: {[i.category.value for i in all_incidents]}",
                            "categories": [i.category.value for i in all_incidents], "result": "FP"})
        else:
            fn += 1
            results.append({"scenario": name, "expected": f"TP ({expected_cat})", "actual": "FN (0 incidents)", "result": "FN"})

    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fp_rate = fp / (tn + fp) if (tn + fp) > 0 else 0.0

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn, "total": total,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "false_positive_rate": round(fp_rate, 3),
        "results": results,
    }


def write_report(metrics: Dict, out_path: str = "docs/validation-results.md") -> None:
    lines = [
        "# AgentGuard Detection Validation Results",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| True Positives  | {metrics['tp']} |",
        f"| True Negatives  | {metrics['tn']} |",
        f"| False Positives | {metrics['fp']} |",
        f"| False Negatives | {metrics['fn']} |",
        f"| Precision       | {metrics['precision']:.1%} |",
        f"| Recall          | {metrics['recall']:.1%} |",
        f"| False Positive Rate | {metrics['false_positive_rate']:.1%} |",
        "",
        "## Scenario Results",
        "",
        "| Scenario | Expected | Actual | Result |",
        "|----------|----------|--------|--------|",
    ]
    for r in metrics["results"]:
        lines.append(f"| {r['scenario'][:70]} | {r['expected']} | {r['actual']} | **{r['result']}** |")

    lines += [
        "",
        "> [!NOTE]",
        "> This validation uses synthetic test vectors. Detection is deterministic and rule-based.",
        "> Results reflect the configured thresholds (R1: ≥5 failures, D3: ≥30 deletes, etc.).",
    ]

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"Validation report written to {out_path}")


if __name__ == "__main__":
    metrics = run_validation()
    print(f"\nTP={metrics['tp']} TN={metrics['tn']} FP={metrics['fp']} FN={metrics['fn']}")
    print(f"Precision={metrics['precision']:.1%}  Recall={metrics['recall']:.1%}  FPR={metrics['false_positive_rate']:.1%}")
    write_report(metrics)
