"""Generate feature status JSON and STATUS.md from test results.

A feature is marked 'Built' only if its test suite passes.
Run: python scripts/gen_status.py

Outputs: docs/feature-status.json, docs/STATUS.md
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


FEATURES = [
    {
        "id": "policy_gateway",
        "name": "Deterministic Policy Gateway",
        "description": "P1-P6 rules: only authorizes when all checks pass. AI only recommends.",
        "test_file": "backend/tests/test_detection_rules.py",
        "status": "unknown",
    },
    {
        "id": "audit_chain",
        "name": "Tamper-Evident Audit Chain",
        "description": "SHA256 hash chain; /api/audit/verify detects tampering.",
        "test_file": "backend/tests/test_milestone_c.py",
        "status": "unknown",
    },
    {
        "id": "raw_evidence_archive",
        "name": "Raw Evidence Archive (Phase B)",
        "description": "4KB-capped append-only archive with SHA256 checksums and retention cleanup.",
        "test_file": "backend/tests/test_phase_b_archive.py",
        "status": "unknown",
    },
    {
        "id": "risk_engine",
        "name": "Risk Scoring Engine (Phase C)",
        "description": "Weighted multi-signal risk engine, session hijack, password spray, mass delete detectors.",
        "test_file": "backend/tests/test_phase_c_risk.py",
        "status": "unknown",
    },
    {
        "id": "waf_adapter",
        "name": "WAF/ModSecurity Log Adapter (Phase D)",
        "description": "Maps ModSecurity JSON audit entries to web_request events. SAMPLE-BASED.",
        "test_file": "backend/tests/test_phase_d_waf.py",
        "status": "unknown",
    },
    {
        "id": "trace_correlation",
        "name": "Trace ID Correlation (Phase E)",
        "description": "Links events by trace_id/request_id or user/session/time window.",
        "test_file": "backend/tests/test_phase_e_correlation.py",
        "status": "unknown",
    },
    {
        "id": "posture",
        "name": "Security Posture Assessment (Phase F)",
        "description": "HTTPS/HSTS, cookie flags, security headers, MFA, RDP, backup, KEV check. Localhost only.",
        "test_file": "backend/tests/test_phase_f_posture.py",
        "status": "unknown",
    },
    {
        "id": "validation_matrix",
        "name": "Validation Matrix (Phase G)",
        "description": "6 benign / 8 attack scenarios; TP/FP/TN/FN, precision, recall.",
        "test_file": "backend/tests/test_phase_g_validation.py",
        "status": "unknown",
    },
    {
        "id": "sample_connectors",
        "name": "Sample-Based Connectors (Phase I)",
        "description": "BigQuery audit log and Sysmon event mappers. SAMPLE-BASED, not live.",
        "test_file": "backend/tests/test_phase_i_connectors.py",
        "status": "unknown",
    },
    {
        "id": "phishing_scorer",
        "name": "Phishing Scoring",
        "description": "Deterministic rule-based phishing scorer with verdict red/amber/green.",
        "test_file": "backend/tests/test_milestone_a.py",
        "status": "unknown",
    },
    {
        "id": "contract_extensions",
        "name": "Contract Extensions (Phase A)",
        "description": "block_ip action, network_connection event, optional trace/session fields, affected_ips.",
        "test_file": "backend/tests/test_phase_a_extensions.py",
        "status": "unknown",
    },
]


def run_test(test_file: str) -> bool:
    """Run a specific test file and return True if all tests pass."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test_file, "-q", "--tb=no", "--no-header"],
        capture_output=True, text=True, timeout=120,
    )
    return result.returncode == 0


def generate_status() -> dict:
    features = []
    for f in FEATURES:
        test_file = f["test_file"]
        if Path(test_file).exists():
            passed = run_test(test_file)
            status = "Built" if passed else "Failing"
        else:
            status = "Missing tests"

        features.append({
            "id": f["id"],
            "name": f["name"],
            "description": f["description"],
            "status": status,
            "test_file": test_file,
        })

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "features": features,
    }


def write_status_md(status_data: dict, out_path: str = "docs/STATUS.md") -> None:
    lines = [
        "# AgentGuard Feature Status",
        "",
        f"Generated: {status_data['generated_at']}",
        "",
        "> [!NOTE]",
        "> A feature is marked **Built** only if its automated test suite passes.",
        "> SAMPLE-BASED features use synthetic data and are not connected to live systems.",
        "",
        "| Feature | Status | Description |",
        "|---------|--------|-------------|",
    ]
    for f in status_data["features"]:
        status_emoji = "✅" if f["status"] == "Built" else ("❌" if f["status"] == "Failing" else "⚠️")
        lines.append(f"| {f['name']} | {status_emoji} {f['status']} | {f['description'][:80]} |")

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"STATUS.md written to {out_path}")


if __name__ == "__main__":
    print("Generating feature status (running tests per feature)...")
    status_data = generate_status()

    json_path = "docs/feature-status.json"
    Path(json_path).write_text(json.dumps(status_data, indent=2), encoding="utf-8")
    print(f"Feature status JSON written to {json_path}")

    write_status_md(status_data)

    built = sum(1 for f in status_data["features"] if f["status"] == "Built")
    total = len(status_data["features"])
    print(f"\n{built}/{total} features Built and passing tests.")

