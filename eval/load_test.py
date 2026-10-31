"""Load test for AgentGuard ingest pipeline.

Generates synthetic log events, ingests them, measures throughput and latency.
Writes docs/performance-results.md.

Usage:
    python eval/load_test.py [--count 100000] [--batch-size 100]

SIMULATION: generates synthetic data only. Does not connect to external systems.
"""

import argparse
import json
import os
import platform
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


def generate_events(count: int, batch_size: int = 100) -> List[dict]:
    """Generate synthetic log event payloads."""
    events = []
    event_types = [
        "authentication_failure", "authentication_success", "web_request", "data_access",
        "file_created", "process_start", "network_connection",
    ]
    for i in range(count):
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        etype = event_types[i % len(event_types)]
        events.append({
            "event_id": f"evt-load-{uuid.uuid4().hex[:12]}",
            "timestamp": ts,
            "source": "simulator",
            "host_id": f"host-{(i % 10) + 1:02d}",
            "user_id": f"user-{(i % 50) + 1:03d}",
            "event_type": etype,
            "severity": ["low", "medium", "high"][i % 3],
            "raw_event_ref": f"load_test:{i}",
            "attributes": {
                "src_ip": f"192.168.{(i % 10) + 1}.{(i % 254) + 1}",
                "action": "view_record",
                "record_count": 1,
            },
            "schema_version": "1.0",
        })
    return events


def run_load_test(count: int, batch_size: int, backend_url: str = "http://localhost:8000") -> dict:
    """Run load test by processing events through the detection pipeline locally (no network)."""
    import importlib

    print(f"[LOAD TEST] Generating {count} synthetic events...", flush=True)
    t_gen_start = time.monotonic()
    events_raw = generate_events(count, batch_size)
    t_gen_end = time.monotonic()
    gen_time = t_gen_end - t_gen_start
    print(f"[LOAD TEST] Generation took {gen_time:.2f}s", flush=True)

    # Parse events through shared contracts
    from shared.contracts import Event
    parsed_events = []
    t_parse_start = time.monotonic()
    parse_errors = 0
    for raw in events_raw:
        try:
            ev = Event(**raw)
            parsed_events.append(ev)
        except Exception:
            parse_errors += 1
    t_parse_end = time.monotonic()
    parse_time = t_parse_end - t_parse_start

    # Run through detection pipeline (batched)
    from detection.pipeline import process_events
    incidents = []
    t_detect_start = time.monotonic()
    for i in range(0, len(parsed_events), batch_size):
        batch = parsed_events[i:i + batch_size]
        batch_incidents = process_events(batch)
        incidents.extend(batch_incidents)
    t_detect_end = time.monotonic()
    detect_time = t_detect_end - t_detect_start

    total_time = gen_time + parse_time + detect_time
    ingest_rate = count / total_time if total_time > 0 else 0

    # Memory
    peak_memory_mb = None
    if _PSUTIL_AVAILABLE:
        proc = psutil.Process(os.getpid())
        peak_memory_mb = round(proc.memory_info().rss / 1024 / 1024, 1)

    return {
        "total_events": count,
        "batch_size": batch_size,
        "parse_errors": parse_errors,
        "incidents_detected": len(incidents),
        "generation_time_s": round(gen_time, 3),
        "parse_time_s": round(parse_time, 3),
        "detection_time_s": round(detect_time, 3),
        "total_time_s": round(total_time, 3),
        "ingest_rate_per_s": round(ingest_rate),
        "peak_memory_mb": peak_memory_mb,
        "machine": {
            "os": platform.system(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
    }


def write_report(metrics: dict, out_path: str = "docs/performance-results.md") -> None:
    m = metrics["machine"]
    lines = [
        "# AgentGuard Performance Test Results",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Machine Specification",
        "",
        f"- OS: {m['os']} ({m['platform'][:60]})",
        f"- Python: {m['python']}",
        f"- CPU cores: {m['cpu_count']}",
        "",
        "## Results",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total events | {metrics['total_events']:,} |",
        f"| Batch size | {metrics['batch_size']} |",
        f"| Parse errors | {metrics['parse_errors']} |",
        f"| Incidents detected | {metrics['incidents_detected']} |",
        f"| Generation time | {metrics['generation_time_s']:.3f}s |",
        f"| Parse time | {metrics['parse_time_s']:.3f}s |",
        f"| Detection time | {metrics['detection_time_s']:.3f}s |",
        f"| **Total time** | **{metrics['total_time_s']:.3f}s** |",
        f"| **Ingest rate** | **{metrics['ingest_rate_per_s']:,} events/s** |",
    ]
    if metrics["peak_memory_mb"] is not None:
        lines.append(f"| Peak memory | {metrics['peak_memory_mb']} MB |")

    lines += [
        "",
        "> [!NOTE]",
        "> SIMULATION: synthetic events only. Detection pipeline runs in-process without database.",
        "> Real ingest rate with SQLite persistence will be lower.",
    ]

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"Performance report written to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentGuard load test (SIMULATION)")
    parser.add_argument("--count", type=int, default=10000, help="Number of events (default 10000)")
    parser.add_argument("--batch-size", type=int, default=100, help="Batch size (default 100)")
    args = parser.parse_args()

    print(f"[LOAD TEST] SIMULATION - synthetic data only", flush=True)
    metrics = run_load_test(args.count, args.batch_size)
    print(f"\nIngest rate: {metrics['ingest_rate_per_s']:,} events/s")
    print(f"Total time: {metrics['total_time_s']:.3f}s")
    print(f"Incidents: {metrics['incidents_detected']}")
    write_report(metrics)

