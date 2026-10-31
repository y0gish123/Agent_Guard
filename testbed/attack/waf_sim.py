"""WAF simulator: writes ModSecurity-style audit log lines for localhost scenarios.

SIMULATION - this generates synthetic WAF log entries. Not connected to a real WAF.
Refuses to target any non-localhost host.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from typing import List

_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "clinic-web-01"}
_MAX_REQUESTS = 200

SAMPLE_ATTACKS = [
    {
        "uri": "/admin/login",
        "method": "POST",
        "action": "blocked",
        "rule_id": "941100",
        "rule_message": "XSS Attack Detected",
        "status": 403,
        "bytes": 512,
        "user_agent": "Mozilla/5.0 (Synthetic/SIMULATION)",
    },
    {
        "uri": "/patients/search?q=1' OR '1'='1",
        "method": "GET",
        "action": "blocked",
        "rule_id": "942100",
        "rule_message": "SQL Injection Attack",
        "status": 403,
        "bytes": 256,
        "user_agent": "sqlmap/1.7 (Synthetic/SIMULATION)",
    },
    {
        "uri": "/api/records",
        "method": "GET",
        "action": "allowed",
        "rule_id": "949110",
        "rule_message": "Inbound Anomaly Score Exceeded",
        "status": 200,
        "bytes": 4096,
        "user_agent": "Mozilla/5.0 (Synthetic/SIMULATION)",
    },
    {
        "uri": "/../../../etc/passwd",
        "method": "GET",
        "action": "blocked",
        "rule_id": "930100",
        "rule_message": "Path Traversal Attack",
        "status": 403,
        "bytes": 0,
        "user_agent": "curl/7.68.0 (Synthetic/SIMULATION)",
    },
]


def generate_waf_lines(target_host: str, count: int, client_ip: str) -> List[dict]:
    if target_host not in _ALLOWED_HOSTS:
        print(f"[SIMULATION] ERROR: Refusing non-localhost target '{target_host}'. Only localhost is permitted.", file=sys.stderr)
        sys.exit(1)

    count = min(count, _MAX_REQUESTS)
    lines = []
    for i in range(count):
        attack = SAMPLE_ATTACKS[i % len(SAMPLE_ATTACKS)]
        uid = f"sim-waf-{i:04d}"
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        entry = {
            "unique_id": uid,
            "timestamp": ts,
            "client_ip": client_ip,
            "uri": attack["uri"][:300],
            "method": attack["method"],
            "status": attack["status"],
            "action": attack["action"],
            "rule_id": attack["rule_id"],
            "rule_message": attack["rule_message"],
            "bytes": attack["bytes"],
            "host_id": target_host,
            "user_agent": attack["user_agent"],
        }
        lines.append(entry)
    return lines


def main():
    print("[SIMULATION] WAF simulator starting. This generates synthetic WAF log data only.", flush=True)

    parser = argparse.ArgumentParser(description="WAF attack simulator (SIMULATION ONLY, localhost only)")
    parser.add_argument("--host", default="localhost", help="Target host (must be localhost)")
    parser.add_argument("--count", type=int, default=5, help=f"Number of entries (max {_MAX_REQUESTS})")
    parser.add_argument("--client-ip", default="203.0.113.42", help="Synthetic attacker IP")
    parser.add_argument("--output", default="-", help="Output file path (- for stdout)")
    args = parser.parse_args()

    lines = generate_waf_lines(args.host, args.count, args.client_ip)

    output_lines = [json.dumps(line) for line in lines]
    output_text = "\n".join(output_lines) + "\n"

    if args.output == "-":
        print(output_text, end="")
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        print(f"[SIMULATION] Wrote {len(lines)} WAF log entries to {args.output}")


if __name__ == "__main__":
    main()

