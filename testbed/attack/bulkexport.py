"""Bulk Data Access and Exfiltration Simulator [SIMULATION].

Logs in as front.desk or priya.rec and rapidly views/exports 80 records to trigger D1.

Safety: Strictly localhost only. Max 30 HTTP requests (with bulk record parameters).
"""

import argparse
import sys
import time
import urllib.parse
import httpx


def verify_target(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if hostname not in ("localhost", "127.0.0.1"):
        print(f"[SIMULATION] ERROR: Target {url} is forbidden. Refusing non-localhost.")
        sys.exit(1)


def run_bulkexport(target_url: str = "http://localhost:8002", retry_after: int = 0) -> None:
    verify_target(target_url)
    print("\n" + "=" * 60)
    print(" [SIMULATION] Starting Bulk Data Access / Export Simulation")
    print(f" Target Site: {target_url}")
    print(" User:        front.desk")
    print(" Action:      Rapid record views and bulk export (80 records)")
    print(" Safety:      Localhost only.")
    print("=" * 60 + "\n")

    with httpx.Client(base_url=target_url, timeout=5.0) as client:
        # Step 1: Login
        resp_login = client.post("/login", json={"username": "front.desk", "password": "FrontDesk2026!"})
        if resp_login.status_code != 200:
            print(f"[SIMULATION] Login failed with status {resp_login.status_code}")
            return
        token = resp_login.json().get("token")
        headers = {"Authorization": f"Bearer {token}"}
        print(f"[SIMULATION] Authenticated as front.desk (Token: {token})")

        # Step 2: View 20 individual records rapidly
        print("[SIMULATION] Accessing patient charts...")
        for i in range(1, 21):
            client.get(f"/records/P-{1000 + i}", headers=headers)
            time.sleep(0.02)
        print("  [Completed] 20 individual records accessed.")

        # Step 3: Trigger bulk export of 80 records
        print("[SIMULATION] Initiating bulk export of 80 records...")
        resp_export = client.post("/export", json={"record_count": 80}, headers=headers)
        print(f"  [Export Status] {resp_export.status_code} (Exported 80 records)")

        if retry_after > 0:
            print(f"\n[SIMULATION] Waiting {retry_after}s for SOC response...")
            time.sleep(retry_after)
            resp = client.get("/records/P-1001", headers=headers)
            print(f"  [Post-Response Check] Status {resp.status_code}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bulk Export Simulator [SIMULATION]")
    parser.add_argument("--url", default="http://localhost:8002")
    parser.add_argument("--retry-after", type=int, default=0)
    args = parser.parse_args()
    run_bulkexport(args.url, args.retry_after)

