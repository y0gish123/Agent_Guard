"""Account Takeover Attack Simulator [SIMULATION].

Simulates brute-force credential stuffing against priya.rec from external IP 203.0.113.50,
followed by successful sign-in and privilege escalation.

Safety: Strictly restricted to localhost (127.0.0.1/localhost). Max 30 requests.
"""

import argparse
import sys
import time
import urllib.parse
import httpx

MAX_REQUESTS = 30


def verify_target(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if hostname not in ("localhost", "127.0.0.1"):
        print(f"[SIMULATION] ERROR: Target {url} is forbidden. Simulator refuses any host except localhost/127.0.0.1.")
        sys.exit(1)


def run_takeover(target_url: str = "http://localhost:8002", retry_after: int = 0) -> None:
    verify_target(target_url)
    print("\n" + "=" * 60)
    print(" [SIMULATION] Starting Account Takeover Simulation")
    print(f" Target Site:   {target_url}")
    print(f" Target User:   priya.rec")
    print(" Source IP:     203.0.113.50 (Simulated via X-Demo-Source-IP)")
    print(" Safety:        Localhost only, request-capped.")
    print("=" * 60 + "\n")

    headers = {
        "X-Demo-Source-IP": "203.0.113.50",
        "Content-Type": "application/json",
    }

    requests_sent = 0

    with httpx.Client(base_url=target_url, timeout=5.0) as client:
        # Phase 1: 8 failed login attempts
        print("[SIMULATION] Phase 1: Sending 8 failed login attempts (brute-force)...")
        for i in range(1, 9):
            if requests_sent >= MAX_REQUESTS:
                break
            resp = client.post(
                "/login",
                json={"username": "priya.rec", "password": f"WrongPass{i}!"},
                headers=headers,
            )
            requests_sent += 1
            print(f"  [Attempt {i}/8] Status {resp.status_code} (Expected 401)")
            time.sleep(0.1)

        # Phase 2: 1 successful login
        if requests_sent < MAX_REQUESTS:
            print("\n[SIMULATION] Phase 2: Sending successful login with harvested credential...")
            resp = client.post(
                "/login",
                json={"username": "priya.rec", "password": "ClinicPass2026!"},
                headers=headers,
            )
            requests_sent += 1
            print(f"  [Success Login] Status {resp.status_code} (Expected 200), Token: {resp.json().get('token')}")

        # Phase 3: Privilege escalation
        if requests_sent < MAX_REQUESTS:
            print("\n[SIMULATION] Phase 3: Triggering privilege escalation to Administrator...")
            resp = client.post("/demo/escalate", json={"username": "priya.rec"}, headers=headers)
            requests_sent += 1
            print(f"  [Escalate Role] Status {resp.status_code} (Expected 200), Role: {resp.json().get('new_role')}")

        print("\n[SIMULATION] Attack simulation sequence completed.")

        # Phase 4: Retry after SOC response
        if retry_after > 0:
            print(f"\n[SIMULATION] Waiting {retry_after}s for SOC response to take effect...")
            time.sleep(retry_after)
            print("[SIMULATION] Attempting post-response login...")
            resp = client.post(
                "/login",
                json={"username": "priya.rec", "password": "ClinicPass2026!"},
                headers=headers,
            )
            print(f"  [Post-Response Login] Status {resp.status_code} ({'LOCKED (423) - SOC Policy Enforced' if resp.status_code == 423 else 'Still Open'})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Account Takeover Attack Simulator [SIMULATION]")
    parser.add_argument("--url", default="http://localhost:8002", help="Target site URL")
    parser.add_argument("--retry-after", type=int, default=0, help="Seconds to wait before testing response enforcement")
    args = parser.parse_args()

    run_takeover(args.url, args.retry_after)

