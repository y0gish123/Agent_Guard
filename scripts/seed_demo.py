"""Seed demonstration events and incidents into AgentGuard AI SOC."""

import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import httpx
from backend.incidents.demo_data import get_scenario_data


def seed_demo(base_url: str = "http://localhost:8000", scenario: str = "all"):
    print(f"Connecting to AgentGuard backend at {base_url} (scenario: {scenario})...")
    events_raw, incidents_raw = get_scenario_data(scenario)

    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        # Ingest events
        print(f"Ingesting {len(events_raw)} demonstration events...")
        r_events = client.post("/api/ingest/events", json=events_raw)
        if r_events.status_code != 200:
            print(f"Error ingesting events: {r_events.text}")
            sys.exit(1)
        print("Events ingested successfully:", r_events.json())

        # Ingest incidents
        print(f"Ingesting {len(incidents_raw)} demonstration incidents...")
        r_inc = client.post("/api/ingest/incident-candidates", json=incidents_raw)
        if r_inc.status_code != 200:
            print(f"Error ingesting incidents: {r_inc.text}")
            sys.exit(1)
        print("Incidents ingested successfully:", r_inc.json())

        # Check funnel
        r_funnel = client.get("/api/funnel")
        print("Current Funnel counts:", r_funnel.json())
        print("Seeding complete.")


if __name__ == "__main__":
    target_url = os.getenv("API_URL", "http://localhost:8000")
    scen = sys.argv[1] if len(sys.argv) > 1 else "all"
    seed_demo(target_url, scen)
