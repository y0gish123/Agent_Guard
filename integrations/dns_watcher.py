"""DNS log tailer and anomaly emitter for AgentGuard AI SOC.

Tails DNS_LOG_PATH ("ts client_ip domain" format).
Scores queried domains for lookalike / typosquat indicators using detection.phishing.scorer.
Emits dns_query events to /api/ingest/events and flags R_LOOKALIKE hits.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import time
from typing import Dict, List, Optional

import httpx

from shared.contracts import Event, EventType, Severity, Source
from detection.phishing.scorer import score_domain

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [DnsWatcher] %(message)s")
logger = logging.getLogger("dns_watcher")

DNS_LOG_PATH = Path(os.getenv("DNS_LOG_PATH", "dns_logs/dns.log")).resolve()
BACKEND_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")
STATE_FILE = Path(os.getenv("DNS_STATE_FILE", "integrations/dns_offsets.json")).resolve()


class DnsWatcher:
    def __init__(self, log_path: Path = DNS_LOG_PATH, backend_url: str = BACKEND_URL):
        self.log_path = log_path
        self.backend_url = backend_url
        self.offset = 0
        self.load_offset()

    def load_offset(self) -> None:
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.offset = data.get(str(self.log_path), 0)
            except Exception:
                pass

    def save_offset(self) -> None:
        try:
            STATE_FILE.parent.mkdir(exist_ok=True, parents=True)
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump({str(self.log_path): self.offset}, f, indent=2)
        except Exception as exc:
            logger.warning("Could not save DNS offset: %s", exc)

    def parse_dns_line(self, raw_line: str, line_no: int) -> Optional[Event]:
        """Line format: 'ts client_ip queried_domain' e.g. '2026-10-31T15:00:00Z 192.168.1.50 portal-update-fakelogin.org'"""
        parts = raw_line.strip().split()
        if len(parts) < 3:
            return None

        ts_str, client_ip, domain = parts[0], parts[1], parts[2]
        try:
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)

        is_lookalike, score, reasons = score_domain(domain)
        event_id = f"evt-dns-{hashlib.sha256(f'{domain}:{line_no}:{raw_line}'.encode()).hexdigest()[:8]}"
        severity = Severity.high if is_lookalike else Severity.low

        attrs = {
            "domain": domain,
            "client_ip": client_ip,
            "lookalike_score": score,
            "is_lookalike": is_lookalike,
        }
        if is_lookalike:
            attrs["rule_flag"] = "R_LOOKALIKE"
            attrs["reasons"] = "; ".join(reasons)

        return Event(
            event_id=event_id,
            timestamp=dt,
            source=Source.collector,
            host_id=client_ip,
            user_id=None,
            event_type=EventType.dns_query,
            severity=severity,
            raw_event_ref=f"dns.log#{line_no}",
            attributes=attrs,
            schema_version="1.0",
        )

    def tail(self) -> List[Event]:
        if not self.log_path.exists():
            return []

        events: List[Event] = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                f.seek(self.offset)
                line_no = 1
                while True:
                    line = f.readline()
                    if not line:
                        break
                    ev = self.parse_dns_line(line, line_no)
                    if ev:
                        events.append(ev)
                    line_no += 1
                self.offset = f.tell()
        except Exception as exc:
            logger.error("Error reading %s: %s", self.log_path, exc)

        return events

    def forward(self, events: List[Event]) -> bool:
        if not events:
            return True
        payload = [e.model_dump(mode="json") for e in events]
        url = f"{self.backend_url}/api/ingest/events"
        try:
            with httpx.Client(timeout=4.0) as client:
                r = client.post(url, json=payload)
                if r.status_code == 200:
                    logger.info("Forwarded %d DNS query events to SOC.", len(events))
                    return True
        except Exception as exc:
            logger.warning("Could not forward DNS events: %s", exc)
        return False

    def run(self, once: bool = False, poll_interval: float = 2.0) -> None:
        logger.info("DNS watcher monitoring %s", self.log_path)
        while True:
            evs = self.tail()
            if evs:
                if self.forward(evs):
                    self.save_offset()
            if once:
                break
            time.sleep(poll_interval)


if __name__ == "__main__":
    watcher = DnsWatcher()
    watcher.run()

