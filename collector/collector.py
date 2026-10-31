"""Log tailer and event forwarder for AgentGuard AI SOC."""

import json
import logging
import os
from pathlib import Path
import time
from typing import Dict, List, Optional
import yaml

import httpx

from collector.mapper import map_log_line_to_event
from collector.raw_archive import RawArchiveManager
from shared.contracts import Event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Collector] %(message)s")
logger = logging.getLogger("collector")

CONFIG_PATH = Path(os.getenv("COLLECTOR_CONFIG", "collector/config.yaml"))


class CollectorService:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.load_config()
        self.offsets: Dict[str, int] = {}
        self.load_offsets()
        self.archiver = RawArchiveManager()

    def load_config(self) -> None:
        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {
                "backend_url": os.getenv("API_URL", "http://localhost:8000"),
                "batch_interval_seconds": 1.0,
                "batch_size": 50,
                "offset_file": "collector/offsets.json",
                "logs": {
                    "auth": {"path": "site_logs/auth.log", "type": "auth"},
                    "access": {"path": "site_logs/access.log", "type": "access"},
                    "data": {"path": "site_logs/data.log", "type": "data"},
                },
            }

        self.backend_url = self.config.get("backend_url", "http://localhost:8000")
        self.batch_interval = float(self.config.get("batch_interval_seconds", 1.0))
        self.batch_size = int(self.config.get("batch_size", 50))
        self.offset_file = Path(self.config.get("offset_file", "collector/offsets.json"))

    def load_offsets(self) -> None:
        if self.offset_file.exists():
            try:
                with open(self.offset_file, "r", encoding="utf-8") as f:
                    self.offsets = json.load(f)
            except Exception:
                self.offsets = {}

    def save_offsets(self) -> None:
        try:
            self.offset_file.parent.mkdir(exist_ok=True, parents=True)
            with open(self.offset_file, "w", encoding="utf-8") as f:
                json.dump(self.offsets, f, indent=2)
        except Exception as exc:
            logger.warning("Could not save offsets: %s", exc)

    def tail_files(self) -> List[Event]:
        collected_events: List[Event] = []
        logs_cfg = self.config.get("logs", {})

        for log_key, log_info in logs_cfg.items():
            log_path = Path(log_info.get("path", ""))
            log_type = log_info.get("type", "auth")
            if not log_path.exists():
                continue

            last_offset = self.offsets.get(str(log_path), 0)

            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    f.seek(last_offset)
                    line_no = self.offsets.get(f"{log_path}_line", 1)

                    while True:
                        line = f.readline()
                        if not line:
                            break
                        # Archive raw line and get tamper-evident checksum ref
                        archive_ref, _ = self.archiver.archive_line(line, source_name=log_path.name)
                        event = map_log_line_to_event(log_type, line, log_path.name, line_no)
                        if event:
                            # Link to raw evidence archive
                            event.raw_event_ref = archive_ref
                            collected_events.append(event)
                        line_no += 1

                    self.offsets[str(log_path)] = f.tell()
                    self.offsets[f"{log_path}_line"] = line_no
            except Exception as exc:
                logger.warning("Error reading %s: %s", log_path, exc)

        return collected_events

    def forward_events(self, events: List[Event]) -> bool:
        if not events:
            return True

        payload = [e.model_dump(mode="json") for e in events]
        url = f"{self.backend_url}/api/ingest/events"

        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    logger.info("Forwarded %d events to SOC backend: %s", len(events), resp.json())
                    return True
                else:
                    logger.error("Backend error %d: %s", resp.status_code, resp.text)
                    return False
        except Exception as exc:
            logger.warning("Backend unreachable at %s: %s", url, exc)
            return False

    def run(self, once: bool = False) -> None:
        logger.info("Collector started. Tailing site logs -> %s", self.backend_url)
        backoff = 1.0

        while True:
            events = self.tail_files()
            if events:
                success = self.forward_events(events)
                if success:
                    self.save_offsets()
                    backoff = 1.0
                else:
                    # Exponential backoff up to 15s when backend is down
                    backoff = min(backoff * 1.5, 15.0)
                    logger.info("Retrying in %.1fs...", backoff)
                    time.sleep(backoff)
                    continue

            if once:
                break
            time.sleep(self.batch_interval)


if __name__ == "__main__":
    collector = CollectorService(CONFIG_PATH)
    collector.run()

