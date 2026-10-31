"""File monitoring service using watchdog for AgentGuard AI SOC.

Monitors demo_sandbox/ and aggregates file modifications into 5-second windows.
Emits file_change_burst events (event_id evt-3000+) and file_created for ransom notes.
POSTs events to /api/ingest/events.
"""

from collections import Counter
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Set

import httpx
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from shared.contracts import Event, EventType, Severity, Source
from detection.pipeline import is_restore_note_file

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [FileWatcher] %(message)s")
logger = logging.getLogger("filemon")

SANDBOX_DIR = Path(os.getenv("DEMO_SANDBOX_DIR", "demo_sandbox")).resolve()
BACKEND_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")
HOST_ID = os.getenv("HOST_ID", "clinic-pc-02")
CURRENT_USER = os.getenv("CURRENT_USER", "front.desk")


class FileBurstAggregator:
    def __init__(self, window_sec: float = 5.0, backend_url: str = BACKEND_URL):
        self.window_sec = window_sec
        self.backend_url = backend_url
        self.lock = threading.Lock()
        self.event_counter = 3000
        self.modified_files: Set[str] = set()
        self.new_extensions: Counter = Counter()
        self.note_files: List[str] = []
        self.last_flush = time.time()

    def record_change(self, path_str: str) -> None:
        with self.lock:
            p = Path(path_str)
            self.modified_files.add(path_str)
            if p.suffix:
                self.new_extensions[p.suffix.lower()] += 1

            if is_restore_note_file(p.name):
                self.note_files.append(path_str)

    def flush_window(self) -> List[Event]:
        events_to_send: List[Event] = []
        with self.lock:
            count = len(self.modified_files)
            if count == 0 and not self.note_files:
                self.last_flush = time.time()
                return []

            now_utc = datetime.now(timezone.utc)
            most_common_ext = self.new_extensions.most_common(1)[0][0] if self.new_extensions else ".unknown"

            # 1. Burst Event
            if count > 0:
                self.event_counter += 1
                burst_event = Event(
                    event_id=f"evt-{self.event_counter}",
                    timestamp=now_utc,
                    source=Source.collector,
                    host_id=HOST_ID,
                    user_id=CURRENT_USER,
                    event_type=EventType.file_change_burst,
                    severity=Severity.high if count >= 100 else Severity.medium,
                    raw_event_ref=f"fs-watchdog#{self.event_counter}",
                    attributes={
                        "files_changed": count,
                        "window_sec": self.window_sec,
                        "new_extension": most_common_ext,
                        "dir": str(SANDBOX_DIR),
                    },
                    schema_version="1.0",
                )
                events_to_send.append(burst_event)

            # 2. Note files created
            for n_path in self.note_files:
                self.event_counter += 1
                note_event = Event(
                    event_id=f"evt-{self.event_counter}",
                    timestamp=now_utc,
                    source=Source.collector,
                    host_id=HOST_ID,
                    user_id=CURRENT_USER,
                    event_type=EventType.file_created,
                    severity=Severity.high,
                    raw_event_ref=f"fs-watchdog#{self.event_counter}",
                    attributes={
                        "file_path": n_path,
                        "filename": Path(n_path).name,
                    },
                    schema_version="1.0",
                )
                events_to_send.append(note_event)

            # Reset window
            self.modified_files.clear()
            self.new_extensions.clear()
            self.note_files.clear()
            self.last_flush = time.time()

        return events_to_send

    def send_events(self, events: List[Event]) -> None:
        if not events:
            return
        payload = [e.model_dump(mode="json") for e in events]
        url = f"{self.backend_url}/api/ingest/events"
        try:
            with httpx.Client(timeout=4.0) as client:
                r = client.post(url, json=payload)
                if r.status_code == 200:
                    logger.info("Sent %d file burst events to SOC: %s", len(events), r.json())
        except Exception as exc:
            logger.warning("Could not forward file burst events: %s", exc)


class SandboxChangeHandler(FileSystemEventHandler):
    def __init__(self, aggregator: FileBurstAggregator):
        self.aggregator = aggregator

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.aggregator.record_change(event.src_path)

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self.aggregator.record_change(event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory and event.dest_path:
            self.aggregator.record_change(event.dest_path)


def start_file_watcher(sandbox_dir: Path = SANDBOX_DIR, window_sec: float = 5.0) -> None:
    sandbox_dir.mkdir(exist_ok=True, parents=True)
    aggregator = FileBurstAggregator(window_sec=window_sec)
    handler = SandboxChangeHandler(aggregator)

    observer = Observer()
    observer.schedule(handler, str(sandbox_dir), recursive=True)
    observer.start()
    logger.info("Watchdog file monitoring started on %s (window: %.1fs)", sandbox_dir, window_sec)

    try:
        while True:
            time.sleep(window_sec)
            events = aggregator.flush_window()
            if events:
                aggregator.send_events(events)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_file_watcher()

