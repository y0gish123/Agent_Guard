"""Raw evidence archival utility for AgentGuard AI SOC.

- Writes each accepted raw JSON line (bounded to 4 KB, sensitive keys redacted)
  to an append-only archive file per day under data/raw_archive/YYYY-MM-DD.jsonl
  with an accompanying checksum index data/raw_archive/YYYY-MM-DD.sha256.
- Enforces retention policies configured in environment or settings:
  RAW_RETENTION_DAYS, EVENT_RETENTION_DAYS.
- Never modifies or deletes audit logs or database audit chains.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, Optional, Tuple

ARCHIVE_DIR = Path(os.getenv("RAW_ARCHIVE_DIR", "data/raw_archive"))
MAX_LINE_BYTES = 4096

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"pass(word)?", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"token", re.I),
    re.compile(r"api[_-]?key", re.I),
    re.compile(r"auth(orization)?", re.I),
    re.compile(r"cookie", re.I),
]


def redact_sensitive_data(obj: Any) -> Any:
    """Recursively redact sensitive keys and values from JSON-like dicts/lists."""
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            is_sensitive = any(pat.search(k) for pat in SENSITIVE_KEY_PATTERNS)
            if is_sensitive:
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_data(v)
        return redacted
    elif isinstance(obj, list):
        return [redact_sensitive_data(item) for item in obj]
    return obj


class RawArchiveManager:
    def __init__(self, archive_dir: Optional[Path] = None):
        self.archive_dir = archive_dir or ARCHIVE_DIR
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    def _get_archive_paths(self, dt: Optional[datetime] = None) -> Tuple[Path, Path]:
        if dt is None:
            dt = datetime.now(timezone.utc)
        date_str = dt.strftime("%Y-%m-%d")
        log_path = self.archive_dir / f"{date_str}.jsonl"
        idx_path = self.archive_dir / f"{date_str}.sha256"
        return log_path, idx_path

    def archive_line(
        self,
        raw_text: str,
        source_name: str = "site_log",
        dt: Optional[datetime] = None,
    ) -> Tuple[str, str]:
        """Archive a raw line after redaction and bounding.

        Returns (archive_ref, sha256_checksum).
        archive_ref format: "archive://YYYY-MM-DD.jsonl#line_no"
        """
        if dt is None:
            dt = datetime.now(timezone.utc)

        log_path, idx_path = self._get_archive_paths(dt)

        # Parse and redact if JSON, else cap length
        capped_raw = raw_text.strip()
        try:
            parsed = json.loads(capped_raw)
            clean_parsed = redact_sensitive_data(parsed)
            bounded_text = json.dumps(clean_parsed, separators=(",", ":"))
        except Exception:
            bounded_text = capped_raw

        # Bound to MAX_LINE_BYTES
        bounded_bytes = bounded_text.encode("utf-8")[:MAX_LINE_BYTES]
        final_line = bounded_bytes.decode("utf-8", errors="ignore")

        checksum = hashlib.sha256(final_line.encode("utf-8")).hexdigest()

        # Count existing lines to determine line number
        line_no = 1
        if log_path.exists():
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                line_no = sum(1 for _ in f) + 1

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(final_line + "\n")

        with open(idx_path, "a", encoding="utf-8") as f:
            f.write(f"{line_no} {checksum}\n")

        archive_ref = f"archive://{log_path.name}#{line_no}"
        return archive_ref, checksum

    def verify_archive(self, date_str: str) -> Dict[str, Any]:
        """Verify checksums for a given day's archive."""
        log_path = self.archive_dir / f"{date_str}.jsonl"
        idx_path = self.archive_dir / f"{date_str}.sha256"

        if not log_path.exists() or not idx_path.exists():
            return {"ok": False, "error": "Archive or index file missing", "date": date_str}

        with open(idx_path, "r", encoding="utf-8") as f:
            expected = {}
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2:
                    expected[int(parts[0])] = parts[1]

        checked = 0
        with open(log_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                actual_ck = hashlib.sha256(line.rstrip("\r\n").encode("utf-8")).hexdigest()
                exp_ck = expected.get(idx)
                if exp_ck != actual_ck:
                    return {
                        "ok": False,
                        "error": f"Checksum mismatch at line {idx}",
                        "line": idx,
                        "expected": exp_ck,
                        "actual": actual_ck,
                    }
                checked += 1

        return {"ok": True, "checked_lines": checked, "date": date_str}

    def cleanup_old_archives(self, retention_days: int) -> int:
        """Remove archive files older than retention_days. Never touches audit chain."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        removed_count = 0
        for f in self.archive_dir.glob("*.jsonl"):
            try:
                date_str = f.stem
                file_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if file_date < cutoff_date:
                    f.unlink(missing_ok=True)
                    idx_file = self.archive_dir / f"{date_str}.sha256"
                    idx_file.unlink(missing_ok=True)
                    removed_count += 1
            except Exception:
                continue
        return removed_count

