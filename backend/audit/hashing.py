"""Cryptographic hashing helpers for tamper-evident audit log."""

import hashlib
import json
from typing import Any, Dict

GENESIS_PREVIOUS_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """Produce deterministic canonical JSON representation."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_event_hash(previous_hash: str, payload: Dict[str, Any]) -> str:
    """Compute SHA256(previous_hash + canonical_json(payload))."""
    serialized = previous_hash + canonical_json(payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

