"""Mock tool state management and persistence."""

import copy
import json
import os
import threading
from typing import Any, Dict

INITIAL_ACCOUNTS = {
    "priya.rec": {"locked": False, "sessions_revoked": False},
    "ceo": {"locked": False, "sessions_revoked": False},
    "front.desk": {"locked": False, "sessions_revoked": False},
    "svc-backup": {"locked": False, "sessions_revoked": False},
}

INITIAL_HOSTS = {
    "clinic-pc-01": {"isolated": False},
    "clinic-pc-02": {"isolated": False},
    "db-server-01": {"isolated": False},
}


class MockStateManager:
    def __init__(self, filepath: str = "mock_state.json"):
        self.filepath = filepath
        self.lock = threading.Lock()
        self._state: Dict[str, Any] = {}
        self.reset()

    def reset(self) -> Dict[str, Any]:
        with self.lock:
            self._state = {
                "accounts": copy.deepcopy(INITIAL_ACCOUNTS),
                "hosts": copy.deepcopy(INITIAL_HOSTS),
                "blocked_ips": {},
            }
            self._save_to_disk()
            return copy.deepcopy(self._state)

    def get_state(self) -> Dict[str, Any]:
        with self.lock:
            return copy.deepcopy(self._state)

    def apply_action(self, action_type: str, target_id: str) -> Dict[str, Any]:
        with self.lock:
            clean_target = (target_id or "").strip().lower()
            accounts = self._state["accounts"]
            hosts = self._state["hosts"]

            if action_type == "lock_account":
                if clean_target in accounts:
                    accounts[clean_target]["locked"] = True
                else:
                    accounts[clean_target] = {"locked": True, "sessions_revoked": False}
                self._save_to_disk()
                return {"target": clean_target, "action": action_type, "locked": True}

            elif action_type == "revoke_session":
                if clean_target in accounts:
                    accounts[clean_target]["sessions_revoked"] = True
                else:
                    accounts[clean_target] = {"locked": False, "sessions_revoked": True}
                self._save_to_disk()
                return {"target": clean_target, "action": action_type, "sessions_revoked": True}

            elif action_type == "isolate_host":
                if clean_target in hosts:
                    hosts[clean_target]["isolated"] = True
                else:
                    hosts[clean_target] = {"isolated": True}
                self._save_to_disk()
                return {"target": clean_target, "action": action_type, "isolated": True}

            elif action_type == "block_ip":
                blocked = self._state.setdefault("blocked_ips", {})
                blocked[clean_target] = {"blocked": True}
                self._save_to_disk()
                return {"target": clean_target, "action": action_type, "blocked": True}

            else:
                raise ValueError(f"Unsupported action_type: {action_type}")

    def _save_to_disk(self):
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
        except Exception:
            pass

