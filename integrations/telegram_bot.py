"""Telegram bot integration for AgentGuard AI SOC.

Capabilities:
1. Users send or forward suspicious messages -> checks /api/phishing/check -> replies with RED/AMBER/GREEN, plain language reasons, and action guidance.
2. Polls open high/critical incidents every 5s -> broadcasts an alert with dashboard link.
3. Strict safety: input truncated to 2000 chars, never fetches external links, approvals exclusively in dashboard.
4. Exits with clear informational message if TELEGRAM_BOT_TOKEN is unset.
"""

import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Set

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [TelegramBot] %(message)s")
logger = logging.getLogger("telegram_bot")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
BACKEND_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:5173").rstrip("/")
USER_MAP_FILE = Path(os.getenv("TELEGRAM_USERS_FILE", "integrations/telegram_users.json")).resolve()


def load_chat_mapping() -> Dict[str, str]:
    if USER_MAP_FILE.exists():
        try:
            with open(USER_MAP_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"default_chat_id": "priya.rec"}


def format_phishing_reply(verdict: str, score: int, reasons: List[Dict[str, Any]]) -> str:
    """Format check result with RED/AMBER/GREEN and plain words."""
    if verdict == "red":
        icon_word = "🔴 RED: High Phishing Risk"
        guidance = "⚠️ What to do: DO NOT click any links, open attachments, or enter passwords. Please report this message to IT immediately."
    elif verdict == "amber":
        icon_word = "🟡 AMBER: Suspicious Indicators Found"
        guidance = "⚠️ What to do: Exercise extreme caution. Verify the sender through a known trusted channel before clicking or responding."
    else:
        icon_word = "🟢 GREEN: No Red Flags Found"
        guidance = "ℹ️ Note: No red flags found. This is not a guarantee that the message is safe. Always remain vigilant."

    reason_lines = []
    for r in reasons[:3]:
        text = r.get("text", "")
        if text:
            reason_lines.append(f"• {text}")

    if not reason_lines:
        reasons_text = "No obvious suspicious indicators matched."
    else:
        reasons_text = "\n".join(reason_lines)

    return (
        f"{icon_word}\n"
        f"Phishing Indicator Score: {score}/100\n\n"
        f"Key Observations:\n{reasons_text}\n\n"
        f"{guidance}"
    )


def handle_user_message(chat_id: str, text: str, backend_url: str = BACKEND_URL) -> str:
    """Process incoming user message, query phishing API, and return formatted reply."""
    # Truncate input to 2000 chars and do NOT fetch external links
    clean_text = (text or "").strip()[:2000]
    if not clean_text:
        return "Please send or forward the text of the message you wish to verify."

    chat_map = load_chat_mapping()
    user_id = chat_map.get(str(chat_id), "priya.rec")

    try:
        with httpx.Client(timeout=6.0) as client:
            resp = client.post(
                f"{backend_url}/api/phishing/check",
                json={"user_id": user_id, "text": clean_text},
            )
            if resp.status_code == 200:
                data = resp.json()
                return format_phishing_reply(data["verdict"], data["score"], data.get("reasons", []))
            else:
                return "AgentGuard SOC was unable to analyze the message at this moment. Please forward directly to your security officer."
    except Exception as exc:
        logger.warning("Error contacting phishing API: %s", exc)
        return "AgentGuard SOC service is temporarily offline. Please exercise caution."


class TelegramBotClient:
    def __init__(self, token: str, backend_url: str = BACKEND_URL, dashboard_url: str = DASHBOARD_URL):
        self.token = token
        self.backend_url = backend_url
        self.dashboard_url = dashboard_url
        self.api_base = f"https://api.telegram.org/bot{token}"
        self.last_update_id = 0
        self.alerted_incidents: Set[str] = set()

    def send_telegram_message(self, chat_id: str, text: str) -> bool:
        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.post(f"{self.api_base}/sendMessage", json={"chat_id": chat_id, "text": text})
                return r.status_code == 200
        except Exception as exc:
            logger.warning("Failed to send telegram message to %s: %s", chat_id, exc)
            return False

    def poll_updates(self) -> None:
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(
                    f"{self.api_base}/getUpdates",
                    params={"offset": self.last_update_id + 1, "timeout": 5},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for upd in data.get("result", []):
                        self.last_update_id = max(self.last_update_id, upd["update_id"])
                        msg = upd.get("message", {})
                        chat = msg.get("chat", {})
                        chat_id = str(chat.get("id", ""))
                        text = msg.get("text", "")
                        if chat_id and text:
                            reply = handle_user_message(chat_id, text, self.backend_url)
                            self.send_telegram_message(chat_id, reply)
        except Exception as exc:
            logger.debug("Error polling telegram updates: %s", exc)

    def poll_incidents_and_alert(self) -> None:
        """Poll open high/critical incidents and broadcast one alert per new/escalated incident."""
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(f"{self.backend_url}/api/incidents?status=open&limit=10")
                if resp.status_code != 200:
                    return
                incidents = resp.json().get("items", [])
                for inc in incidents:
                    inc_id = inc["incident_id"]
                    sev = inc["severity"]
                    if sev in ("high", "critical") and inc_id not in self.alerted_incidents:
                        self.alerted_incidents.add(inc_id)
                        alert_msg = (
                            f"🚨 AgentGuard SOC Alert: {sev.upper()} Incident Detected\n"
                            f"Title: {inc['title']}\n"
                            f"Category: {inc['category']}\n"
                            f"Affected Accounts: {', '.join(inc.get('affected_users', []))}\n"
                            f"Affected Hosts: {', '.join(inc.get('affected_hosts', []))}\n\n"
                            f"Review and authorize response actions in the SOC Dashboard:\n"
                            f"{self.dashboard_url}/#incidents\n\n"
                            f"(Note: Response approvals are performed exclusively in the SOC dashboard.)"
                        )
                        logger.info("Broadcasting incident alert for %s", inc_id)
                        # Broadcast to all registered chats
                        mapping = load_chat_mapping()
                        for c_id in mapping.keys():
                            if c_id != "default_chat_id":
                                self.send_telegram_message(c_id, alert_msg)
        except Exception as exc:
            logger.debug("Incident polling failed: %s", exc)


def run_telegram_bot() -> None:
    if not TELEGRAM_BOT_TOKEN:
        print("[TelegramBot] TELEGRAM_BOT_TOKEN environment variable is not configured.")
        print("[TelegramBot] Exiting gracefully. Set TELEGRAM_BOT_TOKEN to enable real-time Telegram integration.")
        sys.exit(0)

    bot = TelegramBotClient(TELEGRAM_BOT_TOKEN, BACKEND_URL, DASHBOARD_URL)
    logger.info("Telegram Bot service started with token ***%s", TELEGRAM_BOT_TOKEN[-4:])

    while True:
        bot.poll_updates()
        bot.poll_incidents_and_alert()
        time.sleep(5.0)


if __name__ == "__main__":
    run_telegram_bot()

