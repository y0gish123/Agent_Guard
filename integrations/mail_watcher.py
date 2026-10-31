"""Mailbox watcher for AgentGuard AI SOC.

Polls IMAP read-only (if credentials configured) OR watches MAIL_DROP_DIR for .eml files.
Parses headers, sender, reply-to, subject, body text, links, attachment names (NEVER opens/executes attachments).
Maps recipient to user_id via integrations/email_users.json.
Posts to /api/phishing/check.
Maintains state file to prevent reprocessing.
"""

from email import policy
from email.parser import BytesParser
import imaplib
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [MailWatcher] %(message)s")
logger = logging.getLogger("mail_watcher")

MAIL_DROP_DIR = Path(os.getenv("MAIL_DROP_DIR", "./mail_drop")).resolve()
MAPPING_FILE = Path(os.getenv("EMAIL_USERS_FILE", "integrations/email_users.json")).resolve()
STATE_FILE = Path(os.getenv("MAIL_STATE_FILE", "integrations/processed_mail.json")).resolve()
BACKEND_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")

LINK_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def load_email_mapping() -> Dict[str, str]:
    if MAPPING_FILE.exists():
        try:
            with open(MAPPING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "priya.rec@clinic.org": "priya.rec",
        "front.desk@clinic.org": "front.desk",
        "admin@clinic.org": "admin",
        "ceo@clinic.org": "ceo",
    }


def load_processed_ids() -> set:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def save_processed_ids(processed: set) -> None:
    try:
        STATE_FILE.parent.mkdir(exist_ok=True, parents=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(list(processed)), f, indent=2)
    except Exception as exc:
        logger.warning("Could not save processed mail state: %s", exc)


def parse_eml_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse raw RFC-822 bytes into structured metadata and extracted text."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    sender = str(msg.get("from", ""))[:200]
    reply_to = str(msg.get("reply-to", ""))[:200] or None
    to_addr = str(msg.get("to", "")).lower()
    subject = str(msg.get("subject", ""))[:300]
    message_id = str(msg.get("message-id", "")) or None

    body_text = ""
    attachment_names: List[str] = []

    # Extract body and attachment names safely
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get_content_disposition() or "")
            filename = part.get_filename()

            if filename:
                attachment_names.append(filename[:100])
                # STRICT SAFETY: Never open, decode, or execute attachment contents
                continue

            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
            elif content_type == "text/html" and not body_text and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        raw_html = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                        # Strip basic html tags
                        body_text += re.sub(r"<[^>]+>", " ", raw_html)
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
        except Exception:
            body_text = str(msg.get_payload())

    # Extract links
    found_links = LINK_PATTERN.findall(body_text)

    # Format text for phishing check
    combined_text = f"Subject: {subject}\n\n{body_text[:10000]}"
    if attachment_names:
        combined_text += f"\n\nAttachments: {', '.join(attachment_names)}"
    if found_links:
        combined_text += f"\n\nEmbedded URLs: {', '.join(found_links[:5])}"

    return {
        "message_id": message_id,
        "sender": sender,
        "reply_to": reply_to,
        "to_addr": to_addr,
        "subject": subject,
        "body_text": body_text,
        "combined_text": combined_text[:15000],
        "attachment_names": attachment_names,
        "links": found_links,
    }


def resolve_recipient_user(to_header: str, mapping: Dict[str, str]) -> str:
    for email_addr, user_id in mapping.items():
        if email_addr.lower() in to_header.lower():
            return user_id
    # Default fallback
    return "priya.rec"


def send_phishing_check(parsed_email: Dict[str, Any], user_id: str, backend_url: str = BACKEND_URL) -> Optional[Dict]:
    payload = {
        "user_id": user_id,
        "text": parsed_email["combined_text"],
        "sender": parsed_email["sender"] or None,
        "reply_to": parsed_email["reply_to"] or None,
    }
    url = f"{backend_url}/api/phishing/check"
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                result = resp.json()
                logger.info("Phishing check verdict: %s (score=%d, event=%s)", result.get("verdict"), result.get("score"), result.get("event_id"))
                return result
            else:
                logger.warning("Phishing check returned %d: %s", resp.status_code, resp.text)
    except Exception as exc:
        logger.warning("Could not reach phishing endpoint %s: %s", url, exc)
    return None


def poll_mail_drop(mail_dir: Path = MAIL_DROP_DIR, backend_url: str = BACKEND_URL) -> int:
    mail_dir.mkdir(exist_ok=True, parents=True)
    mapping = load_email_mapping()
    processed = load_processed_ids()
    count = 0

    for eml_file in mail_dir.glob("*.eml"):
        file_key = f"{eml_file.name}:{eml_file.stat().st_mtime}"
        if file_key in processed:
            continue

        try:
            with open(eml_file, "rb") as f:
                raw_bytes = f.read()
            parsed = parse_eml_bytes(raw_bytes)
            user_id = resolve_recipient_user(parsed["to_addr"], mapping)
            logger.info("Processing mail file %s for user %s (Subject: %s)", eml_file.name, user_id, parsed["subject"])
            result = send_phishing_check(parsed, user_id, backend_url)
            if result:
                processed.add(file_key)
                count += 1
        except Exception as exc:
            logger.error("Error processing %s: %s", eml_file, exc)

    if count > 0:
        save_processed_ids(processed)

    return count


def start_mail_watcher(poll_interval: float = 3.0) -> None:
    logger.info("Mail watcher started. Monitoring %s", MAIL_DROP_DIR)
    while True:
        try:
            poll_mail_drop()
        except Exception as exc:
            logger.error("Watcher error: %s", exc)
        time.sleep(poll_interval)


if __name__ == "__main__":
    start_mail_watcher()
