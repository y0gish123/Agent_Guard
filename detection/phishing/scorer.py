"""Phishing and Lookalike domain heuristic scorer for AgentGuard."""

import re
from typing import Any, Dict, List, Optional, Tuple

LEGIT_DOMAINS = ["clinic.org", "microsoft.com", "google.com", "office.com"]

SUSPICIOUS_KEYWORDS = [
    (r"password|credential|reset", "R_CREDENTIAL", "Credential harvesting language detected."),
    (r"urgent|immediate|suspended|action required|within 24 hours", "R_URGENT", "High-pressure or urgent language detected."),
    (r"verify your account|login portal|re-authenticate", "R_VERIFY", "Call-to-action requesting login verification."),
]

LOOKALIKE_PATTERNS = [
    re.compile(r"fakelogin|portal-update|login-verify|secure-login", re.IGNORECASE),
    re.compile(r"c1inic|c-linic|clinic-portal|clinic-support", re.IGNORECASE),
    re.compile(r"micros0ft|paypa1|goog1e", re.IGNORECASE),
]


def score_domain(domain: str) -> Tuple[bool, int, List[str]]:
    """Evaluate whether a domain is a lookalike/typosquat."""
    clean_domain = domain.lower().strip()
    score = 0
    reasons = []

    for legit in LEGIT_DOMAINS:
        if clean_domain == legit:
            return False, 0, []

    for pat in LOOKALIKE_PATTERNS:
        if pat.search(clean_domain):
            score += 50
            reasons.append(f"Domain '{clean_domain}' matches known typosquatting / lookalike pattern.")
            break

    # Check excessive hyphens / suspicious TLDs
    if clean_domain.count("-") >= 2:
        score += 20
        reasons.append("Domain contains multiple hyphens indicative of phishing spoofing.")

    is_lookalike = score >= 40
    return is_lookalike, score, reasons


def score_message(text: str, sender: Optional[str] = None, reply_to: Optional[str] = None) -> Dict[str, Any]:
    """Score an email or text message for phishing indicators."""
    score = 0
    reasons = []

    clean_text = text or ""
    clean_sender = (sender or "").lower()
    clean_reply_to = (reply_to or "").lower()

    # Check keywords
    for pat, code, msg in SUSPICIOUS_KEYWORDS:
        if re.search(pat, clean_text, re.IGNORECASE):
            score += 25
            m = re.search(pat, clean_text, re.IGNORECASE)
            snippet = clean_text[max(0, m.start() - 20):min(len(clean_text), m.end() + 20)] if m else ""
            reasons.append({"code": code, "text": msg, "snippet": snippet})

    # Check sender mismatch with reply-to
    if clean_sender and clean_reply_to and clean_sender != clean_reply_to:
        score += 30
        reasons.append({
            "code": "R_SENDER_MISMATCH",
            "text": "Sender and Reply-To addresses do not match.",
            "snippet": f"Sender: {clean_sender}, Reply-To: {clean_reply_to}",
        })

    # Check for lookalike domains in text
    domain_matches = re.findall(r"https?://([a-zA-Z0-9.-]+)", clean_text)
    for d in domain_matches:
        is_lookalike, d_score, d_reasons = score_domain(d)
        if is_lookalike:
            score += d_score
            reasons.append({
                "code": "R_LOOKALIKE",
                "text": f"Lookalike domain found: {d}",
                "snippet": d,
            })

    # Verdict mapping
    if score >= 60:
        verdict = "red"
    elif score >= 25:
        verdict = "amber"
    else:
        verdict = "green"

    return {
        "verdict": verdict,
        "score": min(score, 100),
        "reasons": reasons,
    }

