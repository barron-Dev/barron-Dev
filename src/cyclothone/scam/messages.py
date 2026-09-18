from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
PHONE_RE = re.compile(r"(?:\+|00)?\d[\d\s\-().]{6,}\d")
OTP_RE = re.compile(r"\b(?:otp|one[- ]?time|verification code|pin|code)\b", re.I)
AMOUNT_RE = re.compile(r"(?:aed|usd|eur|gbp|\$|€|£|₹|₦|kes|zar|ngn)\s?\d", re.I)
CRYPTO_RE = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
URGENCY_RE = re.compile(r"\b(?:urgent|immediately|within \d+ (?:min|minutes|hours)|last warning|expires|final notice)\b", re.I)
SENDER_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-_.]{2,10}$")

CATEGORY_PATTERNS: tuple[tuple[str, float, re.Pattern[str]], ...] = (
    ("otp_theft", 0.70, re.compile(r"\b(?:share|send|forward|tell me|give me)\b.{0,40}\b(?:otp|code|pin)\b", re.I | re.S)),
    ("bank_impersonation", 0.60, re.compile(r"\b(?:bank|account|card)\b.{0,60}\b(?:blocked|suspended|verify|update|kyc|limited)\b", re.I | re.S)),
    ("prize_scam", 0.55, re.compile(r"\b(?:won|winner|selected|lucky|prize|lottery|jackpot)\b", re.I)),
    ("investment", 0.55, re.compile(r"\b(?:guaranteed|risk[- ]?free|double your|high returns|\d+%\s?(?:daily|weekly|monthly))\b", re.I)),
    ("romance", 0.40, re.compile(r"\b(?:love|dear|honey|soulmate|met you|profile)\b", re.I)),
    ("tech_support", 0.60, re.compile(r"\b(?:microsoft|apple|windows|virus|hacked|remote access|anydesk|teamviewer)\b", re.I)),
    ("delivery", 0.50, re.compile(r"\b(?:parcel|package|shipment|courier|delivery)\b.{0,60}\b(?:fee|customs|pay|link)\b", re.I | re.S)),
    ("government_impersonation", 0.65, re.compile(r"\b(?:police|court|tax|tra|immigration|visa|fine|summons)\b", re.I)),
    ("crypto", 0.55, re.compile(r"\b(?:bitcoin|usdt|btc|eth|wallet|seed phrase|recovery phrase)\b", re.I)),
    ("sextortion", 0.75, re.compile(r"\b(?:webcam|recording|intimate|expose|publish|leak)\b.{0,80}\b(?:pay|bitcoin|btc|usdt)\b", re.I | re.S)),
    ("loan", 0.45, re.compile(r"\b(?:instant loan|no documents|pre[- ]?approved loan|loan approved)\b", re.I)),
    ("job_offer", 0.45, re.compile(r"\b(?:job offer|work from home|earn|salary|hiring)\b.{0,60}\b(?:fee|deposit|whatsapp|telegram)\b", re.I | re.S)),
)


@dataclass(frozen=True)
class MessageVerdict:
    score: float
    verdict: str
    category: str | None
    signals: list[dict[str, float | str]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    wallets: list[str] = field(default_factory=list)


def normalize(text: str) -> str:
    """Canonicalize text before hashing/training; never persist raw text by default."""
    t = text.lower()
    t = URL_RE.sub(" <url> ", t)
    t = PHONE_RE.sub(" <num> ", t)
    t = re.sub(r"\d+", " <n> ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:1000]


def text_hash(text: str) -> str:
    return hashlib.sha256(normalize(text).encode("utf-8")).hexdigest()


class MessageScamDetector:
    """Deterministic first-pass detector for SMS and messaging text.

    This is a signal generator, not a final policy engine. Production decisions
    can combine these signals with the existing URL scanner, reputation data,
    and a separately versioned ML model.
    """

    def analyze(self, text: str, sender: str | None = None) -> MessageVerdict:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("message text must be non-empty")

        signals: list[dict[str, float | str]] = []
        score = 0.0
        categories: list[tuple[str, float]] = []

        for category, weight, pattern in CATEGORY_PATTERNS:
            if pattern.search(text):
                categories.append((category, weight))
                signals.append({"name": f"cat:{category}", "weight": weight})
                score += weight

        if URGENCY_RE.search(text):
            signals.append({"name": "urgency", "weight": 0.20})
            score += 0.20

        if OTP_RE.search(text) and re.search(r"\b(?:share|send|tell|forward|give)\b", text, re.I):
            signals.append({"name": "otp_request", "weight": 0.50})
            score += 0.50

        if AMOUNT_RE.search(text):
            signals.append({"name": "amount_mentioned", "weight": 0.10})
            score += 0.10

        if sender and SENDER_ID_RE.fullmatch(sender) and not any(c.isdigit() for c in sender):
            signals.append({"name": "alphanumeric_sender", "weight": 0.15})
            score += 0.15

        urls = URL_RE.findall(text)
        wallets = CRYPTO_RE.findall(text)
        if wallets:
            signals.append({"name": "crypto_address", "weight": 0.35})
            score += 0.35
        if len(urls) > 2:
            signals.append({"name": "many_urls", "weight": 0.20})
            score += 0.20

        shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
        if any((urlsplit(url).hostname or "").lower() in shorteners for url in urls):
            signals.append({"name": "url_shortener", "weight": 0.15})
            score += 0.15

        score = min(score, 1.0)
        category = max(categories, key=lambda item: item[1])[0] if categories else None
        verdict = "malicious" if score >= 0.75 else "suspicious" if score >= 0.40 else "safe"
        return MessageVerdict(score, verdict, category, signals, urls, wallets)
