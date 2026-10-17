"""Safe, provenance-first identity graph primitives for Cyclothone.

This module does not collect data or assert that two accounts belong to the
same person. It canonicalizes identifiers and produces explainable candidate
scores for an authorized analyst to review.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

SUPPORTED_ENTITY_TYPES = {
    "person", "organization", "social_account", "email", "phone", "username",
    "ip_address", "domain", "telegram_channel", "breach_record", "image_reference",
}
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def canonicalize(entity_type: str, value: str) -> str:
    """Normalize an identifier without attempting fuzzy identity inference."""
    kind = entity_type.strip().lower()
    if kind not in SUPPORTED_ENTITY_TYPES:
        raise ValueError("unsupported_entity_type")
    raw = " ".join(value.strip().split())
    if not raw or len(raw) > 1000:
        raise ValueError("invalid_identifier")

    if kind == "domain":
        candidate = raw.lower().rstrip(".")
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        if not candidate or "." not in candidate or any(c.isspace() for c in candidate):
            raise ValueError("invalid_domain")
        return candidate
    if kind == "email":
        if raw.count("@") != 1:
            raise ValueError("invalid_email")
        local, domain = raw.rsplit("@", 1)
        if not local or not domain or "." not in domain:
            raise ValueError("invalid_email")
        return f"{local.casefold()}@{domain.rstrip('.').casefold()}"
    if kind == "ip_address":
        try:
            return ipaddress.ip_address(raw).compressed
        except ValueError as exc:
            raise ValueError("invalid_ip_address") from exc
    if kind == "phone":
        digits = re.sub(r"[^0-9+]", "", raw)
        if len(digits.lstrip("+")) < 7 or len(digits) > 16:
            raise ValueError("invalid_phone")
        return digits
    if kind == "username":
        return raw.removeprefix("@").casefold()
    if kind == "telegram_channel":
        return raw.removeprefix("@").casefold()
    if kind == "social_account":
        candidate = raw if "://" in raw else f"https://{raw}"
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("invalid_profile_url")
        host = parsed.hostname.casefold().rstrip(".")
        path = parsed.path.rstrip("/")
        return urlunsplit(("https", host, path, "", ""))
    return raw.casefold()


def identifier_hash(canonical_value: str) -> str:
    """Return a stable SHA-256 digest for indexed identifier matching."""
    value = canonical_value.strip()
    if not value:
        raise ValueError("empty_identifier")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# Signals are deliberately explicit and auditable. Visual similarity, facial
# recognition, writing-style inference, follower graphs, and shared IP alone
# are not valid grounds for asserting that accounts are the same person.
_SIGNAL_WEIGHTS = {
    "customer_attested_link": 0.92,
    "verified_domain_control": 0.90,
    "same_verified_public_profile_url": 0.95,
    "exact_verified_email": 0.88,
    "exact_username": 0.35,
    "shared_email_domain": 0.15,
    "same_display_name": 0.08,
}
_STRONG_SIGNALS = {
    "customer_attested_link",
    "verified_domain_control",
    "same_verified_public_profile_url",
    "exact_verified_email",
}


def score_identity_link(signals: list[str]) -> dict[str, object]:
    """Return an explainable candidate score; never auto-confirm SAME_PERSON."""
    unique = list(dict.fromkeys(signals))
    unknown = [signal for signal in unique if signal not in _SIGNAL_WEIGHTS]
    if unknown:
        raise ValueError(f"unsupported_identity_signals:{','.join(unknown)}")

    # Combine independent supported signals while capping weak-only evidence.
    remaining = 1.0
    for signal in unique:
        remaining *= 1.0 - _SIGNAL_WEIGHTS[signal]
    confidence = 1.0 - remaining
    has_strong = any(signal in _STRONG_SIGNALS for signal in unique)
    if not has_strong:
        confidence = min(confidence, 0.49)

    return {
        "confidence": round(confidence, 3),
        "confidence_percent": round(confidence * 100, 1),
        "review_state": "needs_review" if confidence >= 0.45 else "unreviewed",
        "signals": unique,
        "auto_confirmed": False,
    }


def validate_content_hash(value: str) -> str:
    """Validate a SHA-256 hex digest used to deduplicate evidence records."""
    normalized = value.strip().lower()
    if not _HEX_64.fullmatch(normalized):
        raise ValueError("invalid_content_hash")
    return normalized
