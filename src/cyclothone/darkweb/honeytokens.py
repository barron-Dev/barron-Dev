from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

TOKEN_PREFIX = "cyc-canary-"
TOKEN_BYTES = 32
MAX_TOKEN_LABEL_LENGTH = 120


@dataclass(frozen=True, slots=True)
class Honeytoken:
    """One authorized canary; raw token is returned only at creation time."""

    token_id: str
    label: str
    token_sha256: str
    created_at: str


def create_honeytoken(label: str, *, token_id: str) -> tuple[Honeytoken, str]:
    """Create a high-entropy canary and return raw value exactly once to caller.

    Callers must display/store the raw token only in the authorized deployment
    workflow. Persist token_sha256, never the raw token.
    """
    clean_label = " ".join(str(label).split())
    if not clean_label or len(clean_label) > MAX_TOKEN_LABEL_LENGTH:
        raise ValueError("invalid_honeytoken_label")
    if not token_id or len(token_id) > 128:
        raise ValueError("invalid_honeytoken_id")
    raw = TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)
    record = Honeytoken(
        token_id=token_id,
        label=clean_label,
        token_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        created_at=datetime.now(UTC).isoformat(),
    )
    return record, raw


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def detect_honeytoken(text: str, token_hashes: dict[str, str]) -> list[str]:
    """Return IDs whose full exact token occurs in text, without returning token data.

    token_hashes maps token_id to SHA-256 digest. The detector intentionally
    verifies candidate substrings by digest and never emits the matched secret.
    """
    if not text or not token_hashes:
        return []
    matches: list[str] = []
    for token_id, digest in token_hashes.items():
        if not token_id or not isinstance(digest, str) or len(digest) != 64:
            continue
        # Tokens use a constrained alphabet; scan bounded candidate spans instead
        # of logging or persisting page text.
        start = 0
        while True:
            index = text.find(TOKEN_PREFIX, start)
            if index < 0:
                break
            end = index
            while end < len(text) and (text[end].isalnum() or text[end] in "-_"):
                end += 1
            candidate = text[index:end]
            if candidate and hmac.compare_digest(token_digest(candidate), digest):
                matches.append(token_id)
                break
            start = index + len(TOKEN_PREFIX)
    return matches
