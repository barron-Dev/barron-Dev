from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def new_client_credentials() -> tuple[str, str, str]:
    client_id = "snc_" + b64(secrets.token_bytes(24))
    secret = "sns_" + b64(secrets.token_bytes(32))
    return client_id, secret, hash_secret(secret)


def new_token(prefix: str) -> tuple[str, str]:
    token = prefix + b64(secrets.token_bytes(48))
    return token, hash_secret(token)


def verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    if method == "plain":
        return secrets.compare_digest(verifier, challenge)
    if method == "S256":
        return secrets.compare_digest(b64(hashlib.sha256(verifier.encode()).digest()), challenge)
    return False


def expires(hours: int) -> datetime:
    return datetime.now(UTC) + timedelta(hours=hours)
