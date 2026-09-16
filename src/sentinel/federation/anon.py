from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit


class FederationAnonymizer:
    """Apply deterministic, one-way minimisation before intelligence leaves Sentinel.

    A dedicated secret is mandatory. There is deliberately no development/default
    salt: federation sharing must fail closed when the key is not configured.
    """

    def __init__(self, secret: bytes | None = None) -> None:
        raw = secret if secret is not None else os.getenv("SENTINEL_FED_SALT")
        if not raw:
            raise RuntimeError("SENTINEL_FED_SALT is required for federation anonymization")
        if len(raw.encode("utf-8")) < 32:
            raise RuntimeError("SENTINEL_FED_SALT must contain at least 32 bytes")
        self._secret = raw.encode("utf-8")

    def token(self, value: str, *, context: str) -> str:
        if not value:
            raise ValueError("value must not be empty")
        if not context or ":" in context:
            raise ValueError("context must be a non-empty federation namespace")
        digest = hmac.new(self._secret, f"{context}:{value}".encode(), hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"

    def email(self, value: str) -> str:
        local, sep, domain = value.strip().lower().partition("@")
        if not sep or not local or not domain or len(domain) > 253:
            raise ValueError("invalid email")
        # Internal/private domains must not be disclosed. Public domains remain
        # useful as classification context while the identity is one-way hashed.
        if "." not in domain or domain.endswith((".local", ".internal", ".localhost")):
            domain_ref = self.token(domain, context="email-domain")
        else:
            domain_ref = domain
        return f"{self.token(local, context='email-local')}@{domain_ref}"

    def ip(self, value: str) -> str:
        address = ipaddress.ip_address(value.strip())
        if address.version == 4:
            network = ipaddress.ip_network(f"{address}/24", strict=False)
        else:
            network = ipaddress.ip_network(f"{address}/48", strict=False)
        return str(network.network_address) + ("/24" if address.version == 4 else "/48")

    def domain(self, value: str) -> str:
        domain = value.strip().lower().rstrip(".")
        if not domain or len(domain) > 253 or any(ch.isspace() for ch in domain):
            raise ValueError("invalid domain")
        labels = domain.split(".")
        if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
            raise ValueError("invalid domain")
        if any(label.startswith("-") or label.endswith("-") for label in labels):
            raise ValueError("invalid domain")
        if any(not all(c.isalnum() or c == "-" for c in label) for label in labels):
            raise ValueError("invalid domain")
        return domain

    def url(self, value: str) -> str:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("only HTTP(S) URLs are supported")
        host = self.domain(parsed.hostname) if "." in parsed.hostname else self.token(parsed.hostname, context="url-host")
        netloc = host
        if parsed.port is not None:
            if parsed.port not in (80, 443):
                raise ValueError("non-standard URL ports are not shareable")
            netloc = f"{host}:{parsed.port}"
        path = parsed.path or "/"
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))

    @staticmethod
    def timestamp(value: datetime) -> str:
        if value.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        value = value.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        return value.isoformat().replace("+00:00", "Z")

    @staticmethod
    def redact_metadata(metadata: dict[str, object]) -> dict[str, object]:
        """Remove tenant/device/user/credential material from outbound metadata."""
        forbidden = {"tenant_id", "device_id", "user_id", "access_token", "refresh_token", "cookie", "password", "secret", "api_key", "authorization"}
        return {k: v for k, v in metadata.items() if k.lower() not in forbidden}
