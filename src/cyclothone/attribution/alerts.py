from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _public_https_url(value: str) -> str:
    parts = urllib.parse.urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443):
        raise ValueError("webhook_requires_public_https_url")
    host = parts.hostname.rstrip(".").lower()
    allowed = {x.strip().lower() for x in (os.getenv("CYCLOTHONE_WEBHOOK_ALLOWED_HOSTS") or "").split(",") if x.strip()}
    if not allowed or host not in allowed:
        raise ValueError("webhook_host_not_allowlisted")
    try:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = {ipaddress.ip_address(record[4][0]) for record in records}
    except (OSError, ValueError) as exc:
        raise ValueError("webhook_dns_resolution_failed") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("webhook_host_must_resolve_only_to_public_addresses")
    return urllib.parse.urlunsplit(("https", parts.netloc, parts.path or "/", "", ""))


def sign_payload(secret: bytes, body: bytes, timestamp: str) -> str:
    return hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def deliver_signed_webhook(url: str, secret: bytes, payload: dict[str, Any], *, timeout_seconds: float = 5.0) -> dict[str, Any]:
    safe_url = _public_https_url(url)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    signature = sign_payload(secret, body, timestamp)
    request = urllib.request.Request(safe_url, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "Cyclothone-DW-Webhook/1.0",
        "X-Cyclothone-Timestamp": timestamp, "X-Cyclothone-Signature": "sha256=" + signature,
        "Idempotency-Key": str(payload.get("event_id") or payload.get("assessment_id") or hashlib.sha256(body).hexdigest()),
    })
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            status = int(response.status)
            return {"status": "delivered" if 200 <= status < 300 else "retryable_failure", "http_status": status}
    except urllib.error.HTTPError as exc:
        # Redirects are rejected to prevent a trusted endpoint redirecting into a private network.
        if 300 <= exc.code < 400:
            return {"status": "permanent_failure", "http_status": int(exc.code), "error_type": "redirect_rejected"}
        return {"status": "retryable_failure", "http_status": int(exc.code), "error_type": "http_error"}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"status": "retryable_failure", "error_type": type(exc).__name__}


async def deliver_signed_webhook_async(url: str, secret: bytes, payload: dict[str, Any]) -> dict[str, Any]:
    return await asyncio.to_thread(deliver_signed_webhook, url, secret, payload)
