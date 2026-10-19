"""Fail-closed URL and outcome policy for Cyclothone's DW discovery worker.

This module does not fetch sources or claim jobs. The runtime must call these
validators before every request and every redirect, and route onion traffic
through a separately verified Tor proxy.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit


_ONION_V3 = re.compile(r"^[a-z2-7]{56}\.onion$", re.IGNORECASE)


class SourceOutcome(StrEnum):
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    EMPTY = "empty"
    INSPECTED_NO_MATCH = "inspected_no_match"
    MATCHED = "matched"


@dataclass(frozen=True)
class URLDecision:
    allowed: bool
    reason: str
    host: str | None = None
    requires_tor: bool = False


def validate_candidate_url(value: str, *, tor_configured: bool) -> URLDecision:
    """Validate a URL before fetch; DNS/IP checks must be repeated at connect time."""
    if not isinstance(value, str) or not value or len(value) > 4096:
        return URLDecision(False, "invalid_url")
    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").rstrip(".").lower()
        _ = parsed.port  # Force malformed-port validation.
    except (ValueError, UnicodeError):
        return URLDecision(False, "malformed_url")

    if scheme not in {"http", "https"} or not host:
        return URLDecision(False, "scheme_or_host_not_allowed")
    if parsed.username is not None or parsed.password is not None:
        return URLDecision(False, "embedded_credentials_forbidden")
    # This collector is for public web content, not arbitrary TCP services.
    if parsed.port is not None and parsed.port not in {80, 443}:
        return URLDecision(False, "non_web_port_forbidden", host)
    if parsed.fragment:
        # Fragments are not sent to servers; normalize away rather than reject.
        pass

    if host.endswith(".onion"):
        if not _ONION_V3.fullmatch(host):
            return URLDecision(False, "invalid_onion_hostname", host)
        if not tor_configured:
            return URLDecision(False, "tor_proxy_not_configured", host, True)
        return URLDecision(True, "onion_requires_tor", host, True)

    if host in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        return URLDecision(False, "local_or_metadata_host", host)

    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        # Hostname DNS resolution and every redirect must be validated at the
        # actual connection boundary to prevent DNS rebinding/SSRF.
        return URLDecision(True, "hostname_requires_connect_time_dns_validation", host)

    if not ip.is_global:
        return URLDecision(False, "non_public_ip_address", host)
    return URLDecision(True, "public_ip", host)


def normalize_outcome(
    *,
    response_received: bool,
    timed_out: bool = False,
    blocked: bool = False,
    inspected_content: bool = False,
    matched: bool = False,
    content_bytes: int = 0,
) -> SourceOutcome:
    """Prevent HTTP success alone from becoming a finding or inspected result."""
    if timed_out:
        return SourceOutcome.TIMEOUT
    if blocked:
        return SourceOutcome.BLOCKED
    if not response_received:
        return SourceOutcome.UNAVAILABLE
    if matched and inspected_content:
        return SourceOutcome.MATCHED
    if not inspected_content:
        return SourceOutcome.EMPTY if content_bytes == 0 else SourceOutcome.UNAVAILABLE
    return SourceOutcome.INSPECTED_NO_MATCH
