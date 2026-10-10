"""Shared Telegram public-channel configuration for scheduler and request scans.

Handles are candidates, not assertions of availability. Every configured channel
must be checked at runtime, and partial failures must remain visible in results.
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

# Existing Cyclothone defaults retained for compatibility. Upstream inventory
# labels are catalog metadata only; public reachability is verified per scan.
DEFAULT_PUBLIC_TELEGRAM_CHANNELS = (
    "gladdos69_official",
    "arvin_club",
    "cveNotify",
    "bugatti_cloud",
    "joker_reborn",
    "ObserverCloud",
    "darkstormteambackup2",
    "snatch_info",
    "bl00dy_Ransomware_Gang",
    "Stormous",
    "Openbullet",
    "Forum",
    "AresLoader",
    "opendataleaks",
    "baseleak",
    "NullLeak",
    "DWI_OFFICIAL",
    "DarkfeedNews",
    "txtbaseslog",
    "Developer_Astra",
    "darkside_hubb",
    "TXT_LOG_ALIEN",
    "LeakBase",
    "CodeBreachLab",
    "ExploitService",
)


def configured_telegram_channels() -> list[str]:
    """Resolve configured/default public usernames; reject invite/private URLs.

    An explicitly configured empty value intentionally disables the source.
    """
    configured = os.getenv("CYCLOTHONE_DW_TELEGRAM_CHANNELS")
    if configured is None:
        configured = os.getenv("SENTINEL_DW_TELEGRAM_CHANNELS")
    raw_channels = (
        list(DEFAULT_PUBLIC_TELEGRAM_CHANNELS)
        if configured is None
        else configured.split(",")
    )

    channels: list[str] = []
    seen: set[str] = set()
    for raw in raw_channels:
        value = raw.strip()
        if not value:
            continue
        if "://" in value or value.lower().startswith(("t.me/", "telegram.me/")):
            parsed = urlsplit(value if "://" in value else f"https://{value}")
            if (parsed.hostname or "").lower() not in {
                "t.me", "www.t.me", "telegram.me", "www.telegram.me"
            }:
                continue
            parts = [part for part in parsed.path.split("/") if part]
            if parts and parts[0].lower() == "s":
                parts = parts[1:]
            # Invite links and non-channel paths are intentionally excluded.
            if len(parts) != 1 or parts[0].startswith("+") or parts[0].lower() == "joinchat":
                continue
            value = parts[0]
        else:
            value = value.lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", value):
            continue
        key = value.lower()
        if key not in seen:
            seen.add(key)
            channels.append(value)
    return channels
