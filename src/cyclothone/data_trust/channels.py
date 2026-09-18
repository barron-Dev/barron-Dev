from __future__ import annotations

# Canonical channel vocabulary. The control plane deliberately does not assume
# that exfiltration means USB: every supported transport gets the same policy
# decision path, and unknown transports fail closed to review/block policy.

SOURCE_TYPES = frozenset({
    "endpoint", "browser", "cloud", "mobile", "server", "email",
    "messaging", "api", "network", "unknown",
})

DESTINATION_TYPES = frozenset({
    "endpoint", "usb", "bluetooth", "cloud", "browser", "network",
    "email", "messaging", "airdrop", "nearby_share", "wifi_direct", "nfc",
    "printer", "clipboard", "screen_share", "api", "removable_media",
    "vpn", "unknown",
})

# These are aliases emitted by endpoint integrations and normalized before
# policy evaluation. No platform-specific SDK is required by the policy layer.
_DESTINATION_ALIASES = {
    "flash_drive": "removable_media",
    "external_drive": "removable_media",
    "sd_card": "removable_media",
    "airdrop_peer": "airdrop",
    "nearby-share": "nearby_share",
    "wifi-direct": "wifi_direct",
    "screen-sharing": "screen_share",
    "im": "messaging",
    "chat": "messaging",
    "web_upload": "browser",
    "object_storage": "cloud",
}


def normalize_source(value: str) -> str:
    return _normalize(value, SOURCE_TYPES)


def normalize_destination(value: str) -> str:
    return _normalize(value, DESTINATION_TYPES)


def _normalize(value: str, supported: frozenset[str]) -> str:
    key = value.strip().lower().replace(" ", "_")
    key = _DESTINATION_ALIASES.get(key, key)
    return key if key in supported else "unknown"
