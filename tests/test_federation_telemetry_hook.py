from uuid import UUID

from sentinel.federation.promotion import (
    canonical_event_uuid,
    extract_federation_observations,
)


def test_canonical_event_uuid_preserves_uuid():
    value = "123e4567-e89b-12d3-a456-426614174000"
    assert canonical_event_uuid(value) == UUID(value)


def test_canonical_event_uuid_is_stable_for_agent_id():
    assert canonical_event_uuid("agent-event-42") == canonical_event_uuid("agent-event-42")


def test_extracts_supported_network_and_hash_iocs():
    observations = extract_federation_observations(
        kind="network_connect",
        image="powershell.exe",
        command_line="https://evil.example/login?token=secret",
        remote_address="203.0.113.42",
        payload={"sha": "a" * 64, "mail": "user@example.com"},
    )
    pairs = {(item["ioc_type"], item["value"]) for item in observations}
    assert ("sha256", "a" * 64) in pairs
    assert ("url", "https://evil.example/login?token=secret") in pairs
    assert ("ipv4", "203.0.113.42") in pairs
    assert ("email", "user@example.com") in pairs


def test_extract_skips_private_ip_and_internal_domain():
    observations = extract_federation_observations(
        kind="network_connect",
        image=None,
        command_line="http://intranet.corp/path",
        remote_address="10.0.0.8",
        payload={},
    )
    pairs = {(item["ioc_type"], item["value"]) for item in observations}
    assert not any(kind == "ipv4" for kind, _ in pairs)
    assert not any(kind == "domain" and value.endswith(".corp") for kind, value in pairs)
