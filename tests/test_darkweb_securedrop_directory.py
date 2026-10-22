from __future__ import annotations

import json

import pytest

from cyclothone.darkweb.securedrop_directory import DIRECTORY_URL, parse_directory


def _entry(host: str, **updates):
    row = {
        "title": "Example Newsroom",
        "slug": "example-newsroom",
        "directory_url": "https://securedrop.org/directory/example-newsroom/",
        "landing_page_url": "https://example.org/securedrop/",
        "organization_url": "https://example.org/",
        "onion_address": host,
        "countries": ["Exampleland"],
        "languages": ["English"],
    }
    row.update(updates)
    return row


def test_parse_directory_keeps_v3_candidates_quarantined_and_untrusted():
    host = "a" * 56 + ".onion"
    rows = parse_directory(json.dumps([_entry(host)]).encode())
    assert len(rows) == 1
    row = rows[0]
    assert row["url"] == f"https://{host}/"
    assert row["status"] == "candidate"
    assert row["monitoring_enabled"] is False
    assert row["requires_tor_probe"] is True
    assert row["seed_type"] == "publisher_onion"
    assert row["probe_metadata"]["tor_reachability_verified"] is False
    assert row["probe_metadata"]["publisher_identity_verified"] is False
    assert row["probe_metadata"]["customer_matching_allowed"] is False
    assert row["discovered_from"] == DIRECTORY_URL


def test_parse_directory_rejects_invalid_hosts_duplicate_hosts_and_untrusted_provenance():
    host = "b" * 56 + ".onion"
    rows = parse_directory(json.dumps([
        _entry("short.onion"),
        _entry(host, directory_url="https://attacker.example/fake"),
        _entry(host),
        _entry(host),
    ]).encode())
    assert len(rows) == 1
    assert rows[0]["hostname"] == host


@pytest.mark.parametrize("body", [b"", b"not-json", b"{}", b'{"items": []}'])
def test_parse_directory_rejects_invalid_document_shape(body):
    with pytest.raises(ValueError):
        parse_directory(body)


def test_parse_directory_rejects_oversized_body():
    with pytest.raises(ValueError, match="body_size_invalid"):
        parse_directory(b"x" * (4_000_001))
