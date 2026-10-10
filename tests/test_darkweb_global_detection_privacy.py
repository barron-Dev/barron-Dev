from cyclothone.api.routes.darkweb import _sanitize_global_detection


def test_global_detection_redacts_identifier_context_and_source_url():
    row = {
        "id": 7,
        "tenant_id": None,
        "kind": "email",
        "matched_value": "person@example.com",
        "context": "password=secret123 found in paste",
        "source_url": "https://example.invalid/private-paste",
        "source_metadata": {
            "exposure_layer": "surface",
            "published": "2026-10-01",
            "domain": "customer.example",
            "victim_name": "Customer Name",
            "paste_id": "abc123",
            "nested": {"raw": "sensitive"},
        },
    }

    result = _sanitize_global_detection(row)

    assert result["matched_value"] == "[redacted]"
    assert "secret123" not in result["context"]
    assert result["source_url"] is None
    assert result["source_metadata"] == {
        "exposure_layer": "surface",
        "published": "2026-10-01",
        "paste_id": "abc123",
    }
    assert row["matched_value"] == "person@example.com"


def test_global_detection_sanitizer_keeps_only_scalar_allowlisted_metadata():
    result = _sanitize_global_detection({
        "tenant_id": None,
        "matched_value": "token-value",
        "source_metadata": {
            "group": "reported-group",
            "breach": "ExampleBreach",
            "channel": "public-channel",
            "domain": "sensitive.example",
            "nested": ["raw"],
        },
    })

    assert result["source_metadata"] == {
        "group": "reported-group",
        "breach": "ExampleBreach",
        "channel": "public-channel",
    }
