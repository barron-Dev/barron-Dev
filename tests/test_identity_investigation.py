from __future__ import annotations

import pytest

from cyclothone.identity_investigation import (
    build_integration_matrix,
    build_report,
    normalize_target,
    redact_summary,
)


def test_target_normalization_is_exact_and_canonical():
    assert normalize_target("domain", "HTTPS://Example.COM/path") == "example.com"
    assert normalize_target("email", " Alice@Example.COM ") == "alice@example.com"
    assert normalize_target("username", "@Alice") == "alice"
    assert normalize_target("phone", "+1 (415) 555-0123") == "+14155550123"
    assert normalize_target("ip", "192.0.2.1") == "192.0.2.1"
    assert normalize_target("executive_name", "Example Executive") == "example executive"


def test_unsupported_target_types_fail_closed():
    with pytest.raises(ValueError, match="unsupported_query_type"):
        normalize_target("photo", "image-reference")


def test_redaction_masks_secret_like_values():
    value = redact_summary("api_key=not-for-display access_token:also-not-for-display")
    assert "not-for-display" not in value
    assert "also-not-for-display" not in value
    assert "[REDACTED]" in value
    assert "api_key=not-for-display" not in value


def test_report_never_claims_fresh_collection_or_identity_attribution():
    report = build_report(
        target_kind="domain",
        canonical_target="example.com",
        watch_id="watch-1",
        findings=[],
        sources=[],
        requested_modules=["all"],
    )
    assert report["fresh_collection_performed"] is False
    assert report["identity_links"] == []
    assert report["status"] == "no_persisted_matches"
    assert report["risk_summary"]["identity_attribution"] == "not_assessed"
    assert report["integration_matrix"]


def test_integration_matrix_does_not_assume_unknown_stages_pass():
    matrix = build_integration_matrix([], evidence_count=0)
    assert {row["module"] for row in matrix} == {"darkweb", "breach", "code", "infra", "social"}
    assert all(row["automated_tests_pass"] == "not_verified" for row in matrix)
    assert all(row["production_e2e_verified"] is False for row in matrix)
    assert all(row["source_reachable"] == "not_probed" for row in matrix)


def test_source_aliases_are_mapped_without_claiming_live_reachability():
    matrix = build_integration_matrix(
        [{"id": "ransomwatch-main", "name": "Ransomwatch", "kind": "feed", "enabled": True,
          "last_status": "ok", "last_pull_at": "2026-10-09T10:00:00Z"}],
        evidence_count=0,
    )
    darkweb = next(row for row in matrix if row["module"] == "darkweb")
    assert darkweb["configured"] is True
    assert darkweb["last_collection_successful"] is True
    assert darkweb["source_reachable"] == "not_probed"
