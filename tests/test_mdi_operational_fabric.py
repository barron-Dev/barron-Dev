from cyclothone.mdi_ingestion.sovereignty_policy import (
    resolve_sovereignty_policy,
    pseudonymize_identifier,
    SovereigntyPolicyError,
)
from cyclothone.mdi_ingestion.threat_hash_registry import (
    build_hash_intel_record,
    ThreatHashError,
)
from cyclothone.mdi_ingestion.offline_response import plan_offline_response


def test_unverified_or_conflicting_jurisdiction_is_local_only():
    a = resolve_sovereignty_policy(
        country_candidates=["FR", "AE"], jurisdiction_verified=False
    )
    b = resolve_sovereignty_policy(
        country_candidates=["AE", "FR"], jurisdiction_verified=False
    )
    assert a == b
    assert a.transmission == "local_only"
    assert "device_fingerprint" not in a.allowed_fields


def test_verified_fr_minimizes_sensitive_fields():
    result = resolve_sovereignty_policy(
        country_candidates=["FR"], jurisdiction_verified=True
    )
    assert result.transmission == "minimized_fields_only"
    assert "raw_location" not in result.allowed_fields
    assert "device_fingerprint" not in result.allowed_fields


def test_tenant_hmac_pseudonyms_are_stable_and_keyed():
    first = pseudonymize_identifier("device-1", b"a" * 32)
    assert first == pseudonymize_identifier("device-1", b"a" * 32)
    assert first != pseudonymize_identifier("device-1", b"b" * 32)
    try:
        pseudonymize_identifier("device-1", b"short")
        assert False, "short tenant secrets must be rejected"
    except SovereigntyPolicyError:
        pass


def test_single_source_malware_claim_requires_provenance_review():
    result = build_hash_intel_record(
        app_sha256="a" * 64,
        verdict="malicious",
        source_ids=["one"],
        rule_version="v1",
    )
    assert result.confidence == 0
    assert result.action == "require_trusted_provenance_review_before_enforcement"


def test_hash_intel_is_order_independent_and_requires_valid_hash():
    first = build_hash_intel_record(
        app_sha256="a" * 64,
        verdict="malicious",
        source_ids=["two", "one"],
        rule_version="v1",
    )
    second = build_hash_intel_record(
        app_sha256="a" * 64,
        verdict="malicious",
        source_ids=["one", "two"],
        rule_version="v1",
    )
    assert first == second
    assert first.confidence == 0
    assert first.action == "require_trusted_provenance_review_before_enforcement"
    try:
        build_hash_intel_record(
            app_sha256="not-hash",
            verdict="benign",
            source_ids=[],
            rule_version="v1",
        )
        assert False, "invalid hashes must be rejected"
    except ThreatHashError:
        pass


def test_offline_response_is_deterministic_and_non_destructive():
    first = plan_offline_response(
        disposition="threat_detected",
        coverage="complete",
        corporate_container_available=True,
        key_invalidation_supported=True,
    )
    second = plan_offline_response(
        disposition="threat_detected",
        coverage="complete",
        corporate_container_available=True,
        key_invalidation_supported=True,
    )
    assert first == second
    assert "lock_cyclothone_corporate_container" in first.actions
    assert "wipe_personal_data" not in first.actions
    assert "kill_all_network" not in first.actions
