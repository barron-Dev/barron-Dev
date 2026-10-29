from cyclothone.mdi_ingestion.sovereignty_policy import resolve_sovereignty_policy, pseudonymize_identifier, SovereigntyPolicyError
from cyclothone.mdi_ingestion.threat_hash_registry import build_hash_intel_record, ThreatHashError
from cyclothone.mdi_ingestion.offline_response import plan_offline_response

def test_unverified_or_conflicting_jurisdiction_is_local_only():
    a=resolve_sovereignty_policy(country_candidates=["FR","AE"],jurisdiction_verified=False)
    b=resolve_sovereignty_policy(country_candidates=["AE","FR"],jurisdiction_verified=False)
    assert a==b and a.transmission=="local_only"
    assert "device_fingerprint" not in a.allowed_fields

def test_verified_fr_minimizes_sensitive_fields():
    r=resolve_sovereignty_policy(country_candidates=["FR"],jurisdiction_verified=True)
    assert r.transmission=="minimized_fields_only"
    assert "raw_location" not in r.allowed_fields and "device_fingerprint" not in r.allowed_fields

def test_tenant_hmac_pseudonyms_are_stable_and_keyed():
    assert pseudonymize_identifier("device-1",b"a"*32)==pseudonymize_identifier("device-1",b"a"*32)
    assert pseudonymize_identifier("device-1",b"a"*32)!=pseudonymize_identifier("device-1",b"b"*32)
    try: pseudonymize_identifier("device-1",b"short"); assert False
    except SovereigntyPolicyError: pass

def test_single_source_malware_claim_does_not_trigger_quarantine():
    r=build_hash_intel_record(app_sha256="a"*64,verdict="malicious",source_ids=["one"],rule_version="v1")
    assert r.confidence==0 and r.action=="monitor_and_collect_evidence"

def test_hash_intel_is_order_independent_and_requires_valid_hash():
    a=build_hash_intel_record(app_sha256="a"*64,verdict="malicious",source_ids=["two","one"],rule_version="v1")
    b=build_hash_intel_record(app_sha256="a"*64,verdict="malicious",source_ids=["one","two"],rule_version="v1")
    assert a==b and a.confidence==0\n    assert a.action=="require_trusted_provenance_review_before_enforcement"
    try: build_hash_intel_record(app_sha256="not-hash",verdict="benign",source_ids=[],rule_version="v1"); assert False
    except ThreatHashError: pass

def test_offline_response_is_deterministic_and_non_destructive():
    a=plan_offline_response(disposition="threat_detected",coverage="complete",corporate_container_available=True,key_invalidation_supported=True)
    b=plan_offline_response(disposition="threat_detected",coverage="complete",corporate_container_available=True,key_invalidation_supported=True)
    assert a==b and "lock_cyclothone_corporate_container" in a.actions
    assert "wipe_personal_data" not in a.actions and "kill_all_network" not in a.actions
