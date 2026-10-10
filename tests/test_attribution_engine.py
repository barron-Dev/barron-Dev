from datetime import UTC, datetime, timedelta

from cyclothone.attribution.engine import (
    ATTRIBUTION_WEIGHTS, ActorProfile, AttributionEvidence, build_diamond_model,
    compute_attribution, extract_behavioural_fingerprint, map_kill_chain_phase, map_unified_kill_chain_phase,
    validate_attack_techniques, validate_capec_ids,
)


def test_weights_sum_to_one_and_infrastructure_is_heaviest():
    assert round(sum(ATTRIBUTION_WEIGHTS.values()), 8) == 1.0
    assert ATTRIBUTION_WEIGHTS["infrastructure"] == max(ATTRIBUTION_WEIGHTS.values())


def test_diamond_model_always_has_four_vertices_and_marks_unknown():
    result = build_diamond_model({"infrastructure": {"domains": ["EXAMPLE.COM"]}})
    assert set(result) == {"adversary", "capability", "infrastructure", "victim"}
    assert result["infrastructure"]["domains"] == ["example.com"]
    assert result["adversary"]["status"] == "unknown"


def test_attack_technique_ids_and_kill_chain_mapping():
    assert validate_attack_techniques(["T1566.001", "T1059.001", "nonsense", "T9999"]) == ["T1059.001", "T1566.001", "T9999"]
    assert map_kill_chain_phase(["c2_infrastructure", "credential_dump"]) == ["command_and_control", "actions_on_objectives"]


def test_capec_validation_and_unified_kill_chain_mapping():
    assert validate_capec_ids(["CAPEC-66", "capec-66", "CAPEC-XYZ"]) == ["CAPEC-66"]
    assert map_unified_kill_chain_phase(["stealer_log", "c2_domain"]) == ["command_and_control", "credential_access"]


def test_missing_signals_do_not_create_confidence():
    result = compute_attribution(AttributionEvidence(), ActorProfile(actor_id="a-1", primary_name="Example Actor"))
    assert result["score"] == 0
    assert result["tier"] == "INSUFFICIENT"
    assert result["analyst_review_required"] is True


def test_high_score_without_independent_sources_is_downgraded():
    evidence = AttributionEvidence(
        infrastructure={"domains": ["shared.example"], "ips": ["192.0.2.4"]},
        attack_techniques=["T1059.001"], aliases=["handle-x"],
        independent_sources=["source-one"],
    )
    profile = ActorProfile(actor_id="a-1", primary_name="Example Actor", infrastructure={"domains": ["shared.example"], "ips": ["192.0.2.4"]}, attack_techniques=["T1059.001"], aliases=["handle-x"])
    result = compute_attribution(evidence, profile)
    assert result["raw_score_tier"] in {"CONFIRMED", "SUSPECTED", "POSSIBLE"}
    assert result["tier"] in {"POSSIBLE", "INSUFFICIENT"}
    assert "fewer_than_two_independent_sources" in result["guardrail_reasons"]


def test_confidence_never_claims_person_identity_and_requires_review():
    evidence = AttributionEvidence(
        infrastructure={"domains": ["c2.example"]}, attack_techniques=["T1059.001"],
        independent_sources=["source-one", "source-two"], source_evidence_ids=["ev1", "ev2"],
    )
    profile = ActorProfile(actor_id="actor-2", primary_name="Campaign cluster", infrastructure={"domains": ["c2.example"]}, attack_techniques=["T1059.001"])
    result = compute_attribution(evidence, profile)
    assert result["analyst_review_required"] is True
    assert "person" not in result["reporting_language"].lower()


def test_behavioural_fingerprint_is_privacy_minimized():
    now = datetime.now(UTC)
    result = extract_behavioural_fingerprint({"timestamps": [now.isoformat(), (now - timedelta(hours=1)).isoformat()], "messages": ["hello world", "another sample"], "hosting_providers": ["Example Hosting"]})
    assert result["message_count"] == 2
    assert "hello world" not in str(result)
    assert result["hosting_providers"] == ["example hosting"]
    assert result["limitations"]
