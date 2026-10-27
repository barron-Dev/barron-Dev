from __future__ import annotations

import json

import pytest

from cyclothone.packs.compiler import (
    PackCompileError,
    build_pack,
    build_pack_file,
    load_pack,
    validate_pack,
)


VALID_PACK = {
    "schema_version": 1,
    "pack_id": "example-finance-eu",
    "industry": "financial_services",
    "sub_segment": "crypto_exchange",
    "geography": "eu",
    "asset_types": {
        "hot_wallet_infra": {"scope": "critical"},
        "cold_wallet_signer": {"scope": "critical", "observe_only": True},
    },
    "services_in_scope": {
        "required": ["darkweb.exposure", "identity.secrets"],
        "optional": ["third_party.supply_chain"],
    },
    "policy_pack": {"base": "regulated_financial", "overlays": ["eu_mica", "gdpr"]},
    "compliance_packs": ["mica", "dora", "gdpr"],
    "delivery_bindings": {
        "default": "webhook_mtls",
        "allowed": ["webhook_mtls", "api_poll"],
        "forbidden": ["public_webhook"],
    },
    "data_residency": {"default_region": "eu_west_1", "cross_border_forbidden": True},
    "retention": {"min_days": 1825, "worm": True},
    "approval": {"dual_control": True, "roles": ["compliance_officer", "ciso"]},
    "workflows": ["leaked_seed_phrase_to_incident"],
    "failure_tests": ["partial_coverage_is_not_clean"],
    "ttfvr_target_seconds": 900,
}


def test_compilation_is_deterministic_and_unresolved_is_preview() -> None:
    first = build_pack(VALID_PACK)
    second = build_pack(VALID_PACK)
    assert first["artifact_sha256"] == second["artifact_sha256"]
    assert first["publication_state"] == "preview"
    assert first["unresolved"]["required_services"] == [
        "darkweb.exposure",
        "identity.secrets",
    ]
    assert first["conformance"]["status"] == "not_run"


def test_resolved_pack_is_still_not_conformant() -> None:
    services = set(VALID_PACK["services_in_scope"]["required"] + VALID_PACK["services_in_scope"]["optional"])
    bindings = set(VALID_PACK["delivery_bindings"]["allowed"])
    artifact = build_pack(VALID_PACK, known_services=services, known_delivery_bindings=bindings)
    assert artifact["publication_state"] == "compiled_unconformed"
    assert artifact["unresolved"] == {
        "required_services": [],
        "optional_services": [],
        "delivery_bindings": [],
    }


def test_rejects_unknown_fields_and_bad_delivery_default() -> None:
    invalid = {**VALID_PACK, "industry_secret_override": True}
    with pytest.raises(PackCompileError, match="unknown_top_level_keys"):
        validate_pack(invalid)
    invalid = {**VALID_PACK, "delivery_bindings": {
        **VALID_PACK["delivery_bindings"], "default": "public_webhook"
    }}
    with pytest.raises(PackCompileError, match="default_delivery_not_allowed"):
        validate_pack(invalid)


def test_dual_control_requires_two_distinct_roles() -> None:
    invalid = {**VALID_PACK, "approval": {"dual_control": True, "roles": ["ciso"]}}
    with pytest.raises(PackCompileError, match="dual_control_requires_two_roles"):
        validate_pack(invalid)


def test_yaml_duplicate_keys_are_rejected(tmp_path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: 1\nschema_version: 1\n", encoding="utf-8")
    with pytest.raises(PackCompileError, match="duplicate_yaml_key"):
        load_pack(path)


def test_file_build_emits_reviewable_json_and_digest(tmp_path) -> None:
    source = tmp_path / "pack.yaml"
    output = tmp_path / "out" / "compiled.json"
    source.write_text(
        """
schema_version: 1
pack_id: example-finance-eu
industry: financial_services
sub_segment: crypto_exchange
geography: eu
asset_types:
  hot_wallet_infra:
    scope: critical
services_in_scope:
  required: [darkweb.exposure]
  optional: []
policy_pack:
  base: regulated_financial
  overlays: [gdpr]
compliance_packs: [gdpr]
delivery_bindings:
  default: webhook_mtls
  allowed: [webhook_mtls]
  forbidden: [public_webhook]
data_residency:
  default_region: eu_west_1
  cross_border_forbidden: true
retention:
  min_days: 365
  worm: true
approval:
  dual_control: true
  roles: [compliance_officer, ciso]
workflows: [exposure_to_incident]
failure_tests: [partial_coverage_is_not_clean]
ttfvr_target_seconds: 900
""",
        encoding="utf-8",
    )
    artifact = build_pack_file(source, output)
    on_disk = json.loads(output.read_text(encoding="utf-8"))
    assert on_disk["artifact_sha256"] == artifact["artifact_sha256"]
    assert on_disk["publication_state"] == "preview"


def test_three_exemplar_packs_validate_and_keep_unresolved_capabilities_visible() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    examples = [
        root / "packs/financial-services/crypto-exchange-eu.yaml",
        root / "packs/healthcare/hospital-us.yaml",
        root / "packs/developer/solo-developer.yaml",
    ]
    artifacts = [build_pack(load_pack(path)) for path in examples]
    assert [item["pack_id"] for item in artifacts] == [
        "crypto-exchange-eu",
        "hospital-us",
        "solo-developer",
    ]
    assert all(item["publication_state"] == "preview" for item in artifacts)
    assert all(item["conformance"]["status"] == "not_run" for item in artifacts)
    solo = load_pack(examples[2])
    assert "policy_pack" not in solo
    assert solo["controls"]["policy_pack_required"] is False
    hospital = load_pack(examples[1])
    assert hospital["asset_types"]["medical_device_credentials"]["observe_only"] is True
    assert hospital["controls"]["hipaa_breach_clock_days"] == 60
    crypto = load_pack(examples[0])
    assert crypto["asset_types"]["cold_wallet_signer"]["observe_only"] is True
