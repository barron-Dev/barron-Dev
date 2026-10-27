from __future__ import annotations

import copy
import json

import pytest

from cyclothone.packs.compiler import PackCompileError, compile_pack, load_pack


VALID_PACK = {
    "schema_version": "1.0",
    "pack_id": "crypto-exchange-eu",
    "industry": "financial-services",
    "sub_segment": "crypto-exchange",
    "geography": "eu",
    "developer_type": "enterprise_team",
    "asset_types": {
        "hot_wallet_infra": {"scope": "critical"},
        "cold_wallet_signer": {"scope": "critical", "observe_only": True},
        "liquidity_partner": {"scope": "high", "third_party": True},
    },
    "services_in_scope": {
        "required": ["darkweb.exposure", "identity.secrets"],
        "optional": ["third_party.supply_chain"],
    },
    "policy_pack": {"base": "regulated-financial", "overlays": ["eu-mica", "eu-dora"]},
    "compliance_packs": ["mica", "dora", "gdpr"],
    "delivery_bindings": {
        "default": "webhook_mtls",
        "allowed": ["webhook_mtls", "sse", "api_poll"],
        "forbidden": ["mqtt", "opc_ua", "public_webhook"],
    },
    "data_residency": {"default_region": "eu-west-1", "cross_border_forbidden": True},
    "retention": {"min_days": 1825, "worm": True},
    "approval": {"dual_control": True, "roles": ["compliance-officer", "ciso"]},
    "workflows": ["leaked-seed-phrase-to-incident"],
    "failure_tests": ["partial-coverage-is-not-clean", "observed-wallet-finding-does-not-trigger-actuation"],
    "ttfvr_target_seconds": 900,
}


def test_compilation_is_deterministic_and_explicitly_unverified() -> None:
    first = compile_pack(VALID_PACK)
    second = compile_pack(copy.deepcopy(VALID_PACK))
    assert first == second
    assert first["pack_id"] == "crypto-exchange-eu"
    assert first["compilation_state"] == "compiled_unverified"
    assert first["conformance"]["status"] == "not_run"
    assert all(binding["state"] == "declaration_only" for binding in first["primitive_bindings"])
    assert len(first["pack_sha256"]) == 64
    assert len(first["manifest_sha256"]) == 64


def test_compilation_normalizes_list_order_before_hashing() -> None:
    changed = copy.deepcopy(VALID_PACK)
    changed["compliance_packs"].reverse()
    changed["policy_pack"]["overlays"].reverse()
    assert compile_pack(changed)["pack_sha256"] == compile_pack(VALID_PACK)["pack_sha256"]


def test_unknown_root_key_fails_closed() -> None:
    changed = copy.deepcopy(VALID_PACK)
    changed["secret_override"] = True
    with pytest.raises(PackCompileError, match="unknown keys"):
        compile_pack(changed)


def test_default_delivery_cannot_be_forbidden_or_undeclared() -> None:
    changed = copy.deepcopy(VALID_PACK)
    changed["delivery_bindings"]["default"] = "public_webhook"
    with pytest.raises(PackCompileError, match="must be in"):
        compile_pack(changed)


def test_allowed_and_forbidden_delivery_sets_must_be_disjoint() -> None:
    changed = copy.deepcopy(VALID_PACK)
    changed["delivery_bindings"]["allowed"].append("public_webhook")
    with pytest.raises(PackCompileError, match="disjoint"):
        compile_pack(changed)


def test_dual_control_requires_two_distinct_roles() -> None:
    changed = copy.deepcopy(VALID_PACK)
    changed["approval"]["roles"] = ["ciso"]
    with pytest.raises(PackCompileError, match="at least two"):
        compile_pack(changed)


def test_required_and_optional_services_cannot_overlap() -> None:
    changed = copy.deepcopy(VALID_PACK)
    changed["services_in_scope"]["optional"].append("darkweb.exposure")
    with pytest.raises(PackCompileError, match="both required and optional"):
        compile_pack(changed)


def test_ttfvr_target_must_be_positive_integer() -> None:
    changed = copy.deepcopy(VALID_PACK)
    changed["ttfvr_target_seconds"] = 0
    with pytest.raises(PackCompileError, match="positive integer"):
        compile_pack(changed)


def test_yaml_duplicate_keys_are_rejected(tmp_path) -> None:
    source = tmp_path / "duplicate.yaml"
    source.write_text("pack_id: first\npack_id: second\n", encoding="utf-8")
    with pytest.raises(PackCompileError, match="Duplicate YAML key"):
        load_pack(source)


def test_boolean_fields_do_not_accept_strings() -> None:
    changed = copy.deepcopy(VALID_PACK)
    changed["data_residency"]["cross_border_forbidden"] = "false"
    with pytest.raises(PackCompileError, match="must be a boolean"):
        compile_pack(changed)
