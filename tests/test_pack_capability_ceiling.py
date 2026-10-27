import pytest

from cyclothone.packs.capability_ceiling import (
    CapabilityCeilingError, evaluate_capability_ceiling,
)


def fixture():
    pack = {
        "pack_id": "banking-basic",
        "services_in_scope": {"required": ["identity"], "optional": ["journal"]},
        "delivery_bindings": {"default": "api", "allowed": ["api"], "forbidden": ["email"]},
        "data_residency": {"default_region": "sa-central", "cross_border_forbidden": True},
        "retention": {"min_days": 90, "worm": True},
        "approval": {"dual_control": True, "roles": ["security", "compliance"]},
        "asset_types": {"payment_api": {"scope": "critical"}},
    }
    return {
        "artifact_type": "cyclothone.reference_pack", "pack_id": "banking-basic",
        "artifact_sha256": "a" * 64, "source_pack": pack,
    }


def ceiling(**changes):
    value = {
        "version": 1, "services": ["identity", "journal"],
        "delivery_bindings": ["api"], "regions": ["sa-central"],
        "max_retention_days": 180, "minimum_dual_control": True,
        "minimum_asset_scope": "high", "cross_border_allowed": False,
    }
    value.update(changes)
    return value


def test_pack_within_ceiling_passes_without_granting_capabilities():
    result = evaluate_capability_ceiling(fixture(), ceiling())
    assert result["status"] == "pass"
    assert result["capabilities_granted"] == []


def test_service_and_delivery_widening_are_blocked():
    artifact = fixture()
    artifact["source_pack"]["services_in_scope"]["optional"].append("admin_root")
    artifact["source_pack"]["delivery_bindings"]["allowed"].append("unapproved_export")
    result = evaluate_capability_ceiling(artifact, ceiling())
    assert result["status"] == "blocked"
    assert {x["code"] for x in result["findings"]} >= {
        "service_outside_ceiling", "delivery_binding_outside_ceiling"
    }


def test_region_retention_cross_border_and_dual_control_widening_blocked():
    artifact = fixture()
    artifact["source_pack"]["data_residency"]["default_region"] = "us-east"
    artifact["source_pack"]["data_residency"]["cross_border_forbidden"] = False
    artifact["source_pack"]["retention"]["min_days"] = 365
    artifact["source_pack"]["approval"]["dual_control"] = False
    result = evaluate_capability_ceiling(artifact, ceiling())
    assert result["status"] == "blocked"
    assert {x["code"] for x in result["findings"]} >= {
        "region_outside_ceiling", "cross_border_policy_widening",
        "retention_exceeds_ceiling", "dual_control_cannot_be_disabled"
    }


def test_invalid_ceiling_fails_closed():
    with pytest.raises(CapabilityCeilingError, match="invalid_ceiling_schema"):
        evaluate_capability_ceiling(fixture(), {"version": 1})


def test_asset_scope_cannot_be_lowered_below_floor():
    artifact = fixture()
    artifact["source_pack"]["asset_types"]["payment_api"]["scope"] = "low"
    result = evaluate_capability_ceiling(artifact, ceiling(minimum_asset_scope="high"))
    assert result["status"] == "blocked"
    assert any(x["code"] == "asset_scope_below_ceiling_floor" for x in result["findings"])


def test_ceiling_is_restrictive_not_capability_granting():
    result = evaluate_capability_ceiling(fixture(), ceiling())
    assert result["capabilities_granted"] == []
    assert "runtime must recheck" in result["note"]
