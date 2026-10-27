"""Fail-closed pack capability-ceiling analysis.

This is a build-time policy check only. Runtime must independently re-evaluate
the current ceiling before every session; this module does not grant capabilities.
"""
from __future__ import annotations

from typing import Any, Mapping


class CapabilityCeilingError(ValueError):
    pass


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise CapabilityCeilingError(code)


def evaluate_capability_ceiling(
    artifact: Mapping[str, Any], ceiling: Mapping[str, Any]
) -> dict[str, Any]:
    _need(isinstance(artifact, Mapping), "artifact_must_be_mapping")
    _need(isinstance(ceiling, Mapping), "ceiling_must_be_mapping")
    required_keys = {
        "version", "services", "delivery_bindings", "regions",
        "max_retention_days", "minimum_dual_control", "minimum_asset_scope",
        "cross_border_allowed",
    }
    _need(set(ceiling) == required_keys, "invalid_ceiling_schema")
    _need(ceiling.get("version") == 1, "unsupported_ceiling_version")
    for key in ("services", "delivery_bindings", "regions"):
        _need(isinstance(ceiling[key], list) and all(isinstance(x, str) and x for x in ceiling[key]),
              f"invalid_ceiling_list:{key}")
        _need(len(ceiling[key]) == len(set(ceiling[key])), f"duplicate_ceiling_value:{key}")
    _need(type(ceiling["max_retention_days"]) is int and ceiling["max_retention_days"] >= 0,
          "invalid_ceiling_max_retention_days")
    _need(type(ceiling["minimum_dual_control"]) is bool, "invalid_ceiling_dual_control")
    _need(type(ceiling["cross_border_allowed"]) is bool, "invalid_ceiling_cross_border")
    _need(ceiling["minimum_asset_scope"] in {"critical", "high", "medium", "low"},
          "invalid_ceiling_minimum_asset_scope")

    pack = artifact.get("source_pack")
    _need(isinstance(pack, Mapping), "artifact_source_pack_missing")
    findings: list[dict[str, str]] = []

    def violation(code: str, detail: str) -> None:
        findings.append({"code": code, "detail": detail})

    declared_services = set(pack.get("services_in_scope", {}).get("required", [])) | set(
        pack.get("services_in_scope", {}).get("optional", [])
    )
    for item in sorted(declared_services - set(ceiling["services"])):
        violation("service_outside_ceiling", item)

    delivery = pack.get("delivery_bindings", {})
    requested = set(delivery.get("allowed", []))
    for item in sorted(requested - set(ceiling["delivery_bindings"])):
        violation("delivery_binding_outside_ceiling", item)
    if delivery.get("default") not in requested:
        violation("default_binding_not_in_allowed_set", str(delivery.get("default")))

    residency = pack.get("data_residency", {})
    region = residency.get("default_region")
    if region not in ceiling["regions"]:
        violation("region_outside_ceiling", str(region))
    if residency.get("cross_border_forbidden") is False and not ceiling["cross_border_allowed"]:
        violation("cross_border_policy_widening", "pack_allows_cross_border_when_ceiling_forbids")

    retention = pack.get("retention", {})
    retention_days = retention.get("min_days")
    if type(retention_days) is not int:
        violation("retention_days_invalid", "min_days_must_be_integer")
    elif retention_days > ceiling["max_retention_days"]:
        violation("retention_exceeds_ceiling", str(retention_days))

    approval = pack.get("approval", {})
    if ceiling["minimum_dual_control"] and approval.get("dual_control") is not True:
        violation("dual_control_cannot_be_disabled", "platform_requires_dual_control")

    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    minimum_scope = rank[ceiling["minimum_asset_scope"]]
    assets = pack.get("asset_types", {})
    for asset, settings in sorted(assets.items()):
        scope = settings.get("scope") if isinstance(settings, Mapping) else None
        if scope not in rank:
            violation("invalid_asset_scope", str(asset))
        elif rank[scope] < minimum_scope:
            violation("asset_scope_below_ceiling_floor", f"{asset}:{scope}<{ceiling['minimum_asset_scope']}")

    return {
        "analysis_version": 1,
        "pack_id": artifact.get("pack_id"),
        "artifact_sha256": artifact.get("artifact_sha256"),
        "ceiling_version": ceiling["version"],
        "status": "pass" if not findings else "blocked",
        "findings": findings,
        "capabilities_granted": [],
        "note": "Build-time analysis only; runtime must recheck the current effective ceiling.",
    }
