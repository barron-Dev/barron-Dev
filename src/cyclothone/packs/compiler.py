"""Strict, deterministic compiler for declarative Cyclothone reference packs.

Compilation validates configuration and emits a content-addressed manifest.
It does not activate services, authorize actions, or certify that referenced
platform primitives are deployed. Runtime binding and conformance are separate
proof gates and remain explicitly unverified in generated output.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml


PACK_SCHEMA_VERSION = "1.0"
COMPILER_VERSION = "0.1.0"
_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SERVICE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_REGION = re.compile(r"^[a-z]{2,3}(?:-[a-z0-9]+)+$")
_SCOPE_VALUES = {"critical", "high", "medium", "low"}
_DELIVERY = {"webhook_mtls", "sse", "api_poll", "splunk_hec", "mcp_agent", "mqtt", "opc_ua", "public_webhook"}
_DEVELOPER_TYPES = {"solo_indie", "startup_small_team", "enterprise_team", "mssp_si_auditor"}

# Stable contract identifiers describe intended platform binding points. Their
# presence is not proof that the corresponding runtime integration is active.
_FIELD_BINDINGS = {
    "asset_types": "platform_contracts.asset_inventory.v1",
    "services_in_scope": "platform_contracts.service_catalog.v1",
    "policy_pack": "platform_contracts.policy_engine.v1",
    "compliance_packs": "platform_contracts.compliance_registry.v1",
    "delivery_bindings": "platform_contracts.result_delivery.v1",
    "data_residency": "platform_contracts.residency_guard.v1",
    "retention": "platform_contracts.evidence_retention.v1",
    "approval": "platform_contracts.approval_policy.v1",
    "workflows": "platform_contracts.workflow_templates.v1",
    "failure_tests": "platform_contracts.conformance_fixtures.v1",
    "ttfvr_target_seconds": "platform_contracts.ttfvr_measurement.v1",
}

_ROOT_KEYS = {
    "schema_version", "pack_id", "industry", "sub_segment", "geography",
    "developer_type", "asset_types", "services_in_scope", "policy_pack",
    "compliance_packs", "delivery_bindings", "data_residency", "retention",
    "approval", "workflows", "failure_tests", "ttfvr_target_seconds",
}


class PackCompileError(ValueError):
    """A pack is malformed or violates a fail-closed compilation rule."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys instead of overwriting."""


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise PackCompileError("YAML mapping keys must be scalar and hashable.") from exc
        if duplicate:
            raise PackCompileError(f"Duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _require_mapping(value: Any, path: str) -> dict:
    if not isinstance(value, dict):
        raise PackCompileError(f"{path} must be a mapping.")
    return value


def _require_keys(value: dict, required: set[str], allowed: set[str], path: str) -> None:
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - allowed)
    if missing:
        raise PackCompileError(f"{path} is missing required keys: {', '.join(missing)}")
    if unknown:
        raise PackCompileError(f"{path} has unknown keys: {', '.join(unknown)}")


def _slug(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _SLUG.fullmatch(value):
        raise PackCompileError(f"{path} must be a lowercase kebab-case identifier.")
    return value


def _string_list(value: Any, path: str, *, pattern: re.Pattern[str] | None = None, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise PackCompileError(f"{path} must be {'a non-empty' if nonempty else 'a'} list.")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise PackCompileError(f"{path} must contain only non-empty strings.")
    if len(set(value)) != len(value):
        raise PackCompileError(f"{path} must not contain duplicates.")
    if pattern and any(not pattern.fullmatch(item) for item in value):
        raise PackCompileError(f"{path} contains an invalid identifier.")
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise PackCompileError(f"{path} must be a boolean.")
    return value


def validate_pack(raw: Any) -> dict[str, Any]:
    pack = _require_mapping(raw, "pack")
    _require_keys(pack, _ROOT_KEYS - {"schema_version"}, _ROOT_KEYS, "pack")
    version = pack.get("schema_version", PACK_SCHEMA_VERSION)
    if version != PACK_SCHEMA_VERSION:
        raise PackCompileError(f"Unsupported schema_version {version!r}; expected {PACK_SCHEMA_VERSION!r}.")
    normalized = dict(pack)
    normalized["schema_version"] = PACK_SCHEMA_VERSION

    for field in ("pack_id", "industry", "sub_segment", "geography"):
        normalized[field] = _slug(pack[field], field)
    developer_type = pack.get("developer_type", "enterprise_team")
    if developer_type not in _DEVELOPER_TYPES:
        raise PackCompileError(f"developer_type must be one of: {', '.join(sorted(_DEVELOPER_TYPES))}.")
    normalized["developer_type"] = developer_type

    assets = _require_mapping(pack["asset_types"], "asset_types")
    if not assets:
        raise PackCompileError("asset_types must declare at least one asset.")
    clean_assets: dict[str, dict[str, Any]] = {}
    for name, raw_config in sorted(assets.items()):
        _slug(name.replace("_", "-") if isinstance(name, str) else name, "asset_types key")
        config = _require_mapping(raw_config, f"asset_types.{name}")
        allowed_asset = {"scope", "observe_only", "third_party", "session_theft"}
        _require_keys(config, {"scope"}, allowed_asset, f"asset_types.{name}")
        if config["scope"] not in _SCOPE_VALUES:
            raise PackCompileError(f"asset_types.{name}.scope must be one of {sorted(_SCOPE_VALUES)}.")
        clean = {"scope": config["scope"]}
        for flag in ("observe_only", "third_party", "session_theft"):
            if flag in config:
                clean[flag] = _boolean(config[flag], f"asset_types.{name}.{flag}")
        clean_assets[name] = clean
    normalized["asset_types"] = clean_assets

    services = _require_mapping(pack["services_in_scope"], "services_in_scope")
    _require_keys(services, {"required", "optional"}, {"required", "optional"}, "services_in_scope")
    required = _string_list(services["required"], "services_in_scope.required", pattern=_SERVICE)
    optional = _string_list(services["optional"], "services_in_scope.optional", pattern=_SERVICE, nonempty=False)
    overlap = sorted(set(required) & set(optional))
    if overlap:
        raise PackCompileError(f"Services cannot be both required and optional: {', '.join(overlap)}")
    normalized["services_in_scope"] = {"required": sorted(required), "optional": sorted(optional)}

    policy = _require_mapping(pack["policy_pack"], "policy_pack")
    _require_keys(policy, {"base", "overlays"}, {"base", "overlays"}, "policy_pack")
    normalized["policy_pack"] = {
        "base": _slug(policy["base"], "policy_pack.base"),
        "overlays": sorted(_string_list(policy["overlays"], "policy_pack.overlays", pattern=_SLUG, nonempty=False)),
    }
    normalized["compliance_packs"] = sorted(
        _string_list(pack["compliance_packs"], "compliance_packs", pattern=_SLUG)
    )

    delivery = _require_mapping(pack["delivery_bindings"], "delivery_bindings")
    _require_keys(delivery, {"default", "allowed", "forbidden"}, {"default", "allowed", "forbidden"}, "delivery_bindings")
    allowed_delivery = _string_list(delivery["allowed"], "delivery_bindings.allowed", nonempty=True)
    forbidden_delivery = _string_list(delivery["forbidden"], "delivery_bindings.forbidden", nonempty=False)
    unknown_delivery = (set(allowed_delivery) | set(forbidden_delivery)) - _DELIVERY
    if unknown_delivery:
        raise PackCompileError(f"Unknown delivery binding(s): {', '.join(sorted(unknown_delivery))}")
    if set(allowed_delivery) & set(forbidden_delivery):
        raise PackCompileError("delivery_bindings.allowed and forbidden must be disjoint.")
    if delivery["default"] not in allowed_delivery:
        raise PackCompileError("delivery_bindings.default must be in delivery_bindings.allowed.")
    if delivery["default"] in forbidden_delivery:
        raise PackCompileError("The default delivery binding is explicitly forbidden.")
    normalized["delivery_bindings"] = {
        "default": delivery["default"],
        "allowed": sorted(allowed_delivery),
        "forbidden": sorted(forbidden_delivery),
    }

    residency = _require_mapping(pack["data_residency"], "data_residency")
    _require_keys(residency, {"default_region", "cross_border_forbidden"}, {"default_region", "cross_border_forbidden"}, "data_residency")
    region = residency["default_region"]
    if not isinstance(region, str) or not _REGION.fullmatch(region):
        raise PackCompileError("data_residency.default_region must be a region identifier such as eu-west-1.")
    normalized["data_residency"] = {
        "default_region": region,
        "cross_border_forbidden": _boolean(residency["cross_border_forbidden"], "data_residency.cross_border_forbidden"),
    }

    retention = _require_mapping(pack["retention"], "retention")
    _require_keys(retention, {"min_days", "worm"}, {"min_days", "worm"}, "retention")
    days = retention["min_days"]
    if type(days) is not int or not 1 <= days <= 36500:
        raise PackCompileError("retention.min_days must be an integer between 1 and 36500.")
    normalized["retention"] = {"min_days": days, "worm": _boolean(retention["worm"], "retention.worm")}

    approval = _require_mapping(pack["approval"], "approval")
    _require_keys(approval, {"dual_control", "roles"}, {"dual_control", "roles"}, "approval")
    dual = _boolean(approval["dual_control"], "approval.dual_control")
    roles = _string_list(approval["roles"], "approval.roles", pattern=_SLUG)
    if dual and len(roles) < 2:
        raise PackCompileError("approval.roles must name at least two distinct roles when dual_control is true.")
    normalized["approval"] = {"dual_control": dual, "roles": sorted(roles)}

    normalized["workflows"] = sorted(_string_list(pack["workflows"], "workflows", pattern=_SLUG))
    normalized["failure_tests"] = sorted(_string_list(pack["failure_tests"], "failure_tests", pattern=_SLUG))
    target = pack["ttfvr_target_seconds"]
    if type(target) is not int or not 1 <= target <= 31_536_000:
        raise PackCompileError("ttfvr_target_seconds must be a positive integer no greater than one year.")
    normalized["ttfvr_target_seconds"] = target
    return normalized


def load_pack(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        with source.open("r", encoding="utf-8") as handle:
            raw = yaml.load(handle, Loader=_UniqueKeyLoader)
    except OSError as exc:
        raise PackCompileError(f"Cannot read pack file {source}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PackCompileError(f"Invalid YAML in {source}: {exc}") from exc
    return validate_pack(raw)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compile_pack(raw: Any) -> dict[str, Any]:
    """Validate and compile a pack into a deterministic, explicitly unverified manifest."""
    pack = validate_pack(raw)
    pack_digest = hashlib.sha256(_canonical_json(pack)).hexdigest()
    bindings = [
        {"field": field, "contract_id": contract_id, "state": "declaration_only"}
        for field, contract_id in _FIELD_BINDINGS.items()
        if field in pack
    ]
    blocking_gates = [
        "Resolve every declared contract binding to an implemented runtime primitive.",
        "Resolve the geography overlay against a versioned overlay registry.",
        "Run all mandatory pack conformance tests and publish the artifact.",
        "Measure TTFVR against the declared target in an isolated reference flow.",
    ]
    manifest = {
        "artifact_schema_version": "1.0",
        "compiler_version": COMPILER_VERSION,
        "pack_id": pack["pack_id"],
        "pack_sha256": pack_digest,
        "compilation_state": "compiled_unverified",
        "conformance": {"status": "not_run", "blocking_gates": blocking_gates},
        "geography_overlay_ref": f"geography:{pack['geography']}",
        "primitive_bindings": bindings,
        "pack": pack,
    }
    manifest["manifest_sha256"] = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    return manifest
