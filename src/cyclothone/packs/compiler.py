from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

PACK_SCHEMA_VERSION = 1
PACK_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
SCOPES = {"critical", "high", "medium", "low"}
TOP_LEVEL_KEYS = {
    "schema_version", "pack_id", "industry", "sub_segment", "geography",
    "asset_types", "services_in_scope", "policy_pack", "compliance_packs",
    "delivery_bindings", "data_residency", "retention", "approval",
    "workflows", "failure_tests", "ttfvr_target_seconds", "controls", "patterns",
    "developer_profile",
}


class PackCompileError(ValueError):
    """A pack is invalid or cannot be compiled without ambiguity."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys instead of shadowing them."""


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise PackCompileError(f"duplicate_yaml_key:{key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise PackCompileError(code)


def _identifier(value: Any, field: str) -> str:
    _require(isinstance(value, str) and IDENTIFIER_RE.fullmatch(value) is not None,
             f"invalid_identifier:{field}")
    return value


def _string_list(value: Any, field: str) -> list[str]:
    _require(isinstance(value, list), f"expected_list:{field}")
    result: list[str] = []
    for item in value:
        result.append(_identifier(item, field))
    _require(len(result) == len(set(result)), f"duplicate_list_item:{field}")
    return result


def load_pack(path: str | Path) -> dict[str, Any]:
    """Load YAML safely, reject duplicate keys, then validate the pack contract."""
    try:
        raw = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except PackCompileError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PackCompileError(f"pack_read_or_yaml_error:{type(exc).__name__}") from exc
    return validate_pack(raw)


def validate_pack(raw: Any) -> dict[str, Any]:
    _require(isinstance(raw, dict), "pack_must_be_mapping")
    unknown = sorted(set(raw) - TOP_LEVEL_KEYS)
    _require(not unknown, "unknown_top_level_keys:" + ",".join(unknown))
    required = {
        "schema_version", "pack_id", "industry", "sub_segment", "geography",
        "asset_types", "services_in_scope", "compliance_packs",
        "delivery_bindings", "data_residency", "retention", "approval",
        "workflows", "failure_tests", "ttfvr_target_seconds",
    }
    missing = sorted(required - set(raw))
    _require(not missing, "missing_required_keys:" + ",".join(missing))
    _require(raw["schema_version"] == PACK_SCHEMA_VERSION, "unsupported_schema_version")
    pack_id = raw["pack_id"]
    _require(isinstance(pack_id, str) and PACK_ID_RE.fullmatch(pack_id) is not None,
             "invalid_pack_id")
    for field in ("industry", "sub_segment", "geography"):
        _identifier(raw[field], field)

    assets = raw["asset_types"]
    _require(isinstance(assets, dict) and bool(assets), "asset_types_must_be_nonempty_mapping")
    for asset, settings in assets.items():
        _identifier(asset, "asset_type")
        _require(isinstance(settings, dict), f"asset_settings_must_be_mapping:{asset}")
        _require(set(settings) <= {"scope", "observe_only", "third_party", "session_theft"},
                 f"unknown_asset_settings:{asset}")
        _require(settings.get("scope") in SCOPES, f"invalid_asset_scope:{asset}")
        for flag in ("observe_only", "third_party", "session_theft"):
            if flag in settings:
                _require(type(settings[flag]) is bool, f"invalid_asset_flag:{asset}:{flag}")

    services = raw["services_in_scope"]
    _require(isinstance(services, dict) and set(services) == {"required", "optional"},
             "services_in_scope_requires_required_and_optional")
    required_services = _string_list(services["required"], "service")
    optional_services = _string_list(services["optional"], "service")
    _require(not set(required_services) & set(optional_services), "service_cannot_be_required_and_optional")

    if "policy_pack" in raw:
        policy = raw["policy_pack"]
        _require(isinstance(policy, dict) and set(policy) == {"base", "overlays"},
                 "invalid_policy_pack")
        _identifier(policy["base"], "policy_pack.base")
        _string_list(policy["overlays"], "policy_overlay")

    _string_list(raw["compliance_packs"], "compliance_pack")
    delivery = raw["delivery_bindings"]
    _require(isinstance(delivery, dict) and set(delivery) == {"default", "allowed", "forbidden"},
             "invalid_delivery_bindings")
    for key in ("allowed", "forbidden"):
        _string_list(delivery[key], f"delivery_bindings.{key}")
    _identifier(delivery["default"], "delivery_bindings.default")
    _require(delivery["default"] in delivery["allowed"], "default_delivery_not_allowed")
    _require(not set(delivery["allowed"]) & set(delivery["forbidden"]),
             "delivery_binding_both_allowed_and_forbidden")

    residency = raw["data_residency"]
    _require(isinstance(residency, dict) and set(residency) == {"default_region", "cross_border_forbidden"},
             "invalid_data_residency")
    _identifier(residency["default_region"], "data_residency.default_region")
    _require(type(residency["cross_border_forbidden"]) is bool, "invalid_cross_border_flag")

    retention = raw["retention"]
    _require(isinstance(retention, dict) and set(retention) == {"min_days", "worm"},
             "invalid_retention")
    _require(type(retention["min_days"]) is int and retention["min_days"] >= 0,
             "invalid_retention_min_days")
    _require(type(retention["worm"]) is bool, "invalid_retention_worm")

    approval = raw["approval"]
    _require(isinstance(approval, dict) and set(approval) == {"dual_control", "roles"},
             "invalid_approval")
    _require(type(approval["dual_control"]) is bool, "invalid_dual_control")
    _string_list(approval["roles"], "approval.role")
    _require(not approval["dual_control"] or len(approval["roles"]) >= 2,
             "dual_control_requires_two_roles")

    for field in ("workflows", "failure_tests"):
        values = _string_list(raw[field], field)
        _require(bool(values), f"{field}_must_be_nonempty")
    _require(type(raw["ttfvr_target_seconds"]) is int and raw["ttfvr_target_seconds"] > 0,
             "invalid_ttfvr_target_seconds")

    for field in ("controls", "patterns", "developer_profile"):
        if field in raw:
            _require(isinstance(raw[field], (dict, list)), f"invalid_optional_field:{field}")

    # Round-trip through JSON to reject non-JSON YAML values and normalize data types.
    try:
        normalized = json.loads(json.dumps(raw, sort_keys=True, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise PackCompileError("pack_contains_non_json_value") from exc
    return normalized


def build_pack(
    raw: dict[str, Any],
    *,
    known_services: set[str] | None = None,
    known_delivery_bindings: set[str] | None = None,
) -> dict[str, Any]:
    """Compile a validated pack into deterministic configuration.

    Missing registries never imply support: unresolved service/binding references
    make the artifact preview-only. This command does not provision capabilities.
    """
    pack = validate_pack(raw)
    known_services = known_services or set()
    known_delivery_bindings = known_delivery_bindings or set()
    required_services = pack["services_in_scope"]["required"]
    optional_services = pack["services_in_scope"]["optional"]
    unresolved_required = sorted(set(required_services) - known_services)
    unresolved_optional = sorted(set(optional_services) - known_services)
    unresolved_bindings = sorted(set(pack["delivery_bindings"]["allowed"]) - known_delivery_bindings)
    preview_only = bool(unresolved_required or unresolved_optional or unresolved_bindings)

    compiled = {
        "artifact_type": "cyclothone.reference_pack",
        "artifact_version": 1,
        "pack_id": pack["pack_id"],
        "schema_version": pack["schema_version"],
        "source_pack": pack,
        "resolved": {
            "required_services": sorted(set(required_services) & known_services),
            "optional_services": sorted(set(optional_services) & known_services),
            "delivery_bindings": sorted(set(pack["delivery_bindings"]["allowed"]) & known_delivery_bindings),
        },
        "unresolved": {
            "required_services": unresolved_required,
            "optional_services": unresolved_optional,
            "delivery_bindings": unresolved_bindings,
        },
        "publication_state": "preview" if preview_only else "compiled_unconformed",
        "conformance": {"status": "not_run", "artifact_digest": None},
    }
    canonical = json.dumps(compiled, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    compiled["artifact_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return compiled


def build_pack_file(
    source: str | Path,
    destination: str | Path,
    *,
    capabilities_file: str | Path | None = None,
) -> dict[str, Any]:
    pack = load_pack(source)
    known_services: set[str] = set()
    known_bindings: set[str] = set()
    if capabilities_file is not None:
        try:
            registry = json.loads(Path(capabilities_file).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PackCompileError(f"capability_registry_error:{type(exc).__name__}") from exc
        if not isinstance(registry, dict) or set(registry) != {"services", "delivery_bindings"}:
            raise PackCompileError("invalid_capability_registry_shape")
        known_services = set(_string_list(registry["services"], "registry.service"))
        known_bindings = set(_string_list(registry["delivery_bindings"], "registry.delivery_binding"))
    artifact = build_pack(
        pack, known_services=known_services, known_delivery_bindings=known_bindings
    )
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(artifact, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return artifact
