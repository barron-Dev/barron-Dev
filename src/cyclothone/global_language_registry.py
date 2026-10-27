"""Cyclothone language-tier parity registry and release gate."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


class LanguageRegistryError(ValueError):
    pass


def evaluate_language_registry(registry: Mapping[str, Any], *, minimum_tier: int = 1) -> dict[str, Any]:
    if not isinstance(registry, Mapping) or set(registry) != {"version", "locales"}:
        raise LanguageRegistryError("invalid_language_registry_shape")
    if registry["version"] != 1 or not isinstance(registry["locales"], Mapping) or not registry["locales"]:
        raise LanguageRegistryError("invalid_language_registry_version_or_locales")
    if type(minimum_tier) is not int or minimum_tier not in {1, 2, 3, 4}:
        raise LanguageRegistryError("invalid_minimum_tier")
    results = []
    for locale, entry in sorted(registry["locales"].items()):
        if not isinstance(locale, str) or not locale.strip():
            raise LanguageRegistryError("invalid_locale_key")
        if not isinstance(entry, Mapping) or set(entry) != {"tier", "surfaces"}:
            raise LanguageRegistryError(f"invalid_locale_entry:{locale}")
        tier = entry["tier"]
        surfaces = entry["surfaces"]
        if type(tier) is not int or tier not in {1, 2, 3, 4} or not isinstance(surfaces, Mapping) or not surfaces:
            raise LanguageRegistryError(f"invalid_locale_tier_or_surfaces:{locale}")
        missing = []
        for surface, units in sorted(surfaces.items()):
            if not isinstance(surface, str) or not isinstance(units, Mapping) or set(units) != {"required", "available"}:
                raise LanguageRegistryError(f"invalid_surface_entry:{locale}:{surface}")
            required, available = units["required"], units["available"]
            if (not isinstance(required, list) or not isinstance(available, list)
                or any(not isinstance(x, str) or not x for x in required + available)
                or len(required) != len(set(required)) or len(available) != len(set(available))):
                raise LanguageRegistryError(f"invalid_surface_units:{locale}:{surface}")
            missing.extend(f"{surface}:{unit}" for unit in sorted(set(required) - set(available)))
        gate_applies = tier <= minimum_tier
        results.append({
            "locale": locale, "tier": tier, "gate_applies": gate_applies,
            "status": "pass" if not (gate_applies and missing) else "blocked",
            "missing_units": missing,
        })
    return {
        "registry_version": 1,
        "minimum_tier_gate": minimum_tier,
        "status": "blocked" if any(item["status"] == "blocked" for item in results) else "pass",
        "locales": results,
    }


def load_language_registry(path: str | Path, *, minimum_tier: int = 1) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LanguageRegistryError(f"language_registry_read_failed:{type(exc).__name__}") from exc
    return evaluate_language_registry(value, minimum_tier=minimum_tier)
