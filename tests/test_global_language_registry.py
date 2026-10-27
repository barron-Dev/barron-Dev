import pytest

from cyclothone.global_language_registry import LanguageRegistryError, evaluate_language_registry


def registry():
    return {
        "version": 1,
        "locales": {
            "en": {"tier": 1, "surfaces": {
                "cli": {"required": ["errors", "help"], "available": ["errors", "help"]},
                "customer": {"required": ["navigation"], "available": ["navigation"]},
            }},
            "ar-SA": {"tier": 1, "surfaces": {
                "cli": {"required": ["errors", "help"], "available": ["errors"]},
            }},
            "fr": {"tier": 3, "surfaces": {
                "docs": {"required": ["getting-started"], "available": []},
            }},
        },
    }


def test_tier_one_parity_blocks_missing_required_units():
    result = evaluate_language_registry(registry(), minimum_tier=1)
    assert result["status"] == "blocked"
    arabic = next(x for x in result["locales"] if x["locale"] == "ar-SA")
    assert arabic["status"] == "blocked"
    assert arabic["missing_units"] == ["cli:help"]


def test_lower_priority_tier_can_be_tracked_without_blocking_tier_one():
    result = evaluate_language_registry(registry(), minimum_tier=1)
    french = next(x for x in result["locales"] if x["locale"] == "fr")
    assert french["gate_applies"] is False
    assert french["status"] == "pass"
    assert french["missing_units"] == ["docs:getting-started"]


def test_stricter_release_gate_can_block_tier_three():
    result = evaluate_language_registry(registry(), minimum_tier=3)
    assert result["status"] == "blocked"


def test_invalid_registry_shape_fails_closed():
    with pytest.raises(LanguageRegistryError, match="invalid_language_registry_shape"):
        evaluate_language_registry({"version": 1})


def test_duplicate_units_are_rejected():
    value = registry()
    value["locales"]["en"]["surfaces"]["cli"]["required"] = ["help", "help"]
    with pytest.raises(LanguageRegistryError, match="invalid_surface_units"):
        evaluate_language_registry(value)
