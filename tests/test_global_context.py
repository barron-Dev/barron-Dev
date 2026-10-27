import pytest

from cyclothone.global_context import (
    GlobalContext, GlobalContextError, resolve_canonical_message, validate_global_context,
)


def context(**changes):
    values = dict(
        tenant_id="tenant-a", surface_role="customer", locale="ar-SA",
        jurisdiction="SA", region="sa-central", timezone="Asia/Riyadh",
        currency="SAR", direction="rtl", accessibility={"reduced_motion": True},
    )
    values.update(changes)
    return GlobalContext(**values)


@pytest.mark.parametrize("role", ["customer", "developer"])
def test_customer_and_developer_share_same_context_contract(role):
    result = validate_global_context(context(surface_role=role))
    assert result.locale == "ar-SA"
    assert result.jurisdiction == "SA"
    assert result.surface_role == role


def test_language_does_not_overwrite_jurisdiction():
    result = validate_global_context(context(locale="en-US", jurisdiction="SA"))
    assert result.locale == "en-US"
    assert result.jurisdiction == "SA"


def test_invalid_context_fails_closed():
    with pytest.raises(GlobalContextError, match="global_context_field_required:region"):
        validate_global_context(context(region=""))


def test_canonical_error_code_survives_localized_display_fallback():
    result = resolve_canonical_message(
        code="source_unavailable",
        arguments={"source": "native_onion"},
        locale="ar-SA",
        catalogs={"en": {"source_unavailable": "Source unavailable"}},
    )
    assert result.code == "source_unavailable"
    assert result.display == "Source unavailable"
    assert result.fallback_used is True
    assert result.display_locale == "en"


def test_missing_translation_is_not_silently_fabricated():
    with pytest.raises(GlobalContextError, match="canonical_message_untranslated"):
        resolve_canonical_message(
            code="unknown_reason", arguments={}, locale="ar-SA", catalogs={"en": {}}
        )
