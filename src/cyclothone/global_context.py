"""Shared Cyclothone global context contract for customer and developer surfaces.

Locale is presentation context; jurisdiction is an independently resolved policy
context. Neither customer/developer role nor language can grant capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping

SurfaceRole = Literal["customer", "developer"]


class GlobalContextError(ValueError):
    pass


@dataclass(frozen=True)
class GlobalContext:
    tenant_id: str
    surface_role: SurfaceRole
    locale: str
    jurisdiction: str
    region: str
    timezone: str
    currency: str
    direction: Literal["ltr", "rtl"]
    accessibility: Mapping[str, bool]


@dataclass(frozen=True)
class CanonicalMessage:
    code: str
    arguments: Mapping[str, str | int | float | bool]
    display: str
    display_locale: str
    fallback_used: bool


def validate_global_context(value: GlobalContext) -> GlobalContext:
    """Validate shared context without inferring legal scope from UI language."""
    if not value.tenant_id.strip():
        raise GlobalContextError("tenant_context_required")
    if value.surface_role not in {"customer", "developer"}:
        raise GlobalContextError("unsupported_surface_role")
    for field, text in (
        ("locale", value.locale), ("jurisdiction", value.jurisdiction),
        ("region", value.region), ("timezone", value.timezone),
        ("currency", value.currency),
    ):
        if not isinstance(text, str) or not text.strip():
            raise GlobalContextError(f"global_context_field_required:{field}")
    if value.direction not in {"ltr", "rtl"}:
        raise GlobalContextError("invalid_text_direction")
    if not isinstance(value.accessibility, Mapping):
        raise GlobalContextError("accessibility_preferences_must_be_mapping")
    if any(not isinstance(key, str) or type(enabled) is not bool for key, enabled in value.accessibility.items()):
        raise GlobalContextError("accessibility_preferences_must_be_typed_booleans")
    return value


def resolve_canonical_message(
    *,
    code: str,
    arguments: Mapping[str, str | int | float | bool],
    locale: str,
    catalogs: Mapping[str, Mapping[str, str]],
) -> CanonicalMessage:
    """Resolve display text while preserving canonical machine code.

    This deliberately does not implement ICU MessageFormat. Catalog strings with
    ICU arguments must be passed through the ICU compiler gate before registration.
    """
    if not code or not locale:
        raise GlobalContextError("message_code_and_locale_required")
    selected = catalogs.get(locale, {})
    display = selected.get(code)
    resolved_locale = locale
    fallback = False
    if display is None:
        language = locale.split("-", 1)[0]
        selected = catalogs.get(language, {})
        display = selected.get(code)
        resolved_locale = language
        fallback = display is not None
    if display is None:
        selected = catalogs.get("en", {})
        display = selected.get(code)
        resolved_locale = "en"
        fallback = True
    if display is None:
        raise GlobalContextError(f"canonical_message_untranslated:{code}")
    return CanonicalMessage(
        code=code, arguments=dict(arguments), display=display,
        display_locale=resolved_locale, fallback_used=fallback,
    )
