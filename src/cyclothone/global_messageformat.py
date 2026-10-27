"""Cyclothone's fail-closed ICU MessageFormat contract gate.

Supported grammar: simple arguments, select, plural and selectordinal with
nested messages. This validator intentionally rejects unsupported ICU syntax
instead of silently accepting strings the runtime cannot safely render.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

from babel import Locale
from babel.core import UnknownLocaleError


class MessageFormatError(ValueError):
    pass


@dataclass(frozen=True)
class CompiledMessage:
    source: str
    locale: str
    arguments: Mapping[str, str]
    plural_categories: Mapping[str, tuple[str, ...]]


_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_TYPE = re.compile(r"^(string|number|integer|date|time|boolean|select)$")
_SELECTOR = re.compile(r"^(?:[A-Za-z][A-Za-z0-9_-]*|=-?\d+(?:\.\d+)?)$")


class _Parser:
    def __init__(self, source: str, locale: str, declared: Mapping[str, str]):
        self.source = source
        self.locale = locale
        self.declared = declared
        self.used: dict[str, str] = {}
        self.plural_categories: dict[str, tuple[str, ...]] = {}
        try:
            self.locale_data = Locale.parse(locale.replace("-", "_"))
        except (UnknownLocaleError, ValueError, TypeError) as exc:
            raise MessageFormatError(f"unsupported_locale:{locale}") from exc

    def parse(self) -> CompiledMessage:
        self._message(0, nested=False)
        unused = sorted(set(self.declared) - set(self.used))
        if unused:
            raise MessageFormatError("declared_but_unused_arguments:" + ",".join(unused))
        return CompiledMessage(self.source, self.locale, dict(self.used), dict(self.plural_categories))

    def _message(self, pos: int, *, nested: bool) -> int:
        while pos < len(self.source):
            char = self.source[pos]
            if char == "}":
                if not nested:
                    raise MessageFormatError("unexpected_closing_brace")
                return pos + 1
            if char == "{":
                pos = self._argument(pos + 1)
                continue
            if char == "'":
                # ICU apostrophe quoting is complex; accept doubled apostrophe only.
                if pos + 1 < len(self.source) and self.source[pos + 1] == "'":
                    pos += 2
                    continue
                raise MessageFormatError("unsupported_icu_apostrophe_quoting")
            pos += 1
        if nested:
            raise MessageFormatError("unclosed_nested_message")
        return pos

    def _read_token(self, pos: int, stops: str) -> tuple[str, int, str]:
        end = pos
        while end < len(self.source) and self.source[end] not in stops:
            end += 1
        if end == len(self.source):
            raise MessageFormatError("unterminated_argument")
        return self.source[pos:end].strip(), end, self.source[end]

    def _register(self, name: str, inferred: str | None) -> None:
        if not _NAME.fullmatch(name):
            raise MessageFormatError(f"invalid_argument_name:{name}")
        declared = self.declared.get(name)
        if declared is None:
            raise MessageFormatError(f"argument_type_not_declared:{name}")
        if not _TYPE.fullmatch(declared):
            raise MessageFormatError(f"invalid_declared_argument_type:{name}")
        if inferred == "number" and declared not in {"number", "integer"}:
            raise MessageFormatError(f"argument_type_mismatch:{name}:expected_number")
        if inferred == "string" and declared not in {"string", "select"}:
            raise MessageFormatError(f"argument_type_mismatch:{name}:expected_string")
        previous = self.used.get(name)
        if previous is not None and previous != declared:
            raise MessageFormatError(f"argument_type_inconsistent:{name}")
        self.used[name] = declared

    def _argument(self, pos: int) -> int:
        name, end, delim = self._read_token(pos, ",}")
        if delim == "}":
            self._register(name, None)
            return end + 1
        kind, end, delim = self._read_token(end + 1, ",}")
        kind = kind.strip()
        if delim == "}":
            if kind in {"number", "date", "time"}:
                self._register(name, "number" if kind == "number" else "string")
                return end + 1
            raise MessageFormatError(f"unsupported_argument_format:{name}:{kind}")
        if delim != ",":
            raise MessageFormatError(f"unsupported_argument_format:{name}:{kind}")
        if kind in {"plural", "selectordinal", "select"}:
            return self._choice(name, kind, end + 1)
        # Numeric/date/time ICU format styles may not contain braces in this strict gate.
        style, style_end, style_delim = self._read_token(end + 1, "}")
        if style_delim != "}":
            raise MessageFormatError(f"unsupported_format_style:{name}:{kind}")
        if kind in {"number", "date", "time"}:
            self._register(name, "number" if kind == "number" else "string")
            return style_end + 1
        raise MessageFormatError(f"unsupported_icu_argument_type:{kind}")

    def _choice(self, name: str, kind: str, pos: int) -> int:
        self._register(name, "string" if kind == "select" else "number")
        allowed = {"zero", "one", "two", "few", "many", "other"}
        if kind == "plural":
            allowed = set(self.locale_data.plural_form.rules) | {"other"}
        elif kind == "selectordinal":
            allowed = set(self.locale_data.ordinal_form.rules) | {"other"}
        selectors: set[str] = set()
        while pos < len(self.source):
            while pos < len(self.source) and self.source[pos].isspace():
                pos += 1
            if pos < len(self.source) and self.source[pos] == "}":
                pos += 1
                break
            selector, end, delim = self._read_token(pos, "{")
            selector = selector.strip()
            if delim != "{" or not _SELECTOR.fullmatch(selector):
                raise MessageFormatError(f"invalid_selector:{name}:{selector}")
            if selector in selectors:
                raise MessageFormatError(f"duplicate_selector:{name}:{selector}")
            if kind != "select" and not selector.startswith("=") and selector not in allowed:
                raise MessageFormatError(f"invalid_plural_category:{self.locale}:{selector}")
            selectors.add(selector)
            pos = self._message(end + 1, nested=True)
        else:
            raise MessageFormatError(f"unclosed_choice_argument:{name}")
        if "other" not in selectors:
            raise MessageFormatError(f"mandatory_other_missing:{name}")
        if kind in {"plural", "selectordinal"}:
            self.plural_categories[name] = tuple(sorted(selectors))
        return pos


def compile_message(
    source: str, *, locale: str, argument_types: Mapping[str, str]
) -> CompiledMessage:
    if not isinstance(source, str) or not source:
        raise MessageFormatError("message_source_required")
    if not isinstance(argument_types, Mapping):
        raise MessageFormatError("argument_type_registry_required")
    for name, value in argument_types.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise MessageFormatError("argument_type_registry_must_be_string_mapping")
    return _Parser(source, locale, argument_types).parse()


def compile_catalog(
    catalog: Mapping[str, Mapping[str, object]], *, locale: str
) -> dict[str, CompiledMessage]:
    """Compile a catalog where each message is {text, arguments:{name:type}}."""
    if not isinstance(catalog, Mapping) or not catalog:
        raise MessageFormatError("catalog_must_be_nonempty_mapping")
    result: dict[str, CompiledMessage] = {}
    for code, item in sorted(catalog.items()):
        if not isinstance(code, str) or not _NAME.fullmatch(code):
            raise MessageFormatError(f"invalid_canonical_message_code:{code}")
        if not isinstance(item, Mapping) or set(item) != {"text", "arguments"}:
            raise MessageFormatError(f"invalid_catalog_entry_shape:{code}")
        try:
            result[code] = compile_message(
                item["text"], locale=locale, argument_types=item["arguments"]
            )
        except MessageFormatError as exc:
            raise MessageFormatError(f"catalog_entry_invalid:{code}:{exc}") from exc
    return result
