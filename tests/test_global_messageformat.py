import pytest

from cyclothone.global_messageformat import MessageFormatError, compile_catalog, compile_message


def test_english_plural_requires_other_and_accepts_locale_category():
    compiled = compile_message(
        "{count, plural, one {# alert} other {# alerts}}",
        locale="en",
        argument_types={"count": "integer"},
    )
    assert compiled.arguments == {"count": "integer"}
    assert compiled.plural_categories["count"] == ("one", "other")


def test_arabic_plural_categories_are_checked_against_cldr_locale_data():
    compiled = compile_message(
        "{count, plural, zero {صفر} one {واحد} two {اثنان} few {قليل} many {كثير} other {آخر}}",
        locale="ar-SA",
        argument_types={"count": "integer"},
    )
    assert set(compiled.plural_categories["count"]) == {"zero", "one", "two", "few", "many", "other"}


def test_missing_other_branch_fails_closed():
    with pytest.raises(MessageFormatError, match="mandatory_other_missing"):
        compile_message("{count, plural, one {one}}", locale="en", argument_types={"count": "integer"})


def test_invalid_locale_plural_category_is_rejected():
    with pytest.raises(MessageFormatError, match="invalid_plural_category"):
        compile_message("{count, plural, few {few} other {other}}", locale="en", argument_types={"count": "integer"})


def test_nested_select_and_plural_compile():
    compiled = compile_message(
        "{gender, select, female {{count, plural, one {one item} other {# items}}} other {unknown}}",
        locale="en",
        argument_types={"gender": "select", "count": "integer"},
    )
    assert set(compiled.arguments) == {"gender", "count"}


def test_untyped_and_unused_arguments_are_rejected():
    with pytest.raises(MessageFormatError, match="argument_type_not_declared"):
        compile_message("Hello {name}", locale="en", argument_types={})
    with pytest.raises(MessageFormatError, match="declared_but_unused"):
        compile_message("Hello", locale="en", argument_types={"name": "string"})


def test_typed_number_argument_and_simple_variable_are_supported():
    compiled = compile_message(
        "Value: {value, number}",
        locale="en",
        argument_types={"value": "number"},
    )
    assert compiled.arguments == {"value": "number"}


def test_catalog_gate_rejects_invalid_canonical_code_and_entry_shape():
    with pytest.raises(MessageFormatError, match="invalid_canonical_message_code"):
        compile_catalog({"not a code": {"text": "Hello", "arguments": {}}}, locale="en")
    with pytest.raises(MessageFormatError, match="invalid_catalog_entry_shape"):
        compile_catalog({"valid_code": {"text": "Hello"}}, locale="en")
