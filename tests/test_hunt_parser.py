import pytest

from sentinel.hunting.parser import And, Or, Predicate, parse


def test_simple_predicate():
    query = parse('detections where verdict == "block"')
    assert query.table == "detections"
    assert isinstance(query.where, Predicate)
    assert query.where.field == "verdict"
    assert query.where.value == "block"


def test_and_or_parentheses():
    query = parse('detections where (verdict == "block" or verdict == "quarantine") and score > 0.5')
    assert isinstance(query.where, And)
    assert isinstance(query.where.clauses[0], Or)


def test_boolean_literal():
    query = parse("agent_actions where blocked == true | limit 25")
    assert isinstance(query.where, Predicate)
    assert query.where.value is True
    assert query.limit == 25


def test_limit_is_capped():
    assert parse("events | limit 99999").limit == 5000


def test_sort_command():
    query = parse("detections | sort created_at asc | limit 10")
    assert query.order_by == "created_at"
    assert query.order_desc is False


def test_unknown_command_rejected():
    with pytest.raises(SyntaxError):
        parse("events | delete all")


def test_trailing_tokens_rejected():
    with pytest.raises(SyntaxError):
        parse('events where event_type == "process" garbage')


def test_bad_syntax_raises():
    with pytest.raises(SyntaxError):
        parse("detections where")
    with pytest.raises(SyntaxError):
        parse("detections where verdict")
