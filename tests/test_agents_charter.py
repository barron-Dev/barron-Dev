import pytest
from datetime import datetime, timezone

from cyclothone.agents.charter import Charter, CharterGate


def test_charter_rejects_unknown_action():
    with pytest.raises(ValueError):
        Charter.from_json({"allowed_actions": ["shell_exec"]})


def test_charter_rejects_invalid_thresholds():
    with pytest.raises(ValueError):
        Charter.from_json({"min_confidence": 1.2})
    with pytest.raises(ValueError):
        Charter.from_json({"max_risk_per_action": -0.1})


def test_gate_stops_on_forbidden_target():
    charter = Charter.from_json({
        "allowed_actions": ["kill_process"],
        "forbidden_targets": ["dc-primary"],
        "min_confidence": 0.7,
        "max_risk_per_action": 0.8,
    })
    ok, gates = CharterGate().evaluate(
        charter, "kill_process", "dc-primary", 0.99, 1, 0, 0.1,
        datetime(2026, 9, 19, 12, tzinfo=timezone.utc),
    )
    assert not ok
    assert gates[-1].name == "forbidden_target"


def test_gate_rejects_negative_blast_and_bad_confidence():
    charter = Charter.from_json({"allowed_actions": ["kill_process"]})
    ok, gates = CharterGate().evaluate(
        charter, "kill_process", None, 0.99, -1, 0, 0.1,
    )
    assert not ok
    assert gates[-1].name == "blast_radius"


def test_gate_requires_confidence_and_risk_caps():
    charter = Charter.from_json({
        "allowed_actions": ["kill_process"],
        "min_confidence": 0.8,
        "max_risk_per_action": 0.4,
    })
    ok, gates = CharterGate().evaluate(charter, "kill_process", None, 0.75, 1, 0, 0.1)
    assert not ok
    assert gates[-1].name == "confidence"

    ok, gates = CharterGate().evaluate(charter, "kill_process", None, 0.9, 1, 0, 0.5)
    assert not ok
    assert gates[-1].name == "risk_cap"


def test_gate_passes_complete_safe_action():
    charter = Charter.from_json({
        "allowed_actions": ["kill_process"],
        "min_confidence": 0.75,
        "max_risk_per_action": 0.5,
    })
    ok, gates = CharterGate().evaluate(charter, "kill_process", None, 0.9, 2, 1, 0.2)
    assert ok
    assert len(gates) == 8
