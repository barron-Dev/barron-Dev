from decimal import Decimal

import pytest

from cyclothone.ai.provider_execution import _parse_response


def _response(*, input_tokens: int, output_tokens: int, cached_tokens: int = 0) -> dict:
    return {
        "output_text": "verified",
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "input_tokens_details": {"cached_tokens": cached_tokens},
        },
    }


SOL_COST_META = {
    "input_usd_per_million_tokens": 2,
    "cached_input_usd_per_million_tokens": 0.10,
    "output_usd_per_million_tokens": 10,
}


def test_sol_cost_uses_uncached_cached_and_output_rates() -> None:
    result = _parse_response(
        _response(input_tokens=1_000_000, output_tokens=100_000, cached_tokens=100_000),
        latency_ms=17,
        cost_meta=SOL_COST_META,
    )

    assert result.tokens_in == 1_000_000
    assert result.tokens_cached == 100_000
    assert result.tokens_out == 100_000
    assert result.cost_usd == Decimal("2.81000000")


def test_sol_cost_without_cached_tokens_matches_standard_rates() -> None:
    result = _parse_response(
        _response(input_tokens=1_000_000, output_tokens=100_000),
        latency_ms=17,
        cost_meta=SOL_COST_META,
    )

    assert result.cost_usd == Decimal("3.00000000")


def test_missing_usage_fails_closed_instead_of_recording_zero_cost() -> None:
    with pytest.raises(RuntimeError, match="omitted token usage"):
        _parse_response(
            {"output_text": "verified"},
            latency_ms=17,
            cost_meta=SOL_COST_META,
        )


def test_missing_pricing_fails_closed_instead_of_recording_zero_cost() -> None:
    with pytest.raises(RuntimeError, match="pricing is not registered"):
        _parse_response(
            _response(input_tokens=100, output_tokens=20),
            latency_ms=17,
            cost_meta={},
        )


def test_cached_tokens_cannot_exceed_total_input_tokens() -> None:
    with pytest.raises(RuntimeError, match="invalid token usage"):
        _parse_response(
            _response(input_tokens=10, output_tokens=2, cached_tokens=11),
            latency_ms=17,
            cost_meta=SOL_COST_META,
        )
