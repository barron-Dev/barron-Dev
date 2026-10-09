from decimal import Decimal

import pytest

from cyclothone.ai.provider_execution import _parse_response


PRICES = {
    "input_usd_per_million_tokens": "1.0",
    "cached_input_usd_per_million_tokens": "0.1",
    "output_usd_per_million_tokens": "2.0",
}


def test_provider_usage_cost_uses_cached_and_uncached_input_rates():
    result = _parse_response(
        {
            "output_text": "verified output",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "input_tokens_details": {"cached_tokens": 20},
            },
        },
        latency_ms=12,
        cost_meta=PRICES,
    )

    assert result.output_text == "verified output"
    assert result.tokens_in == 100
    assert result.tokens_out == 50
    assert result.tokens_cached == 20
    assert result.latency_ms == 12
    assert result.cost_usd == Decimal("0.00018200")


@pytest.mark.parametrize(
    "usage",
    [
        None,
        {"input_tokens": 10},
        {"input_tokens": -1, "output_tokens": 1},
        {"input_tokens": 10, "output_tokens": -1},
        {
            "input_tokens": 10,
            "output_tokens": 1,
            "input_tokens_details": {"cached_tokens": 11},
        },
    ],
)
def test_provider_usage_rejects_missing_or_invalid_token_accounting(usage):
    with pytest.raises(RuntimeError):
        _parse_response(
            {"output_text": "output", "usage": usage},
            latency_ms=1,
            cost_meta=PRICES,
        )


def test_provider_usage_rejects_missing_model_pricing():
    with pytest.raises(RuntimeError, match="pricing is not registered"):
        _parse_response(
            {
                "output_text": "output",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            latency_ms=1,
            cost_meta={},
        )


def test_provider_usage_rejects_negative_model_pricing():
    with pytest.raises(RuntimeError, match="negative rate"):
        _parse_response(
            {
                "output_text": "output",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            latency_ms=1,
            cost_meta={**PRICES, "output_usd_per_million_tokens": "-1"},
        )


def test_provider_usage_rejects_empty_output():
    with pytest.raises(RuntimeError, match="no text output"):
        _parse_response(
            {
                "output_text": "",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            latency_ms=1,
            cost_meta=PRICES,
        )
