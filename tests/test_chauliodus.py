import pytest
from cyclothone.chauliodus.normalize import NumberNormalizer
from cyclothone.chauliodus.risk import NumberRiskEngine


def test_valid_benin_number():
    n = NumberNormalizer.normalize("+22901970000")
    assert n.e164.startswith("+229")
    assert n.country == "BJ"
    assert len(n.e164_hash) == 64


def test_rejects_garbage():
    with pytest.raises(ValueError):
        NumberNormalizer.normalize("not a number")


def test_hash_is_stable():
    a = NumberNormalizer.normalize("+22901970000")
    b = NumberNormalizer.normalize("+22901970000")
    assert a.e164_hash == b.e164_hash


def test_voip_flag():
    r = NumberRiskEngine().assess(e164="+12015550123", country="US", line_type="voip", carrier_name="Twilio")
    assert r.voip_probability >= 0.9


def test_fraud_score_bounded():
    r = NumberRiskEngine().assess(e164="+22901970000", country="BJ", line_type="mobile", carrier_name="MTN", report_count=20, campaign_associations=3, breach_hits=5)
    assert 0.0 <= r.fraud_score <= 1.0
    assert r.fraud_score > 0.5


def test_no_signals_low_score():
    r = NumberRiskEngine().assess(e164="+22901970000", country="BJ", line_type="mobile", carrier_name="MTN")
    assert r.fraud_score < 0.3
