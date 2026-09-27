from __future__ import annotations

from cyclothone.mobile_intelligence.advanced import (
    SS7Anomaly,
    detect_otp_relay,
    flash_call_anomaly,
    link_cross_border,
    trunk_fingerprint,
)


def test_ss7_anomaly_blocks_high_rate():
    detector = SS7Anomaly()
    result = None
    for i in range(101):
        result = detector.observe("gt-a", "ATI", i * 10)
    assert result is not None
    assert result.action == "block_gt"
    assert result.z_score > 5


def test_otp_relay_blocks_subsecond_read():
    result = detect_otp_relay(
        msisdn="+971000000000",
        imei="imei",
        otp_issued_at_ms=1_000,
        otp_read_at_ms=1_500,
        carrier_mcc="424",
        ip_asn="mobile",
    )
    assert result.block is True
    assert result.reason == "subsecond_read"


def test_flash_call_burst():
    calls = [{"from": "x", "durationMs": 500, "at": 100_000 + i * 10_000} for i in range(6)]
    result = flash_call_anomaly(calls, now_ms=160_000)
    assert result and result[0]["cluster"] == "x"


def test_trunk_fingerprint_is_deterministic():
    invite = {"user-agent": "ua", "p-asserted-identity": "pai", "allow": "INVITE", "supported": "100rel", "contact": "sip:x"}
    assert trunk_fingerprint(invite) == trunk_fingerprint(dict(invite))


def test_cross_border_link():
    events = [
        {"subjectId": "a", "country": "AE", "imei": "i", "at": 0, "event": "activate"},
        {"subjectId": "b", "country": "NG", "imei": "i", "at": 1000, "event": "activate"},
    ]
    result = link_cross_border(events)
    assert result and result[0][0:2] == ("a", "b")
