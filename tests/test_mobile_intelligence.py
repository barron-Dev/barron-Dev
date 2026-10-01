from cyclothone.mobile_intelligence.service import MobileIntelligenceError, MobileIntelligenceService, normalize_number


def test_normalize_e164():
    assert normalize_number("+234 801-234-5678") == "+2348012345678"


def test_reject_invalid_number():
    try:
        normalize_number("08012345678")
    except MobileIntelligenceError as exc:
        assert str(exc) == "invalid_e164_number"
    else:
        raise AssertionError("invalid number accepted")


def test_capabilities_are_explicit():
    assert "location_retrieval" in __import__("cyclothone.mobile_intelligence.service", fromlist=["CAPABILITIES"]).CAPABILITIES
    assert "device_identifier" in __import__("cyclothone.mobile_intelligence.service", fromlist=["CAPABILITIES"]).CAPABILITIES


def test_payload_requires_location_for_verification():
    service = MobileIntelligenceService()
    try:
        service._payload("location_verification", "+2348012345678", 24, None, None, None)
    except MobileIntelligenceError as exc:
        assert str(exc) == "location_verification_coordinates_required"
    else:
        raise AssertionError("location verification accepted without coordinates")
