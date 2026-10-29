from datetime import datetime, timezone
from cyclothone.ai_security.interdiction import ResponseRequest, evaluate_response_request


def request(action="return_to_home"):
    return ResponseRequest("t","robot-1",action,("e1",),"p1","operator-1",datetime.now(timezone.utc))


def test_pursuit_and_interception_are_denied_even_with_evidence():
    result = evaluate_response_request(request("intercept_target"), verified_evidence_ids=frozenset({"e1"}),
        device_tenant_id="t", device_allowlisted=True, kill_switch_active=False, human_approval_id="approved")
    assert result["decision"] == "deny"
    assert result["dispatch_permitted"] is False


def test_safety_action_requires_explicit_approval():
    result = evaluate_response_request(request(), verified_evidence_ids=frozenset({"e1"}),
        device_tenant_id="t", device_allowlisted=True, kill_switch_active=False)
    assert result["decision"] == "deny"
    assert "explicit_human_approval_required" in result["reasons"]


def test_kill_switch_and_tenant_mismatch_deny():
    result = evaluate_response_request(request("alert_operator"), verified_evidence_ids=frozenset({"e1"}),
        device_tenant_id="other", device_allowlisted=True, kill_switch_active=True)
    assert result["decision"] == "deny"
    assert result["dispatch_permitted"] is False
