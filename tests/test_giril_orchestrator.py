from src.cyclothone.giril.orchestrator import AuthoritativeVerificationOrchestrator, to_check_record

LEI = "529900T8BM49AURSDO55"

def payload(lei=LEI, status="ACTIVE"):
    return {"data": {"attributes": {"lei": lei, "entityStatus": status, "entity": {"legalName": {"name": "Example Entity"}}}}}

def test_active_match_verifies():
    result = AuthoritativeVerificationOrchestrator(lambda lei: payload(lei), "GLEIF_LEI").verify_lei(LEI)
    assert result.status == "VERIFIED"

def test_inactive_does_not_verify():
    result = AuthoritativeVerificationOrchestrator(lambda lei: payload(lei, "INACTIVE"), "GLEIF_LEI").verify_lei(LEI)
    assert result.status == "NOT_VERIFIED"

def test_multiple_matches_manual_review():
    result = AuthoritativeVerificationOrchestrator(lambda _: {"data": [{}, {}]}, "GLEIF_LEI").verify_lei(LEI)
    assert result.status == "MANUAL_REVIEW"

def test_check_record_does_not_create_trust_evidence():
    result = AuthoritativeVerificationOrchestrator(lambda lei: payload(lei), "GLEIF_LEI").verify_lei(LEI)
    check = to_check_record(result, "case-1", "giril-verifier-v1")
    assert "trust_evidence_id" not in check
    assert check["check_type"] == "COMPANY_REGISTRY"
