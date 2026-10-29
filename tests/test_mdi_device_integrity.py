from cyclothone.mdi_ingestion.device_integrity import DeviceIntegrityError, evaluate_device_integrity
TENANT = "00000000-0000-0000-0000-000000000001"
DEVICE = "a" * 64

def test_same_inputs_produce_same_hash_and_order():
    items = [{"signal":"root_indicator","observed":True,"source":"os_adapter"},{"signal":"tls_validation_failure","observed":True,"source":"network_adapter"}]
    a = evaluate_device_integrity(tenant_id=TENANT,device_key=DEVICE,observations=items,platform="android",adapter_version="1")
    b = evaluate_device_integrity(tenant_id=TENANT,device_key=DEVICE,observations=list(reversed(items)),platform="android",adapter_version="1")
    assert a.evidence_hash == b.evidence_hash
    assert a.disposition == "human_review_required"

def test_unavailable_is_never_clean():
    r = evaluate_device_integrity(tenant_id=TENANT,device_key=DEVICE,observations=[],platform="ios",adapter_version="1",coverage="unavailable")
    assert r.disposition == "source_unavailable"
    assert "cannot be represented as verified clean" in " ".join(r.limitations)

def test_failed_attestation_restricts_sensitive_access():
    r = evaluate_device_integrity(tenant_id=TENANT,device_key=DEVICE,observations=[{"signal":"device_attestation_failed","observed":True,"source":"attestation"}],platform="android",adapter_version="1")
    assert r.severity == 5 and r.recommended_action == "restrict_sensitive_access_and_require_review"

def test_unknown_and_duplicate_signals_rejected():
    for items in ([{"signal":"zero_click_detected","observed":True,"source":"os_adapter"}],[{"signal":"root_indicator","observed":True,"source":"os_adapter"}]*2):
        try:
            evaluate_device_integrity(tenant_id=TENANT,device_key=DEVICE,observations=items,platform="android",adapter_version="1")
            assert False
        except DeviceIntegrityError:
            pass
