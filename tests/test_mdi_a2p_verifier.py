import hashlib, hmac, time
import pytest
from cyclothone.mdi_ingestion.a2p_verifier import verify_request_signature, A2PValidationError
from cyclothone.mdi_ingestion.contracts import canonical_json

def payload():
    return {"tenant_id":"tenant-1","message_id":"msg-1","from_e164":"+971501234567",
            "to_e164":"+971551234567","body":"Your verification code is 123456","issued_at":int(time.time())}

def test_a2p_request_signature_is_not_carrier_attestation():
    p=payload(); key=b"x"*32
    sig=hmac.new(key,canonical_json(p),hashlib.sha256).hexdigest()
    result=verify_request_signature(p,sig,key)
    assert result.accepted and result.reason_code=="client_request_authenticated"

def test_a2p_rejects_invalid_signature_and_stale_request():
    p=payload()
    assert not verify_request_signature(p,"00",b"x"*32).accepted
    p["issued_at"]-=1000
    with pytest.raises(A2PValidationError): verify_request_signature(p,"00",b"x"*32)
