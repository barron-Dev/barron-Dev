from cyclothone.ai_security.privacy_proofs import PublicStatement, verify_private_attestation


def statement(key="a"*64):
    return PublicStatement("circuit-v1","1",key,"b"*64,"groth16",b"proof")


def test_missing_real_verifier_never_claims_zero_knowledge_verified():
    result = verify_private_attestation(statement(), trusted_circuit_hashes={"circuit-v1":"a"*64}, verifier=None)
    assert result["status"] == "unavailable"
    assert result["raw_private_data_received"] is False


def test_untrusted_verification_key_rejected():
    result = verify_private_attestation(statement(), trusted_circuit_hashes={}, verifier=None)
    assert result["status"] == "rejected"


def test_real_verifier_adapter_controls_verdict():
    class FakeVerifier:
        def verify(self, **kwargs):
            return True
    result = verify_private_attestation(statement(), trusted_circuit_hashes={"circuit-v1":"a"*64},
                                        verifier=FakeVerifier())
    assert result["status"] == "verified"
