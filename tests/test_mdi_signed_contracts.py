from datetime import datetime, timezone
from uuid import uuid4
from dataclasses import replace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyclothone.mdi_ingestion.contracts import build_signed_contract, verify_signed_contract

def test_signed_contract_verifies_and_binds_payload():
    key=Ed25519PrivateKey.generate()
    c=build_signed_contract(tenant_id=str(uuid4()),event_type="RF_ANOMALY_REVIEW",
      disposition="human_review_required",payload={"source":"passive_sdr","frequency_hz":935200000},
      previous_hash=None,signer_key_id="test-key-1",private_key=key,
      created_at=datetime(2026,10,29,tzinfo=timezone.utc))
    assert verify_signed_contract(c,key.public_key())
    assert not verify_signed_contract(replace(c,payload={"source":"altered"}),key.public_key())

def test_contract_rejects_unknown_disposition():
    key=Ed25519PrivateKey.generate()
    try:
        build_signed_contract(tenant_id=str(uuid4()),event_type="SOURCE_STATUS",
          disposition="clean",payload={"coverage":"unavailable"},previous_hash=None,
          signer_key_id="test-key",private_key=key)
    except ValueError: pass
    else: raise AssertionError("unknown disposition must fail closed")
