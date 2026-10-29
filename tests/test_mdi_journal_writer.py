import base64, json, os
from uuid import uuid4
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cyclothone.mdi_ingestion.contracts import build_signed_contract
from cyclothone.mdi_ingestion.journal_writer import persist_verified_contract, JournalWriteError

def test_journal_writer_fails_closed_without_trusted_signer_key(monkeypatch):
    key=Ed25519PrivateKey.generate()
    contract=build_signed_contract(tenant_id=str(uuid4()),event_type="RF_REVIEW",
      disposition="human_review_required",payload={"source":"passive_sdr"},previous_hash=None,
      signer_key_id="unknown-key",private_key=key)
    monkeypatch.setenv("CYCLOTHONE_MDI_SIGNER_PUBLIC_KEYS_JSON","{}")
    with pytest.raises(JournalWriteError): persist_verified_contract(contract)

def test_journal_writer_rejects_tampered_contract_before_network(monkeypatch):
    from dataclasses import replace
    key=Ed25519PrivateKey.generate()
    pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    monkeypatch.setenv("CYCLOTHONE_MDI_SIGNER_PUBLIC_KEYS_JSON",json.dumps({"key-1":base64.b64encode(pub).decode()}))
    contract=build_signed_contract(tenant_id=str(uuid4()),event_type="RF_REVIEW",
      disposition="human_review_required",payload={"source":"passive_sdr"},previous_hash=None,
      signer_key_id="key-1",private_key=key)
    tampered=replace(contract,payload={"source":"forged"})
    with pytest.raises(JournalWriteError): persist_verified_contract(tampered)
