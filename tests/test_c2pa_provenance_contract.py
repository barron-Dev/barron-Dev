from __future__ import annotations

import hashlib
from pathlib import Path

from cyclothone.provenance.c2pa_verify import (
    STATES, ZERO_HASH, build_receipt_hash, canonical_json, classify_validation,
)


def test_five_states_are_closed_set():
    assert STATES == {"VALID", "INVALID", "UNTRUSTED", "MISSING_PROVENANCE", "INDETERMINATE"}


def test_cai_trusted_state_is_valid_only_with_configured_anchors():
    assert classify_validation("Trusted", {}, True) == "VALID"
    assert classify_validation("Trusted", {}, False) == "UNTRUSTED"


def test_cai_valid_state_is_valid_but_untrusted():
    assert classify_validation("Valid", {}, True) == "UNTRUSTED"
    assert classify_validation("Valid", {}, False) == "UNTRUSTED"


def test_integrity_failure_is_invalid():
    results = {"validation_status": [{"code": "assertion.dataHash.mismatch"}]}
    assert classify_validation("Invalid", results, True) == "INVALID"


def test_unknown_validation_failure_abstains():
    assert classify_validation("Invalid", {"validation_status": [{"code": "unmapped.error"}]}, True) == "INDETERMINATE"


def test_trust_failure_is_untrusted():
    results = {"validation_status": [{"code": "signingCredential.untrusted"}]}
    assert classify_validation("Invalid", results, True) == "UNTRUSTED"


def test_receipt_hash_is_canonical_and_deterministic():
    payload = {"b": 2, "a": 1}
    assert build_receipt_hash(payload) == hashlib.sha256(canonical_json(payload)).hexdigest()
    assert build_receipt_hash(payload) == build_receipt_hash({"a": 1, "b": 2})
    assert len(ZERO_HASH) == 64



def test_trust_failure_and_unknown_failure_are_not_misclassified():
    assert classify_validation(
        "Invalid", {"validation_status": [{"code": "signingCredential.expired"}]}, True
    ) == "UNTRUSTED"
    assert classify_validation(
        "Trusted", {"validation_status": [{"code": "timeStamp.untrusted"}]}, True
    ) == "UNTRUSTED"
    assert classify_validation(
        "Trusted", {"validation_status": [{"code": "assertion.dataHash.mismatch"}]}, True
    ) == "INVALID"
    assert classify_validation(
        "Trusted", {"validation_status": [{"code": "claimSignature.missing"}]}, True
    ) == "INDETERMINATE"
    assert classify_validation(
        "Invalid", {"validation_status": [{"code": "unknown.validation.code"}]}, True
    ) == "INDETERMINATE"


def test_migration_enforces_canonical_signed_receipts_and_tenant_chain():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "supabase/migrations/20261030130000_synthetic_media_provenance_v1.sql").read_text()
    assert "tenant_sequence bigint NOT NULL" in sql
    assert "tsa_anchor_pems text[] NOT NULL" in sql
    assert "p_tsa_anchor_sha256 text[]" in sql
    assert "UNIQUE (tenant_id, tenant_sequence)" in sql
    assert "extensions.digest(convert_to(p_signed_payload_canonical, 'UTF8'), 'sha256')" in sql
    assert "REVOKE ALL ON FUNCTION public.append_media_provenance_receipt" in sql
    assert "TO service_role" in sql
    assert "BEFORE UPDATE OR DELETE ON public.media_provenance_receipts" in sql


def test_api_router_and_tenant_scoped_receipt_reads_are_wired():
    root = Path(__file__).resolve().parents[1]
    app = (root / "src/cyclothone/api/app.py").read_text()
    route = (root / "src/cyclothone/api/routes/media_provenance.py").read_text()
    verifier = (root / "src/cyclothone/provenance/c2pa_verify.py").read_text()
    assert "application.include_router(media_provenance_router,prefix='/api/v1')" in app
    assert route.count("Depends(provenance_principal)") == 3
    assert 'eq("tenant_id", tenant_id)' in route
    assert "Reader.try_create(str(path), context=context)" in verifier
    assert '"remote_manifest_fetch": False' in verifier
    assert '"trust_kind": "manifest"' in verifier
    assert '"trust_kind": "tsa"' in verifier



def test_async_worker_queue_is_private_leased_and_tenant_scoped():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "supabase/migrations/20261030130000_synthetic_media_provenance_v1.sql").read_text()
    route = (root / "src/cyclothone/api/routes/media_provenance.py").read_text()
    worker = (root / "src/cyclothone/provenance/worker.py").read_text()
    assert "VALUES ('cyclothone-provenance-staging', 'cyclothone-provenance-staging', false" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "lease_expires_at = now() + interval '30 minutes'" in sql
    assert "REVOKE ALL ON FUNCTION public.claim_media_provenance_job()" in sql
    assert "GRANT EXECUTE ON FUNCTION public.claim_media_provenance_job() TO service_role" in sql
    assert '@router.post("/verify-provenance", status_code=202)' in route
    assert 'tenant_id=tenant_id' in route
    assert 'client.storage.from_(BUCKET).download(object_path)' in worker
    assert "verify_and_persist_media" in worker



def test_sdk_pin_and_separate_official_manifest_tsa_trust_sources():
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text()
    requirements = (root / "requirements-server.txt").read_text()
    importer = (root / "scripts/activate_c2pa_trust_policy.py").read_text()
    verifier = (root / "src/cyclothone/provenance/c2pa_verify.py").read_text()
    assert "c2pa-python==0.38.1" in pyproject
    assert "c2pa-python==0.38.1" in requirements
    assert "C2PA-TSA-TRUST-LIST.json" in importer
    assert '"trust_kind": "manifest"' in verifier
    assert '"trust_kind": "tsa"' in verifier
    assert '"1.3.6.1.4.1.62558.2.1"' in verifier
    assert '"1.3.6.1.5.5.7.3.8"' in verifier
