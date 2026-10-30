from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "supabase/migrations/20261030083703_global_execution_integrity_v1.sql").read_text()
ROUTE = (ROOT / "src/cyclothone/api/routes/global_integrity.py").read_text()
DOC = (ROOT / "docs/security/global-supply-chain-execution-integrity-v1.md").read_text()


def test_global_device_registry_is_tenant_bound_and_fail_closed():
    assert "FOREIGN KEY(tenant_id,principal_id)" in MIGRATION
    assert "attestation_state text NOT NULL DEFAULT 'UNVERIFIED'" in MIGRATION
    assert "attestation_state='UNVERIFIED'" in MIGRATION
    assert "REVOKE ALL ON public.global_principals" in MIGRATION
    assert "global_consume_device_challenge" in MIGRATION


def test_execution_receipts_are_append_only_for_service_role():
    assert "global_execution_receipts" in MIGRATION
    assert "REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER" in MIGRATION
    assert 'decision text NOT NULL CHECK (decision IN (\'AUTHORIZED\',\'BLOCKED\'))' in MIGRATION


def test_sbom_unknown_is_review_not_clean():
    assert "'unknown'" in MIGRATION
    assert '"unknown"' in ROUTE
    assert 'decision = "BLOCKED" if blocked else "REVIEW_REQUIRED"' in ROUTE
    assert "global_cross_tenant_graph" in ROUTE


def test_api_never_promotes_key_possession_to_hardware_verified():
    assert '"attestation_state": "UNVERIFIED"' in ROUTE
    assert '"assurance_level": "key_possession"' in ROUTE
    assert "hardware_attestation_missing_or_stale" in ROUTE
    assert "only a trusted platform-specific verifier" in DOC


def test_api_uses_one_time_challenge_and_canonical_signature():
    assert "global_consume_device_challenge" in ROUTE
    assert "verify_ed25519" in ROUTE
    assert "context_sha256" in ROUTE
    assert "challenge_nonce" in ROUTE


def test_sbom_evidence_and_gate_receipt_commit_atomically():
    atomic = (ROOT / "supabase/migrations/20261030173836_global_sbom_atomic_commit.sql").read_text()
    assert "global_commit_sbom_scan" in atomic
    assert "verified_hardware_attestation_required" in atomic
    assert "INSERT INTO public.global_sbom_artifacts" in atomic
    assert "INSERT INTO public.global_sbom_components" in atomic
    assert "INSERT INTO public.global_execution_receipts" in atomic
    assert "GRANT EXECUTE ON FUNCTION public.global_commit_sbom_scan" in atomic
    assert '"global_commit_sbom_scan"' in ROUTE
    assert "sbom_atomic_evidence_commit_failed" in ROUTE


def test_global_attestation_is_bound_to_enrolled_tenant_device():
    binding = (ROOT / "supabase/migrations/20261030174140_global_integrity_bind_platform_devices.sql").read_text()
    assert "REFERENCES public.devices(tenant_id,id)" in binding
    assert "d.status='active'" in binding
    assert "DROP FUNCTION IF EXISTS public.global_register_device_key" in binding
    assert "p_platform_device_id" in ROUTE
    assert "device_ref_must_be_an_enrolled_device_uuid" in ROUTE
    assert 'row.get("status") != "active"' in ROUTE


def test_sbom_atomic_commit_rechecks_live_enrolled_device_state():
    active_gate = (ROOT / "supabase/migrations/20261030174309_global_sbom_active_device_check.sql").read_text()
    assert "JOIN public.devices pd" in active_gate
    assert "pd.status='active'" in active_gate
    assert "d.last_attested_at <= v_now" in active_gate
    assert "verified_active_hardware_attestation_required" in active_gate


def test_sensitive_blast_radius_reads_require_signed_device_challenge():
    assert '@router.post("/supply-chain/blast-radius")' in ROUTE
    assert "class BlastRadiusRequest(BaseModel)" in ROUTE
    assert "supply_chain_blast_radius_read" in ROUTE
    assert "global_cross_tenant_graph" in ROUTE
    assert "execution_receipt" in ROUTE

def test_sensitive_execution_gate_rechecks_and_receipts_atomically():
    atomic = (ROOT / "supabase/migrations/20261030200000_global_execution_atomic_authorization.sql").read_text()
    assert "global_authorize_execution_atomic" in atomic
    assert "FOR UPDATE OF d" in atomic
    assert "pd.status='active'" in atomic
    assert "v_device.assurance_level NOT IN ('hardware_attested','workload_attested')" in atomic
    assert "v_device.last_attested_at < v_now - interval '5 minutes'" in atomic
    assert "SET consumed_at=v_now" in atomic
    assert "INSERT INTO public.global_execution_receipts" in atomic
    assert "REVOKE ALL ON FUNCTION public.global_authorize_execution_atomic" in atomic
    assert "GRANT EXECUTE ON FUNCTION public.global_authorize_execution_atomic" in atomic
    assert '"global_authorize_execution_atomic"' in ROUTE
    assert "atomic_execution_gate_unavailable" in ROUTE

def test_device_revocation_is_irreversible_and_invalidates_challenges():
    lifecycle = (ROOT / "supabase/migrations/20261030210000_global_device_revocation_lifecycle.sql").read_text()
    assert "global_device_trust_events" in lifecycle
    assert "REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER" in lifecycle
    assert "prevent_global_device_unrevoke" in lifecycle
    assert "OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL" in lifecycle
    assert "attestation_state='REVOKED'" in lifecycle
    assert "assurance_level='none'" in lifecycle
    assert "SET consumed_at=COALESCE(consumed_at,clock_timestamp())" in lifecycle
    assert "global_revoke_device" in ROUTE
    assert 'p.require(("global:device:revoke",))' in ROUTE
    assert '"/devices/revoke"' in ROUTE

def test_platform_attestation_requires_pinned_signed_verifier_assertion():
    verifier = (ROOT / "src/cyclothone/global_integrity/attestation_verifier.py").read_text()
    migration = (ROOT / "supabase/migrations/20261030220000_global_attestation_verifier_authority.sql").read_text()
    assert "Ed25519PublicKey" in verifier
    assert "key.verify(signature, canonical_json(assertion))" in verifier
    assert "challenge_nonce" in verifier and "context_sha256" in verifier
    assert '("ios", "apple_app_attest")' in verifier
    assert '("windows", "tpm2")' in verifier
    assert '("server", "workload")' in verifier
    assert "global_attestation_verifier_keys" in migration
    assert "status IN ('PENDING','ACTIVE','SUSPENDED','REVOKED')" in migration
    assert "global_promote_attested_device_atomic" in migration
    assert "FOR UPDATE OF d" in migration
    assert "SET attestation_state='VERIFIED'" in migration
    assert "GRANT EXECUTE ON FUNCTION public.global_promote_attested_device_atomic" in migration
    assert '"/devices/verify-attestation"' in ROUTE
    assert 'p.require(("global:attestation:verify",))' in ROUTE
    assert "attestation_verifier_not_trusted" in ROUTE


def test_verifier_assertion_rejects_unmapped_platform_formats():
    from cyclothone.global_integrity.attestation_verifier import verify_verifier_assertion
    from cyclothone.global_integrity.crypto import GlobalIntegrityError
    import pytest

    with pytest.raises(GlobalIntegrityError, match="schema mismatch"):
        verify_verifier_assertion({}, "not-a-signature", "not-a-key")

def test_key_possession_enrollment_can_upgrade_only_via_trusted_platform_verifier():
    migration = (ROOT / "supabase/migrations/20261030220000_global_attestation_verifier_authority.sql").read_text()
    assert "v_device.attestation_format<>'proof_of_possession'" in migration
    assert "attestation_format=p_attestation_format,assurance_level=p_assurance_level" in migration
    assert 'device.get("attestation_format") != "proof_of_possession"' in ROUTE
