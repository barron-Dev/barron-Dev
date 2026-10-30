from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "supabase/migrations/20261030180000_global_execution_integrity_v1.sql").read_text()
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
