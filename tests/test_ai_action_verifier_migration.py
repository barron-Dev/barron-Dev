from pathlib import Path


def test_database_rpc_recomputes_hashes_and_backend_verifies_ed25519():
    migration = Path("supabase/migrations/20261028070000_ai_action_verifier.sql").read_text()
    assert "extensions.digest(convert_to(p_payload_canonical, 'UTF8'), 'sha256')" in migration
    assert "public.ai_action_event_hash(" in migration
    assert "ai_action_payload_hash_mismatch" in migration
    assert "public.ai_action_canonical_jsonb(v_payload)" in migration
    assert "ai_action_payload_not_canonical" in migration
    assert "ai_action_number_outside_canonical_profile" in migration
    assert "(p_value #>> '{}') !~ '^-?(0|[1-9][0-9]*)$'" in migration
    assert "abs((p_value #>> '{}')::numeric) > 9007199254740991" in migration
    assert "CREATE OR REPLACE FUNCTION public.trust_register_signing_key(" in migration
    assert "'TRUST_EVIDENCE', 'AI_ACTION'" in migration
    assert "ai_action_event_hash_mismatch" in migration
    assert "p_verified boolean" not in migration.lower()
    assert "pgsodium.crypto_sign_verify_detached(" not in migration
    assert "Ed25519 verification occurs in the trusted Python backend" in migration
    service = Path("src/cyclothone/ai/action_receipt_service.py").read_text()
    assert "verify_action_envelope(" in service
    assert "if not verification.ok:" in service
    assert "FROM public.ai_runs WHERE id = p_run_id FOR UPDATE" in migration
    assert "UNIQUE (tenant_id, run_id, sequence)" in migration
    assert "UNIQUE (tenant_id, event_id)" in migration
    assert "p_sequence - 1" in migration
    assert "ai_action_previous_hash_mismatch" in migration


def test_database_rpc_is_service_role_only_and_append_only():
    migration = Path("supabase/migrations/20261028070000_ai_action_verifier.sql").read_text()
    assert "REVOKE ALL ON TABLE public.ai_action_verification_events" in migration
    assert "GRANT EXECUTE ON FUNCTION public.commit_ai_action_verification_event" in migration
    assert "ai_action_events_no_update_or_delete" in migration
    assert "BEFORE UPDATE OR DELETE" in migration
