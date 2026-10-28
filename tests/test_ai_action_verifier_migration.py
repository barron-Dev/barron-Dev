from pathlib import Path


def test_database_rpc_recomputes_hashes_and_verifies_ed25519():
    migration = Path("supabase/migrations/20261028070000_ai_action_verifier.sql").read_text()
    assert "extensions.digest(convert_to(p_payload_canonical, 'UTF8'), 'sha256')" in migration
    assert "public.ai_action_event_hash(" in migration
    assert "pgsodium.crypto_sign_verify_detached(" in migration
    assert "ai_action_payload_hash_mismatch" in migration
    assert "ai_action_event_hash_mismatch" in migration
    assert "ai_action_signature_invalid" in migration
    assert "p_verified boolean" not in migration.lower()


def test_database_rpc_is_service_role_only_and_append_only():
    migration = Path("supabase/migrations/20261028070000_ai_action_verifier.sql").read_text()
    assert "REVOKE ALL ON TABLE public.ai_action_verification_events" in migration
    assert "GRANT EXECUTE ON FUNCTION public.commit_ai_action_verification_event" in migration
    assert "ai_action_events_no_update_or_delete" in migration
    assert "BEFORE UPDATE OR DELETE" in migration
