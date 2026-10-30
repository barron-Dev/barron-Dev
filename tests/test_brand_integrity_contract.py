from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_live_schema_integrity_migration_is_invoker_and_service_role_only():
    sql = read("supabase/migrations/20261030100000_brand_protection_integrity_v1.sql")
    rpc = sql.split("create or replace function public.record_brand_threat", 1)[1]
    assert "security invoker" in rpc.lower()
    grants = sql.split("revoke all on function public.record_brand_threat", 1)[1]
    assert "from public,anon,authenticated" in grants.replace(" ", "").lower()
    assert "to service_role" in grants
    assert "security definer" not in rpc.lower()


def test_rpc_checks_tenant_brand_binding_and_preserves_verified_state():
    sql = read("supabase/migrations/20261030100000_brand_protection_integrity_v1.sql")
    assert "BRAND_TENANT_MISMATCH" in sql
    assert "foreign key (tenant_id,brand_id)" in sql
    assert "verification_state=brand_threats.verification_state" in sql


def test_threat_api_uses_live_timestamp_and_never_client_promotes_verified():
    source = read("src/cyclothone/api/routes/brand.py")
    assert 'order("first_seen_at"' in source
    assert 'verification_state: str | None = Query' in source
    assert 'pattern="^(open|investigating|monitoring' in source
    assert "verified" not in source.split("class ThreatUpdate", 1)[1].split("@router.patch", 1)[0]


def test_takedown_is_verified_evidence_gated_and_not_auto_dispatched():
    source = read("src/cyclothone/brand/takedown.py")
    assert 'verification_state") != "verified"' in source
    assert 'brand_evidence' in source
    assert '"dispatch_requested": False' in source
    assert '"dispatch_state": "not_dispatched"' in source
