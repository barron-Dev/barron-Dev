from pathlib import Path


def test_governance_privacy_request_migration_is_tenant_scoped_and_audited():
    migration = Path("sql/20261011110000_governance_privacy_requests.sql").read_text()
    assert "tenant_id uuid NOT NULL" in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "governance_privacy_request_audit_trg" in migration
    assert "CREATE TABLE IF NOT EXISTS public.governance_audit_events" in migration


def test_governance_route_enforces_scopes_and_tenant_filters():
    route = Path("src/cyclothone/api/routes/governance.py").read_text()
    assert 'principal.require(("privacy:manage",))' in route
    assert 'principal.require(("privacy:read",))' in route
    assert '.eq("tenant_id", tenant_id)' in route
    assert 'invalid transition:' in route
