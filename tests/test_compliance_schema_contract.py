from pathlib import Path


def test_compliance_freshness_migration_is_additive_and_idempotent():
    migration = Path("sql/20261011100000_compliance_evidence_freshness.sql").read_text()
    assert "ALTER TABLE IF EXISTS public.compliance_control_status" in migration
    assert "ADD COLUMN IF NOT EXISTS evidence_valid_until timestamptz" in migration


def test_compliance_service_schema_contract_is_documented():
    service = Path("src/cyclothone/compliance/service.py").read_text()
    assert "evidence_valid_until" in service
