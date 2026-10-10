from pathlib import Path


def test_retention_and_legal_hold_schema_is_fail_closed_by_default():
    migration = Path("sql/20261011120000_governance_retention_holds.sql").read_text()
    assert "enabled boolean NOT NULL DEFAULT false" in migration
    assert "active boolean NOT NULL DEFAULT true" in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "governance_retention_policy_audit_trg" in migration
    assert "governance_legal_hold_audit_trg" in migration


def test_retention_controls_do_not_claim_execution():
    docs = Path("docs/governance/retention-and-legal-holds.md").read_text()
    assert "does not run deletion" in docs
    assert "only effective after every deletion/expiry worker checks active holds" in docs
