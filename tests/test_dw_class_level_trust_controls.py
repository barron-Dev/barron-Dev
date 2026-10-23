"""Source-level regression checks for DW trust-boundary migrations.

These checks do not replace isolated PostgreSQL integration tests. They guard the
structural contracts while the disposable live-schema base is being reconciled.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIG = ROOT / "supabase" / "migrations"


def read(name: str) -> str:
    return (MIG / name).read_text(encoding="utf-8")


class DwClassLevelTrustControlsTests(unittest.TestCase):
    def test_registry_is_fail_closed_and_receipts_have_distinct_mutability(self):
        sql = read("20261023100000_dw_evidence_policy_registry.sql")
        self.assertIn("create table if not exists public.dw_table_security_policy", sql.lower())
        self.assertIn("unregistered dw trust/evidence tables", sql.lower())
        self.assertIn("for r in", sql.lower())
        self.assertIn("'dw_evidence_ots_receipts', false", sql.lower())
        self.assertIn("'dw_onion_probe_evidence', true", sql.lower())
        self.assertIn("'dw_trust_canary_events', true", sql.lower())
        self.assertIn("'dw_discovery_job_runs', false", sql.lower())
        self.assertIn("'dw_content_translations', true", sql.lower())
        self.assertIn("dw_trust\\_%", sql.lower())
        self.assertIn("create trigger", sql.lower())

    def test_ots_receipt_requires_both_evidence_and_anchor(self):
        sql = read("20261022120000_dw_evidence_processing_entity_foundation.sql")
        start = sql.lower().index("create table if not exists public.dw_evidence_ots_receipts")
        end = sql.lower().index("create table if not exists public.dw_evidence_tsa_receipts", start)
        table = sql[start:end].lower()
        self.assertRegex(table, r"evidence_seq bigint not null")
        self.assertRegex(table, r"anchor_id uuid not null")
        self.assertIn("unique(evidence_seq, anchor_id)", table)
        self.assertNotIn("check((evidence_seq is null)", table)

    def test_ots_state_machine_has_five_states_and_no_presence_shortcut(self):
        sql = read("20261023110000_dw_ots_state_model.sql").lower()
        for state in ("pending", "confirmed", "failed", "expired", "invalid"):
            self.assertIn(f"'{state}'", sql)
        self.assertIn("dw_evidence_ots_confirmed_has_block", sql)
        self.assertIn("dw_evidence_ots_failed_has_reason", sql)
        self.assertIn("invalid ots state transition", sql)
        self.assertIn("legacy \"confirmed\" is only a caller-attested status", sql)
        self.assertIn("where state is null and verification_status = 'confirmed'", sql.replace("\\n", " "))
        self.assertIn("demoted_at", sql)
        self.assertIn("demoted_from_state", sql)
        self.assertIn("demotion_reason", sql)
        self.assertIn("ots demotion provenance is immutable", sql)
        self.assertIn("verified_at is not null", sql)

    def test_probe_rpc_uses_artifact_references_not_attestation_booleans(self):
        sql = read("20261023120000_dw_proof_bound_probe_rpc.sql").lower()
        self.assertIn("drop function if exists public.dw_record_onion_probe_result", sql)
        self.assertIn("p_tor_route_proof_id uuid", sql)
        self.assertIn("p_publisher_proof_id uuid", sql)
        self.assertIn("p_corroboration_proof_id uuid", sql)
        self.assertIn("p_evidence_seq bigint", sql)
        self.assertIn("for share", sql)
        self.assertNotRegex(
            sql,
            r"p_[a-z_]*(?:verified|proof|attested|corroborated|provenance_match|route_verified)[a-z_]*\s+boolean",
        )
        self.assertIn("revoke all on table public.%i from service_role", sql)

    def test_findings_join_remains_explicitly_blocked_until_wired(self):
        docs = (ROOT / "docs/dark-web/class-level-trust-controls.md").read_text(encoding="utf-8").lower()
        self.assertIn("dw_verified_findings", docs)
        self.assertIn("release blocker", docs)
        for finding_class in ("DW-04", "DW-POLICY-01", "DW-OTS-01", "DW-BASE-01", "DW-FINDING-01"):
            self.assertIn(finding_class.lower(), docs)


if __name__ == "__main__":
    unittest.main()
