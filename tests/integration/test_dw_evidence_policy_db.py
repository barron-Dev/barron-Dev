"""Disposable-database checks for DW evidence trust boundaries.

Set DW_TEST_ALLOW_DISPOSABLE=1 and DW_TEST_DATABASE_URL only for an isolated
PostgreSQL database. The live Cyclothone Supabase project is explicitly blocked.
Proof-rejection tests require pre-created verifier-owned fixtures identified by
environment variables; this test never creates proof artifacts.
"""
from __future__ import annotations

import os
import unittest
import uuid

try:
    import psycopg
    from psycopg import sql
    from psycopg.errors import InsufficientPrivilege
except ImportError:  # optional dependency for isolated integration runs
    psycopg = None
    sql = None
    InsufficientPrivilege = Exception

PRODUCTION_REF = "whcomikcftbousoqzeal"


def disposable_dsn() -> str | None:
    dsn = os.getenv("DW_TEST_DATABASE_URL")
    if os.getenv("DW_TEST_ALLOW_DISPOSABLE") != "1" or not dsn:
        return None
    if PRODUCTION_REF in dsn:
        raise RuntimeError("Refusing to run DW integration tests against production Supabase")
    return dsn


@unittest.skipUnless(psycopg is not None and disposable_dsn(), "isolated DW database not configured")
class DwEvidencePolicyDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = psycopg.connect(disposable_dsn())
        cls.conn.autocommit = False

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_anon_and_authenticated_cannot_write_any_registered_table(self):
        with self.conn.cursor() as cur:
            cur.execute(
                "select tablename, grants_to_service_role from public.dw_table_security_policy order by tablename"
            )
            policies = cur.fetchall()
            self.assertTrue(policies, "policy registry must not be empty")

            for table, grants in policies:
                cur.execute(
                    "select column_name from information_schema.columns "
                    "where table_schema='public' and table_name=%s order by ordinal_position limit 1",
                    (table,),
                )
                row = cur.fetchone()
                self.assertIsNotNone(row, f"registered table missing: {table}")
                first_col = row[0]
                for role in ("anon", "authenticated"):
                    statements = (
                        sql.SQL("insert into public.{} default values").format(sql.Identifier(table)),
                        sql.SQL("update public.{} set {} = {} where false").format(
                            sql.Identifier(table), sql.Identifier(first_col), sql.Identifier(first_col)
                        ),
                        sql.SQL("delete from public.{} where false").format(sql.Identifier(table)),
                    )
                    for statement in statements:
                        with self.subTest(table=table, role=role, statement=statement.as_string(self.conn)):
                            class UnexpectedWritePermission(Exception):
                                pass
                            try:
                                with self.conn.transaction():
                                    with self.conn.cursor() as tx:
                                        tx.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))
                                        tx.execute(statement)
                                        raise UnexpectedWritePermission()
                            except InsufficientPrivilege:
                                pass
                            except UnexpectedWritePermission:
                                self.fail(f"{role} unexpectedly had write permission on {table}")

                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                    with self.subTest(table=table, service_role_privilege=privilege):
                        cur.execute(
                            "select has_table_privilege('service_role', %s, %s)",
                            (f"public.{table}", privilege),
                        )
                        actual = cur.fetchone()[0]
                        self.assertEqual(actual, privilege in grants, f"{table}: unexpected {privilege} grant")

    def test_proof_rejections_are_atomic(self):
        required = {
            "DW_TEST_SEED_ID": os.getenv("DW_TEST_SEED_ID"),
            "DW_TEST_REQUEST_URL": os.getenv("DW_TEST_REQUEST_URL"),
            "DW_TEST_RESPONSE_SHA256": os.getenv("DW_TEST_RESPONSE_SHA256"),
            "DW_TEST_VALID_ROUTE_PROOF_ID": os.getenv("DW_TEST_VALID_ROUTE_PROOF_ID"),
            "DW_TEST_VALID_PUBLISHER_PROOF_ID": os.getenv("DW_TEST_VALID_PUBLISHER_PROOF_ID"),
            "DW_TEST_VALID_CORROBORATION_PROOF_ID": os.getenv("DW_TEST_VALID_CORROBORATION_PROOF_ID"),
            "DW_TEST_VALID_EVIDENCE_SEQ": os.getenv("DW_TEST_VALID_EVIDENCE_SEQ"),
            "DW_TEST_WRONG_SOURCE_EVIDENCE_SEQ": os.getenv("DW_TEST_WRONG_SOURCE_EVIDENCE_SEQ"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            self.skipTest("requires verifier-owned disposable fixtures: " + ", ".join(missing))

        seed_id = required["DW_TEST_SEED_ID"]
        request_url = required["DW_TEST_REQUEST_URL"]
        response_sha256 = required["DW_TEST_RESPONSE_SHA256"]
        if len(response_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in response_sha256):
            self.fail("DW_TEST_RESPONSE_SHA256 must be a lowercase SHA-256 hex digest")
        valid_route = required["DW_TEST_VALID_ROUTE_PROOF_ID"]
        valid_publisher = required["DW_TEST_VALID_PUBLISHER_PROOF_ID"]
        valid_corroboration = required["DW_TEST_VALID_CORROBORATION_PROOF_ID"]
        evidence_seq = int(required["DW_TEST_VALID_EVIDENCE_SEQ"])
        wrong_evidence_seq = int(required["DW_TEST_WRONG_SOURCE_EVIDENCE_SEQ"])
        cases = [
            ("route", str(uuid.uuid4()), valid_publisher, valid_corroboration, evidence_seq),
            ( "publisher", valid_route, str(uuid.uuid4()), valid_corroboration, evidence_seq),
            ( "corroboration", valid_route, valid_publisher, str(uuid.uuid4()), evidence_seq),
            ( "evidence", valid_route, valid_publisher, valid_corroboration, wrong_evidence_seq),
        ]
        with self.conn.cursor() as cur:
            for label, route_id, publisher_id, corroboration_id, seq in cases:
                cur.execute("select count(*) from public.dw_onion_probe_evidence")
                probe_before = cur.fetchone()[0]
                cur.execute("select count(*) from public.dw_source_health_events")
                health_before = cur.fetchone()[0]
                cur.execute("select count(*) from public.dw_evidence_ots_receipts")
                receipt_before = cur.fetchone()[0]
                cur.execute("select count(*) from public.dw_findings")
                finding_before = cur.fetchone()[0]
                cur.execute("select count(*) from public.dw_alerts")
                alert_before = cur.fetchone()[0]
                cur.execute(
                    "select status, candidate_trust, monitoring_enabled, last_checked, last_status "
                    "from public.dw_onion_seeds where id=%s",
                    (seed_id,),
                )
                seed_before = cur.fetchone()
                self.assertIsNotNone(seed_before, "disposable seed fixture must exist")
                with self.subTest(rejected_proof=label):
                    class UnexpectedProofSuccess(Exception):
                        pass
                    try:
                        with self.conn.transaction():
                            with self.conn.cursor() as tx:
                                tx.execute("set local role service_role")
                                tx.execute(
                                    """select public.dw_record_onion_probe_result(
                                      %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb
                                    )""",
                                    (
                                        seed_id, "disposable-integration-test", route_id, request_url, 200,
                                        response_sha256, "text/html", 1, publisher_id, corroboration_id, seq,
                                        "verified_publisher", None, "{}",
                                    ),
                                )
                                raise UnexpectedProofSuccess()
                    except psycopg.Error as exc:
                        self.assertEqual(exc.sqlstate, "42501", f"{label} rejection failed for an unexpected reason: {exc}")
                        expected_message = {
                            "route": "verified Tor route proof missing",
                            "publisher": "verified publisher proof missing",
                            "corroboration": "independent corroboration proof missing",
                            "evidence": "evidence sequence does not belong",
                        }[label]
                        self.assertIn(expected_message, str(exc))
                    except UnexpectedProofSuccess:
                        self.fail(f"{label} invalid proof was accepted")
                cur.execute("select count(*) from public.dw_onion_probe_evidence")
                self.assertEqual(cur.fetchone()[0], probe_before, f"{label} rejection wrote probe evidence")
                cur.execute("select count(*) from public.dw_source_health_events")
                self.assertEqual(cur.fetchone()[0], health_before, f"{label} rejection wrote health event")
                cur.execute("select count(*) from public.dw_evidence_ots_receipts")
                self.assertEqual(cur.fetchone()[0], receipt_before, f"{label} rejection wrote OTS receipt")
                cur.execute("select count(*) from public.dw_findings")
                self.assertEqual(cur.fetchone()[0], finding_before, f"{label} rejection wrote finding")
                cur.execute("select count(*) from public.dw_alerts")
                self.assertEqual(cur.fetchone()[0], alert_before, f"{label} rejection wrote alert")
                cur.execute(
                    "select status, candidate_trust, monitoring_enabled, last_checked, last_status "
                    "from public.dw_onion_seeds where id=%s",
                    (seed_id,),
                )
                self.assertEqual(cur.fetchone(), seed_before, f"{label} rejection changed seed status")

    def test_verified_findings_gate_exists_and_requires_confirmed_ots(self):
        if os.getenv("DW_REQUIRE_VERIFIED_FINDINGS") != "1":
            self.skipTest("release-gating finding view check not enabled")
        evidence_seq = os.getenv("DW_TEST_OTS_EVIDENCE_SEQ")
        receipt_id = os.getenv("DW_TEST_OTS_RECEIPT_ID")
        block_height = os.getenv("DW_TEST_CONFIRMED_BLOCK_HEIGHT")
        if not evidence_seq or not receipt_id or not block_height:
            self.skipTest("requires a pending OTS receipt linked to a real disposable evidence-backed finding")
        with self.conn.cursor() as cur:
            cur.execute("select to_regclass('public.dw_verified_findings')")
            self.assertIsNotNone(cur.fetchone()[0], "release blocker: dw_verified_findings is not wired")
            cur.execute("select pg_get_viewdef('public.dw_verified_findings'::regclass, true)")
            definition = cur.fetchone()[0].lower()
            self.assertIn("dw_evidence_ots_receipts", definition)
            self.assertIn("confirmed", definition)
            self.assertIn("state", definition)
            self.assertIn("evidence_seq", definition)
            cur.execute(
                "select state, evidence_seq from public.dw_evidence_ots_receipts where id=%s",
                (receipt_id,),
            )
            receipt = cur.fetchone()
            self.assertIsNotNone(receipt, "OTS receipt fixture must exist")
            self.assertEqual(receipt[0], "pending", "OTS receipt fixture must start pending")
            self.assertEqual(receipt[1], int(evidence_seq))

            class RollbackStateFixture(Exception):
                pass

            for state in ("pending", "confirmed", "failed", "expired", "invalid"):
                with self.subTest(ots_state=state):
                    try:
                        with self.conn.transaction():
                            with self.conn.cursor() as tx:
                                if state != "pending":
                                    tx.execute(
                                        """update public.dw_evidence_ots_receipts
                                              set state=%s,
                                                  bitcoin_block_height=case when %s='confirmed' then %s else bitcoin_block_height end,
                                                  verified_at=case when %s='confirmed' then now() else verified_at end,
                                                  failure_reason=case when %s='failed' then 'disposable verifier rejection' else failure_reason end
                                            where id=%s""",
                                        (state, state, int(block_height), state, state, receipt_id),
                                    )
                                    self.assertEqual(tx.rowcount, 1)
                                tx.execute(
                                    "select count(*) from public.dw_verified_findings where evidence_seq=%s",
                                    (int(evidence_seq),),
                                )
                                visible = tx.fetchone()[0] > 0
                                self.assertEqual(
                                    visible, state == "confirmed",
                                    f"evidence with OTS state {state} has incorrect verified-finding visibility",
                                )
                                raise RollbackStateFixture()
                    except RollbackStateFixture:
                        pass


if __name__ == "__main__":
    unittest.main()
