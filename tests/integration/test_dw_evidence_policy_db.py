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
                            with self.assertRaises(InsufficientPrivilege):
                                with self.conn.transaction():
                                    with self.conn.cursor() as tx:
                                        tx.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))
                                        tx.execute(statement)

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
                with self.subTest(rejected_proof=label):
                    with self.assertRaises(psycopg.Error):
                        with self.conn.transaction():
                            with self.conn.cursor() as tx:
                                tx.execute("set local role service_role")
                                tx.execute(
                                    """select public.dw_record_onion_probe_result(
                                      %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb
                                    )""",
                                    (
                                        seed_id, "disposable-integration-test", route_id, request_url, 200,
                                        "0" * 64, "text/html", 1, publisher_id, corroboration_id, seq,
                                        "verified_publisher", None, "{}",
                                    ),
                                )
                cur.execute("select count(*) from public.dw_onion_probe_evidence")
                self.assertEqual(cur.fetchone()[0], probe_before, f"{label} rejection wrote probe evidence")
                cur.execute("select count(*) from public.dw_source_health_events")
                self.assertEqual(cur.fetchone()[0], health_before, f"{label} rejection wrote health event")

    def test_verified_findings_gate_exists_and_requires_confirmed_ots(self):
        if os.getenv("DW_REQUIRE_VERIFIED_FINDINGS") != "1":
            self.skipTest("release-gating finding view check not enabled")
        with self.conn.cursor() as cur:
            cur.execute("select to_regclass('public.dw_verified_findings')")
            self.assertIsNotNone(cur.fetchone()[0], "release blocker: dw_verified_findings is not wired")
            cur.execute(
                "select pg_get_viewdef('public.dw_verified_findings'::regclass, true)"
            )
            definition = cur.fetchone()[0].lower()
            self.assertIn("dw_evidence_ots_receipts", definition)
            self.assertIn("confirmed", definition)
            self.assertIn("state", definition)


if __name__ == "__main__":
    unittest.main()
