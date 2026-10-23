# Block 2 — DW live-schema reconciliation

**Purpose:** define the disposable PostgreSQL base required to validate PR #76 and the class-level trust-control migrations. This is an inventory and test procedure, not a production change. Observations below are from read-only production inspection on 2026-10-23, with a targeted table-presence recheck on 2026-10-24.

## Reconciliation table

| Area | Last verified live state | Preview migration consequence | Status |
|---|---|---|---|
| Discovery queue | `dw_source_discovery_queue` exists. Queue lease/claim/complete/quarantine migrations are already recorded in the live migration ledger. The last measured backlog was 26,062 rows, all `deferred`, with zero active leases. | Do not replay PR #73 queue migrations blindly. Base the preview DB on the existing queue schema and current RPC definitions. | Present; reconcile exact DDL/ACL |
| Onion inventory | `dw_onion_seeds` exists; last measured count was 1,023. Last measured monitoring-enabled count was 0. | PR #76 tables and proof-bound RPC must reference this existing table and preserve candidate-vs-verified separation. | Present |
| Probe evidence | `dw_onion_probe_evidence` exists; last measured count was 0. Existing `dw_record_onion_probe_result` accepts caller-supplied boolean claims for Tor route, publisher proof, corroboration, and provenance. Its execute ACL was limited to `postgres` and `service_role`. | Preview migration revokes/drops the legacy signature and replaces it with artifact-reference validation. The production function is not changed by this branch. | Present; trust gap identified |
| Source health events | `dw_source_health_events` exists; last measured count was 0. | Registry must lock direct app writes and let only trusted RPCs write observations. | Present |
| PR #76 trust tables | The targeted live check found none of: `dw_client_auth_credentials`, `dw_circuit_assignments`, `dw_mirror_integrity`, `dw_content_fingerprints`, `dw_publisher_key_pins`, `dw_content_embeddings`, `dw_source_anomaly_events`, `dw_descriptor_health`, `dw_trust_honeypot_observations`, `dw_trust_canary_events`. | The trust foundation is not applied in production; validate its dependency chain only in the disposable preview database. | Absent in live |
| PR #76 evidence-processing tables | The targeted live check found none of: `dw_evidence_log`, `dw_evidence_ots_receipts`, `dw_evidence_tsa_receipts`, `dw_merkle_anchors`, `dw_sanitized_content`, `dw_entities`, `dw_entity_aliases`, `dw_entity_links`, `dw_entity_mentions`, `dw_content_translations`, `dw_ner_extractions`, `dw_discovery_job_runs`, `dw_discovery_dead_letters`, `dw_source_health`. | Repair the malformed OTS/TSA DDL first; then test registry, state machine, and proof-bound RPC in migration order. | Absent in live |
| Proof-bound tables | `dw_tor_route_proofs`, `dw_publisher_proofs`, and `dw_corroboration_proofs` do not exist in live. | New tables are preview-only and deliberately read-only to `service_role`; no trusted proof writer exists yet, so success must fail closed. | Absent in live |
| Finding path | Live has `dw_findings` and `dw_alerts`; it has no `dw_verified_findings`. Legacy `dw_findings` has no `evidence_seq` column. | OTS state exclusion cannot honestly be called wired until an evidence-linked finding materializer/view and customer/API path are implemented. | Release blocker |
| Extensions | Last verified: `pg_trgm` and `pgcrypto` are in schema `extensions`; `vector` is in `public`. | Preserve qualified extension operators/functions and verify extension placement and exact versions in the disposable DB. | Known; exact versions must be rechecked |
| Production migration ledger | Queue foundation versions observed: `20261021064731` lease columns, `20261021064748` claim/complete RPC, `20261021070050` operational-table lockdown, `20261021081258` backlog quarantine forward. PR #76 migration versions are absent. | Never infer that a migration is applied from a filename, branch, or green Vercel status. | Reconciled at ledger level |

## Gate: create a faithful disposable schema base

**Do not start the OTS verifier, trusted proof writers, verified-finding view/materializer, or customer/API finding path until the restored-schema inventory diff is empty and reviewed.** A migration ledger, table-presence list, or `pg_dump` file by itself is not proof of reproducibility.

The snapshot must be produced from an authorized read-only connection to the live database and restored only into an isolated disposable database. Never point restore commands at production. If no authorized environment has `psql`, `pg_dumpall`, `pg_dump`, and network access to both endpoints, record that as a release blocker: **schema not recoverable with current team/tooling**. Do not substitute a partial inventory or claim an empty diff.

### 1. Record server and extension prerequisites

Run against live and save deterministic output:

```sql
SELECT current_setting('server_version') AS server_version,
       current_setting('server_version_num') AS server_version_num;
SELECT extname, extversion
FROM pg_extension
ORDER BY extname;
```

Use a disposable PostgreSQL image matching the live **major version** (the last known live major is PostgreSQL 17, so do not copy a `postgres:15` example without new evidence). Install the required extensions at compatible, matching versions and in the same schemas before judging the restore. In particular, record the actual versions and schema locations for `pg_trgm`, `pgcrypto`, and `vector`; the prior schema placement observation was `pg_trgm`/`pgcrypto` in `extensions` and `vector` in `public`, but exact versions still need a fresh check.

### 2. Capture roles first, then schema with ownership and grants

Use a protected workspace because role and schema dumps can reveal privileged role names and database structure. Keep credentials out of shell history, logs, artifacts, and Git.

```sh
umask 077
pg_dumpall --roles-only "$LIVE_DATABASE_URL" > 01_roles.sql
pg_dump --schema-only --no-comments "$LIVE_DATABASE_URL" > 02_schema.sql
```

These commands intentionally preserve schema ownership and GRANT/REVOKE statements. **Do not add `--no-owner` or `--no-privileges`**: doing so would discard properties this gate must verify. Review the roles-only output for environment-specific role attributes before replaying it in a disposable instance; do not copy secrets or production authentication material into shared artifacts. Create/reconcile required roles in the isolated target first, then restore `02_schema.sql` into that target. Resolve extension prerequisites before interpreting restore errors. Capture command versions, exit codes, stderr, and artifact hashes; do not call a failed or partial dump a snapshot.

### 3. Run canonical catalog inventories on both databases

Run the same SQL inventory bundle against live and the restored target, save results as sorted, stable text/CSV, and compare the normalized results with `diff -u`. Do not compare raw `pg_dump` files as the acceptance test. The inventory must cover at least the following.

**Functions, including identity signature, security-definer setting, ACL, and definition hash**

```sql
SELECT n.nspname AS schema_name,
       p.proname AS function_name,
       pg_get_function_identity_arguments(p.oid) AS identity_arguments,
       p.prosecdef AS security_definer,
       COALESCE(p.proacl::text, '<default>') AS acl,
       md5(pg_get_functiondef(p.oid)) AS definition_md5
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY 1, 2, 3;
```

**Tables, owner, RLS flags, and ACL**

```sql
SELECT n.nspname AS schema_name,
       c.relname AS table_name,
       pg_get_userbyid(c.relowner) AS owner_name,
       c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS rls_forced,
       COALESCE(c.relacl::text, '<default>') AS acl
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY 1, 2;
```

**RLS policies**

```sql
SELECT schemaname, tablename, policyname, permissive, roles,
       cmd, qual, with_check
FROM pg_policies
ORDER BY schemaname, tablename, policyname;
```

**Non-internal triggers and definitions**

```sql
SELECT n.nspname AS schema_name,
       c.relname AS relation_name,
       t.tgname AS trigger_name,
       pg_get_triggerdef(t.oid, true) AS trigger_definition,
       t.tgenabled AS enabled_state
FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE NOT t.tgisinternal
ORDER BY 1, 2, 3;
```

**Extensions and versions/schema placement**

```sql
SELECT e.extname, e.extversion, n.nspname AS extension_schema
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
ORDER BY e.extname;
```

**Sequences, ownership, and ACL**

```sql
SELECT schemaname, sequencename, sequenceowner,
       COALESCE(privileges::text, '<none>') AS privileges
FROM pg_sequences
ORDER BY schemaname, sequencename;
```

Also capture sequence ownership/dependencies from the catalogs where applicable; `pg_sequences` alone does not expose every ownership dependency.

**Default privileges**

```sql
SELECT COALESCE(n.nspname, '<global>') AS schema_name,
       pg_get_userbyid(d.defaclrole) AS grantor_role,
       d.defaclobjtype AS object_type,
       COALESCE(d.defaclacl::text, '<default>') AS default_acl
FROM pg_default_acl d
LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
ORDER BY 1, 2, 3;
```

Preserve query text and tool versions with the output. Normalize any known environment-specific values only with a documented, reviewed mapping; do not normalize away owner, ACL, policy, function body, extension, or trigger differences simply to make the diff empty.

### 4. Acceptance criteria

- [ ] Role prerequisites are recreated in the disposable instance without copying production secrets.
- [ ] `01_roles.sql` and `02_schema.sql` both completed successfully; no unreviewed restore errors.
- [ ] Required extensions are installed at compatible versions and in matching schemas.
- [ ] Identical canonical inventories were captured from live and restored target.
- [ ] All inventory outputs are deterministically sorted and compared with `diff -u`.
- [ ] The diff is empty. If it is not empty, every hunk is recorded as a reconciliation item and the gate remains blocked until explained and corrected.
- [ ] Dump hashes, PostgreSQL/tool versions, extension inventory, restore logs, inventory queries/results, and diff are retained in access-controlled release evidence.
- [ ] Only after the empty diff is reviewed: apply PR #76 and follow-on migrations **to the disposable target only**, in dependency order; run migration-ordering, negative privilege, OTS state, proof-rejection atomicity, tenant-isolation, and authenticated evidence-path tests.

## Current gate status

- [ ] Reproducible live schema snapshot produced.
- [ ] Disposable restore completed.
- [ ] Canonical live-vs-restore inventory diff empty and reviewed.
- [ ] Migration-ordering and full database integration tests passed.

Until these are actually evidenced, migration-ordering and full database integration tests remain **BLOCKED**, not passed. This document describes the gate; it is not evidence that the dump, restore, inventory, or diff has run. No production migration, deployment, worker activation, or proof insertion was performed for this reconciliation.
