# Cyclothone Dark Web source-registry release gate

This checklist is intentionally evidence-driven. A healthy API process does not prove that source discovery or a customer Dark Web request completed.

## Current implementation boundary

- Registry tables: `source_registry`, `source_registry_edges`, `source_registry_events`.
- Collection module: `src/cyclothone/darkweb/source_registry.py`.
- Existing scheduled collector: `src/cyclothone/darkweb/scheduler.py`.
- A bounded configured-source validation entry point is wired into `DarkWebScheduler` behind `CYCLOTHONE_DW_SOURCE_REGISTRY_ENABLED=true`; it is disabled by default. It normalizes and deduplicates targets and hard-caps each pass at 25 operator-configured public Telegram targets, with an 8-second request timeout, one-second pacing, no redirects, no login, no proxy rotation, and no target expansion. Confirmed 404 responses mark a source expired; restricted, rate-limited, empty, redirect, and provider-error outcomes remain inconclusive. The recursive snowball-discovery `tick()` is deliberately **not** scheduled. Do not report validation as running unless the flag is explicitly enabled and persisted events prove it ran.
- Production registry row counts were zero at the 2026-10-12 audit. No live collection is claimed by this branch.
- Migration versions `20261012083522` and `20261012083534` are present in the live Supabase migration history, but their source files were absent from the repository. Matching source files are restored here for future reproducible database builds. Do not manually re-apply these versions to production.

## Newly confirmed database privilege blocker (2026-10-12)

A read-only production query found RLS enabled on all three registry tables, but table-level grants remain for the `authenticated` role. No policies were found in the earlier inspection, so ordinary authenticated queries should still be denied by RLS; nevertheless, the grants violate the intended least-privilege boundary.

- Added `20261012100000_darkweb_source_registry_privilege_hardening.sql` to revoke table privileges from `PUBLIC`, `anon`, and `authenticated`, while granting required privileges to `service_role`.
- This corrective migration exists on this branch only and has **not** been applied to production.
- Before deployment, review the exact privilege delta, run it against a disposable Supabase database, and verify effective privileges with `has_table_privilege` plus RLS/policy checks.
- Do not treat the restored historical migration files as proof that production grants already match repository intent.

## Required verification before merge/deploy

- [ ] Run network-free unit tests for handle normalization, candidate extraction, conservative validation tiers, provenance preservation, and connected-reference scoring.
- [ ] Review the two restored SQL migration files against the live schema and a clean disposable database. Confirm constraints, indexes, identity generation, RLS, and grants.
- [ ] Enable `CYCLOTHONE_DW_SOURCE_REGISTRY_ENABLED=true` only after review; then verify the bounded configured-target validator writes source status and event evidence. Recursive snowball discovery remains out of scope for this release gate.
- [ ] Run a bounded test against operator-approved public Telegram targets only. Persist source rows, graph edges, and event rows; verify timestamps and source status reflect actual HTTP outcomes.
- [ ] Confirm a source timeout, rate limit, provider error, empty page, or missing credential is reported as unknown/unavailable/degraded—not as clean.
- [ ] Verify customer request execution end-to-end under an authenticated tenant: request accepted, worker claimed, source pull attempted, findings/evidence persisted, and result visible to that same tenant. A generic “workflow recorded” response is not sufficient.
- [ ] Confirm tenant isolation, service-role-only registry writes, and no raw credential material in findings, events, logs, or evidence.
- [ ] Deploy only after the above gates pass; then repeat the authenticated production check and retain request/case IDs plus evidence timestamps.

## Acceptance evidence

Record the exact commit and deployment, UTC test window, approved public targets, source response states, registry row/edge/event deltas, request/case identifiers, finding/evidence identifiers, tenant identity, and final result. If any of these are absent, mark the gate **NOT VERIFIED** rather than passing it by inference.
