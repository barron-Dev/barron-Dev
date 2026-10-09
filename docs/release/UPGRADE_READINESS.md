# Cyclothone upgrade readiness checkpoint

Last updated: 2026-10-09
Branch: `feat/register-sol-for-existing-tenants`
Current head before this checkpoint: `a344cb49964978dd2b8d54ed760f67214c39a978`
PR: [#53 — Register GPT-6.1 Sol](https://github.com/barron-Dev/barron-Dev/pull/53)

## Operating rule

Prepare and verify as much as possible before an account/plan upgrade. Resume from this checkpoint; do not restart audits, rebuild working surfaces, create duplicate architecture, or activate unverified capabilities. Keep production changes fail-closed until their explicit gates are satisfied.

## Current verified state

- PR #53 is open and draft; not merged.
- Console build passed on CI runs 37979133523 and 37979140186.
- Python tests failed on those runs. Latest reported result: 183 passed, 5 failed. Failures include device-enrollment test fixture missing `DeveloperPrincipal.user_id`, DNA extractor test expecting 1036 dimensions while implementation returns 984, knowledge intent tie-break expecting `api` but receiving `guide`, and perceptual-hash test expecting two flat-color images to hash differently. The first five-failure cap means more failures may remain. Do not describe CI as green.
- Live canonical `ai_runs` query returned zero runs, zero runs with token usage, and zero positive-cost runs. This establishes no recorded run history in that table at query time, not zero provider billing or proof all app activity is token-free.
- Live `ai_missions` query returned no rows at query time. No live mission-backed end-to-end execution was proven.
- No production migration was applied, no model was activated, and no production secret was changed.

## Work in branch

- `sql/105_register_gpt_6_1_sol.sql`: register provider and per-existing-tenant model in `REGISTERED` state only; does not activate routing.
- `src/cyclothone/ai/provider_execution.py`: resolve provider model key from tenant-scoped registry, validate token usage/pricing, calculate cost, and call canonical usage settlement.
- `src/cyclothone/ai/execution_gate.py` plus `tests/test_ai_execution_gate.py`: expose expected mission identity to authorization and align tests with the mission-bound envelope and current authorization path.
- `src/cyclothone/api/routes/ai_gateway.py` plus `sql/151_ai_run_workload_usage.sql`: persist the workload layer on canonical `ai_runs` and derive workload aggregates from that same table; no second usage ledger.

## Required before enabling Sol or calling the system production-ready

1. Fix the five current Python failures based on source-of-truth behavior, not by weakening security or merely changing expected values to force green.
2. Validate migration 151 against the actual deployed `ai_start_run` signature, return type, role grants, RLS behavior, idempotent replay behavior, and the full range of workload labels used by callers.
3. Verify that `ai_record_provider_usage` settlement is reached on every successful real provider call, that settlement failures cannot report a successful completed run with missing cost, and that retry/duplicate execution remains blocked.
4. Verify real provider account access, actual model availability/name and current pricing/limits; configure secrets only through the authorized secret manager.
5. Provision a real tenant-scoped agent, mission, route and execution binding through the existing trust/control path—no fabricated seed records.
6. Apply reviewed migrations only after schema compatibility checks; deploy to a non-production preview/staging surface first where available.
7. Run an authorized real end-to-end test with captured run ID, provider response metadata, input/output/cached token counts, cost, latency, tenant/workload attribution, settlement row, and evidence. Never store API secrets or sensitive prompt content in the evidence.
8. Confirm tenant isolation and app-level attribution across customer/developer web, iOS, Android, desktop and Kontrol Plane before claiming system-wide coverage.
9. Only then consider merge, production migration, provider activation, and deployment, in that order with explicit review of each irreversible or production-impacting action.

## Upgrade-time continuation

When account/plan access changes, first re-check the existing PR head, CI status, current schema signatures and access/secret availability. Continue from the blockers above; do not rerun broad audits unless state changed or evidence is stale. A plan upgrade itself does not prove provider billing access, API credits, model availability, deployment permissions, or successful end-to-end execution.
