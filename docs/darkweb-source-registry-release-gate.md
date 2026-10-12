# Cyclothone Dark Web source-registry release gate

This checklist is intentionally evidence-driven. A healthy API process does not prove that source discovery or a customer Dark Web request completed.

## Current implementation boundary

- Registry tables: `source_registry`, `source_registry_edges`, `source_registry_events`.
- Collection module: `src/cyclothone/darkweb/source_registry.py`.
- Existing scheduled collector: `src/cyclothone/darkweb/scheduler.py`.
- The source-registry module is **not wired into the scheduler**. Do not report registry discovery as running until a separately reviewed, bounded integration is merged and observed.
- Production registry row counts were zero at the 2026-10-12 audit. No live collection is claimed by this branch.
- Migration versions `20261012083522` and `20261012083534` are present in the live Supabase migration history, but their source files were absent from the repository. Matching source files are restored here for future reproducible database builds. Do not manually re-apply these versions to production.

## Required verification before merge/deploy

- [ ] Run network-free unit tests for handle normalization, candidate extraction, conservative validation tiers, provenance preservation, and connected-reference scoring.
- [ ] Review the two restored SQL migration files against the live schema and a clean disposable database. Confirm constraints, indexes, identity generation, RLS, and grants.
- [ ] Decide and document an approved source-registry scheduler entry point with a strict per-tick source cap, bounded request timeouts, pacing, cancellation, and observable failures. Do not add proxy rotation, login, private/invite access, or detection evasion.
- [ ] Run a bounded test against operator-approved public Telegram targets only. Persist source rows, graph edges, and event rows; verify timestamps and source status reflect actual HTTP outcomes.
- [ ] Confirm a source timeout, rate limit, provider error, empty page, or missing credential is reported as unknown/unavailable/degraded—not as clean.
- [ ] Verify customer request execution end-to-end under an authenticated tenant: request accepted, worker claimed, source pull attempted, findings/evidence persisted, and result visible to that same tenant. A generic “workflow recorded” response is not sufficient.
- [ ] Confirm tenant isolation, service-role-only registry writes, and no raw credential material in findings, events, logs, or evidence.
- [ ] Deploy only after the above gates pass; then repeat the authenticated production check and retain request/case IDs plus evidence timestamps.

## Acceptance evidence

Record the exact commit and deployment, UTC test window, approved public targets, source response states, registry row/edge/event deltas, request/case identifiers, finding/evidence identifiers, tenant identity, and final result. If any of these are absent, mark the gate **NOT VERIFIED** rather than passing it by inference.
