# Dark Web + Kontrol — Railway Recovery Handoff

This runbook is prepared for the next Railway maintenance window. It does not change Railway configuration, secrets, deployments, worker state, or production data.

## Guardrails

- Keep all source collectors and discovery workers disabled until their individual readiness checks pass.
- Do not reactivate or bulk-drain the legacy deferred queue (approximately 26k jobs in the last verified snapshot).
- Never count an empty result as clean when source coverage is stale, unavailable, or unverified.
- Do not enable native onion collection until the Tor proxy is reachable from the actual service runtime and probe evidence is persisted.
- No Reddit or Have I Been Pwned (HIBP) sources. Ransomwatch remains historical-only.
- Never print secret values in logs, diagnostics, chat responses, or screenshots.
- Keep the Railway project untouched until the owner confirms the upgrade and explicitly authorizes Railway operations.

## A. Service/runtime recovery

- [ ] Confirm the intended Railway project, environment, service, and deployment target with the owner.
- [ ] Inspect the latest deployment, startup command, health-check path, and recent logs before changing anything.
- [ ] Verify the API process imports successfully and serves `GET /health`.
- [ ] Confirm the service uses the intended main commit and that the deployed SHA matches the approved GitHub commit.
- [ ] Verify required environment variable *presence* without printing values: Supabase URL/service-role credential, OpenAI credential for Engineering AI, GitHub/Vercel read-only credentials if those integrations are intended, and the approved model/project identifiers.
- [ ] Confirm Supabase REST reachability and a minimal authenticated application query from the running service; distinguish reachability from schema correctness.
- [ ] Confirm CORS includes the customer, developer, and Kontrol origins that are actually in use.

## B. Customer DW request chain

- [ ] Verify authenticated tenant identity and scope enforcement for `darkweb:read` and `darkweb:manage`.
- [ ] Create one explicitly approved test target in a test tenant or use an owner-approved existing test target; do not insert synthetic findings.
- [ ] Confirm watchlist persistence and return the persisted target/request identifier.
- [ ] Trace whether watchlist creation currently creates a service request or only a watchlist row. Do not show “monitoring started” until there is an execution acknowledgement.
- [ ] Verify request claim, lease-token binding, bounded retry, expiry, completion, and idempotency using one controlled supported job.
- [ ] Record a real per-source attempt and honest outcome: success with evidence, inspected/no match, unavailable, timeout, blocked, or error.
- [ ] Verify findings are target-matched and tenant-scoped; confirm evidence and coverage timestamps are visible to the customer.
- [ ] Confirm the legacy deferred queue remains excluded from the supported queue path.

## C. Native onion readiness (keep off until every check passes)

- [ ] Verify `CYCLOTHONE_DW_NATIVE_ONION_ENABLED` remains false/default-off until readiness approval.
- [ ] Verify `CYCLOTHONE_DW_ONION_SEEDS` contains only reviewed public onion sources with provenance and candidate status; do not promote seeds automatically.
- [ ] Verify `CYCLOTHONE_DW_ONION_PROXY` points to the approved Tor proxy endpoint reachable from the Railway runtime, not an assumed localhost service.
- [ ] Prove Tor circuit/stream routing and successful retrieval from an approved public onion seed without bypassing Tor.
- [ ] Persist the probe result, worker identity, source URL/descriptor, timestamp, and failure reason where applicable.
- [ ] Run a rollback test and verify no partial evidence, finding, or successful attempt remains after failure.
- [ ] Enable collection only after source registry, Tor route evidence, persisted probe evidence, and rollback test have been reviewed.

## D. Kontrol Engineering AI

- [ ] Verify the Engineering AI endpoint is reachable behind authenticated developer authorization.
- [ ] Confirm missing provider configuration produces a clear 503 state and upstream failures produce a clear 502 state without leaking secrets.
- [ ] Test each enabled read-only integration independently; credential presence alone is not connectivity.
- [ ] Verify GitHub and Vercel tools return actual live results, and Supabase tool is described only as an API reachability check unless schema/data inspection is implemented.
- [ ] Confirm Railway integration remains read-only and does not deploy, restart, or mutate services.
- [ ] Before durable chat persistence is implemented, clearly label conversation history as session-local. Do not imply it survives reloads.
- [ ] Do not expose write tools until approval, policy checks, audit logging, and post-action verification exist.

## E. Release evidence required

Attach the following to the recovery PR/release record:

- [ ] deployed Git SHA and health-check timestamp;
- [ ] redacted startup/runtime log excerpts for the successful boot;
- [ ] authenticated customer DW request ID and tenant-scoped readback;
- [ ] per-source attempt IDs/outcomes and evidence references;
- [ ] queue status counts proving the legacy backlog was not reactivated;
- [ ] Tor route/probe evidence if native onion was tested;
- [ ] Engineering AI endpoint result and integration-by-integration connectivity results;
- [ ] explicit list of blocked checks and reason.

**Exit criterion:** customer DW and Kontrol are not declared end-to-end ready until the authenticated request-to-evidence chain and Engineering AI runtime checks pass against the real deployed service.


## F. Weekend upgrade: owner-authorized recovery sequence

### Known resource identifiers (verify in Railway UI before acting)
- Railway project: `c40a4695-f8b0-41c1-bddf-f5a48a921cbd`
- Service: `cyclothone-api`
- Environment ID last recorded: `5cb394f1-2176-4cef-9f2b-f604f64b24e9`
- Railway had been paused after trial expiry in the last recorded checkpoint. Treat status as stale until rechecked.
- Supabase project ref: `whcomikcftbousoqzeal`
- Repository: `barron-Dev/barron-Dev`; Vercel project: `barron-dev`; production deployment last verified from `main` at SHA `55f78c0b80bd03ae1bc1c532da8c4d626e942ab2`.

### Upgrade-day ordered procedure
1. Owner confirms upgrade/billing is active and explicitly authorizes Railway inspection and recovery. Do not infer approval from the plan upgrade alone.
2. Reconfirm project, environment, service IDs, and region in the Railway UI. Do not create a duplicate project/service or environment.
3. Capture the pre-change service state, latest deployment ID/SHA, health-check configuration, restart policy, replica count, and recent redacted logs. Keep a rollback reference.
4. Compare deployed SHA with the approved GitHub branch/commit. Do not deploy a feature branch or draft-PR head directly to production. Use the owner-approved release commit only.
5. Inspect required variable names and whether each is present; never print or copy secret values into logs or this runbook. Do not rotate, regenerate, or replace secrets unless separately approved.
6. Check build/start command, root directory, runtime version, port binding, and health path from repository configuration. Do not guess a new start command.
7. Start/redeploy only after the previous checks pass. Observe startup and confirm `GET /health` from the actual running service; a Vercel build or local test is not a Railway health proof.
8. From the live service, verify Supabase connectivity with a minimal read-only authenticated query and confirm schema expectations. Do not apply migrations as part of runtime recovery.
9. Run one authenticated developer test through watchlist create/read/update/delete and one explicitly approved request path. Capture request IDs and persisted read-back. Do not seed fake findings or drain old queues.
10. Confirm worker lease/claim/heartbeat and per-source outcomes for the single controlled request. If no worker is deployed or no approved source is available, report blocked/partial; do not claim monitoring is active.
11. Keep native onion collection disabled until the Tor proxy/circuit, approved seed retrieval, persisted probe evidence, and rollback tests are independently proven in the service runtime.
12. Run Kontrol Engineering AI read-only checks and verify provider failures are surfaced honestly. Do not enable write tools or grant broader credentials as a workaround.
13. Attach redacted evidence to the PR/release record, then stop for review. Production promotion, database migrations, signing-key provisioning, and any queue activation remain separate approval gates.

### Current cross-platform blockers to resolve before/after Railway returns
- **Migration-source parity:** live Supabase latest recorded migration is `20261025065948`; 28 versions after `20261017180000` are absent from the inspected `main` timestamped migration directory. Recover exact source/history and validate parity before any schema-changing deployment. Never synthesize missing historical migrations from guessed names or current schema.
- **RLS policy review:** latest read-only inventory found 340 public tables, zero with RLS disabled, and 39 with RLS enabled but no policy. This is not automatically a vulnerability or a fix instruction: inventory ownership, grants, service-role-only intent, and expected access before changing policy.
- **AI Action Verifier:** receipt table/RPC and production `AI_ACTION` key are not present; the verifier PR remains draft. No production signing key or migration should be created during basic Railway recovery.
- **Omni-Vision:** signed evidence primitives are not yet wired to real media ingestion, detector runtimes, authenticated persistence, or customer UI. Do not advertise it as operational.
- **Vercel:** production is currently recorded on `main` SHA `55f78c0b80bd03ae1bc1c532da8c4d626e942ab2`; recent branch preview deployments do not imply production promotion.

### Stop/rollback triggers
Stop and preserve evidence if the service cannot boot, health checks fail, deployed SHA is unapproved, Supabase auth/schema checks fail, a worker claims unsupported work, secrets are exposed, cross-tenant access is observed, or queue/source state changes unexpectedly. Roll back only to the captured owner-approved known-good deployment; do not use schema rollback as a substitute for application rollback.


### High-priority Supabase grant finding (read-only inspection, 2026-10-29)
The live project has RLS enabled on all 340 inspected public tables, but 39 have no RLS policy. More importantly, read-only role-grant inspection found the `authenticated` role has explicit `TRUNCATE` privilege on nine public tables:
- `dw_sector_source_catalog`
- `dw_source_categories`
- `security_claim_history`
- `security_claim_requests`
- `security_claims`
- `security_targets`
- `source_registry`
- `source_registry_edges`
- `source_registry_events`

Five of those tables (`dw_sector_source_catalog`, `dw_source_categories`, `source_registry`, `source_registry_edges`, `source_registry_events`) were also observed with RLS enabled and no policy. The query confirms the grant, not that an exploit has occurred. PostgreSQL `TRUNCATE` is not row-filtered by RLS, so treat these grants as a **high-priority least-privilege defect to validate and remediate**. No rows were modified and no grants were revoked during this inspection.

Before changing privileges:
1. Inspect table ACLs, inherited/default grants, all policies, dependent RPCs, and intended client access for each table.
2. Confirm the application does not rely on direct authenticated table writes; prefer narrow RPCs with explicit authorization and tenant binding.
3. Prepare a reviewed, additive migration that revokes unnecessary `TRUNCATE`, `TRIGGER`, `REFERENCES`, and broad DML privileges from `anon`/`authenticated` while preserving required read paths. Do not blanket-revoke without verifying dependency impact.
4. Test against a disposable clone and verify authenticated users cannot truncate protected tables; verify approved API/RPC paths still work.
5. Do not apply to production until the 28-version migration-source parity gap is reconciled and the exact grant delta has review approval.
