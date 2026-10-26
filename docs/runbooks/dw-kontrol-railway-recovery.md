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
