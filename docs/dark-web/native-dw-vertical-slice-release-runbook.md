# Native DW vertical-slice release runbook

Status: **release gate / not yet proven end to end**  
Scope: one authorized, synthetic-safe test target and one candidate job in an isolated environment. This runbook does not authorize production changes, Tor probing, queue activation, migrations, or secret rotation.

## Pass/fail definition

PASS only when the same job can be followed through every stage, with timestamps and durable IDs:

1. Authorized queue job is claimed with a fresh lease token.
2. Worker validates target authorization and candidate/source policy before network access.
3. Tor connectivity is verified inside the worker runtime, and the request uses an isolated circuit/stream context. A generic SOCKS success is not proof of circuit isolation.
4. HSFETCH obtains the intended onion resource over the expected Tor route.
5. Raw response is captured to a WARC with a recorded digest and bounded size.
6. Sanitization creates a separate safe artifact; original evidence is immutable and access-controlled.
7. Classification records model/rule version and confidence as uncalibrated unless validated against labeled examples.
8. Matching is against the explicitly authorized target only; unrelated findings must not leak across tenants.
9. An append-only evidence row is written with previous-hash/current-hash linkage and all artifact digests.
10. An OpenTimestamps (OTS) proof is created and later verified against the exact evidence hash.
11. Source health records actual outcome, timing, bytes/pages inspected, and availability separately from match count.
12. A second process retrieves by evidence ID only, verifies tenant authorization, hashes, chain linkage, and OTS proof, and reproduces the same result.

Any missing ID, unsupported claim, ambiguous tenant, stale lease, or unverified artifact = FAIL. Do not replace a failure with a green/clean status.

## Execution boundary

- Run the first complete test in a disposable environment with a dedicated non-production Supabase project/database, dedicated test tenant, and a controlled onion endpoint owned by the team.
- Never place a Supabase `service_role` key, Tor client-auth private key, or webhook signing secret in source, logs, fixtures, WARC metadata, or test output.
- Do not use customer data or third-party onion targets for the initial vertical slice.
- No production migration, deployment, worker activation, queue mutation, source activation, or Tor probe without explicit release approval.
- If Railway authorization remains blocked, do not claim the production runtime was tested. Use a disposable one-container runtime only if it can be provisioned without production credentials and with explicit cost/hosting approval.

## Preflight — read-only

Record the UTC time, commit SHA, runtime image digest, migration head, and environment identity. Redact secret values; record only secret names, presence, owner, and rotation date.

Verify:
- [ ] PR branch and main SHA are recorded; no unreviewed code is included.
- [ ] Migration status and RPC signatures/grants are inspected without applying migrations.
- [ ] Queue schema constraints, active leases, supported job kinds, and current backlog counts are captured read-only.
- [ ] Worker feature flags are confirmed disabled in production.
- [ ] Target authorization and tenant-scoping checks are covered by tests.
- [ ] Test endpoint is team-controlled and has no real personal or customer data.
- [ ] Secrets have a documented owner, storage boundary, rotation procedure, and least-privilege plan.
- [ ] Database backup/restore destination and evidence-chain verification procedure are prepared.

Stop if any item is unknown. Do not infer live state from repository code.

## Run tests before network execution

From the repository root in an isolated development/test environment:

```bash
python -m compileall -q src/cyclothone
pytest -q tests/test_darkweb_discovery_queue_worker.py
pytest -q tests/test_darkweb_native_onion.py
pytest -q tests/test_darkweb_securedrop_directory.py
pytest -q tests/dw_discovery/test_url_policy.py
pytest -q tests/test_darkweb.py tests/test_darkweb_silence.py
```

Record exit code, test count, skipped tests, commit SHA, and sanitized logs. A skipped integration test is not a pass for that integration. These commands validate only the named tests; they do not prove production readiness.

## Instrument each arrow

For the single test job, retain a compact trace with correlation ID and these fields (never secret values):

| Stage | Required evidence | Fail condition |
|---|---|---|
| Claim | job ID, attempt, lease expiry, token fingerprint | no lease or duplicate active claim |
| Authorization | tenant/target ID and policy decision | target not authorized or tenant ambiguous |
| Tor | runtime identity, SOCKS endpoint health, circuit/stream isolation proof | only local SOCKS connection shown; isolation unproven |
| HSFETCH | requested onion host, Tor route outcome, status and byte count | direct-network fallback, redirect outside policy, timeout without honest failure |
| WARC | artifact ID, WARC digest, byte limit, write/read-back result | missing, partial, mutable, or unreadable artifact |
| Sanitize | safe artifact ID/digest and sanitizer version | raw content served to UI or sanitizer failure hidden |
| Classify | rule/model version, output, confidence/calibration status | confidence presented as calibrated without labels |
| Match | authorized target ID, matching evidence span/hash | cross-tenant or unsupported target match |
| Evidence | evidence ID, prior hash, current hash, artifact digests | chain mismatch, mutable evidence, partial write |
| OTS | proof ID/file, target hash, verification result | proof only requested, not later verified |
| Health | checked/unavailable/failed, pages/bytes actually inspected, time | zero matches presented as clean when source unavailable |
| Independent read | second process, evidence ID, authorization decision, recomputed hashes | only writer can read, wrong tenant can retrieve, hash/proof mismatch |

## Four high-risk failure modes

1. **Tor isolation is assumed, not demonstrated.** Confirm the actual worker's Tor control/client configuration and that the request stream uses the intended isolated circuit. A successful SOCKS handshake alone is insufficient. Do not run probes against external targets during this check.
2. **WARC is missing, truncated, or not reproducible.** Read the artifact back from its durable store in a separate process; recompute digest and validate WARC structure before classification. Enforce size/time bounds and never silently substitute an in-memory response.
3. **Lease fencing / partial writes.** Expire or replace a test lease and prove the stale worker cannot complete the job. Inject failures between artifact write, evidence append, OTS request, and health update. Every partial state must be recoverable or explicitly marked incomplete; retries must not create a false success.
4. **Evidence chain restore forks.** Restore a copy of the append-only chain and Merkle/OTS anchor inventory into a separate database. Verify all historical links and anchors before permitting any append. Then append a test record and verify the new chain from a second process. Never append to a partial restore until anchor reconciliation passes.

## Restore drill

- [ ] Take a consistent test backup of evidence rows, artifact manifests, WARC objects, OTS proofs, and Merkle anchors.
- [ ] Restore to a fresh isolated database and object-store prefix.
- [ ] Verify row count and canonical ordering; recompute every hash link and each Merkle root.
- [ ] Verify each available OTS proof against the exact anchored digest; distinguish pending proofs from verified proofs.
- [ ] Deliberately omit one record/anchor in a disposable copy and confirm verification fails.
- [ ] Append one test record only after the restored chain passes; verify it independently.
- [ ] Record RPO/RTO, missing-object behavior, and recovery owner.

## Secrets and key management gate

Inventory only; never print secret values. For each secret/key record purpose, owner, storage system, access principals, rotation/revocation process, last rotation, and audit trail.

- [ ] Separate production DB credentials from worker credentials; do not give the worker broad service-role authority if narrowly scoped RPCs can do the job.
- [ ] Store Tor client-auth private keys in a dedicated secret manager or equivalent protected store; mount only to the process that needs them, with restrictive permissions and rotation/revocation documented.
- [ ] Store canary webhook signing material separately; verify signatures and prevent replay.
- [ ] Confirm secrets are absent from logs, crash dumps, telemetry, WARC, and error messages.
- [ ] Test credential revocation and recovery in isolation.

## Source governance and product claim

Before any production collection, document per source class: legal basis/authority, purpose, data categories, geographic scope, retention/deletion period, access controls, processor/transfer posture, source terms, and escalation contact. Have qualified counsel review applicable GDPR and other jurisdictional obligations; this runbook is not legal advice.

Proposed narrow product statement, subject to evidence from the completed slice:

> Cyclothone records and verifies evidence from explicitly authorized dark-web monitoring jobs, and reports findings only when source availability, target matching, and evidence integrity can be demonstrated.

Do not claim comprehensive dark-web coverage, calibrated risk scores, attribution, or “clean” status unless each claim has separately documented evidence.

## Release decision

**GO** only if every vertical-slice stage and the restore drill pass in isolation, security/legal gates have owners and approvals, all artifacts are independently retrievable and verifiable, and no customer-facing status overstates coverage.

**NO-GO** if Tor isolation or WARC durability is unproven, secrets remain broadly exposed, tenant authorization is ambiguous, chain restore can fork, source is unavailable but shown as clean, or any stage relies on mocked/synthetic provider success.

After isolation passes, prepare a separate release plan. Production migration/deployment/worker enablement still requires explicit approval and a fresh read-only production preflight.
