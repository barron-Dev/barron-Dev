# Cyclothone AI Trust Service v1 — implementation ledger

**State:** feature-branch proposal; not merged, deployed, or applied to production.

## User-request inventory

1. Cryptographic AI Action Verifier: Ed25519 signatures, canonical payloads, SHA-256 payload commitments, hash-linked action receipts, and actual verification.
2. Trusted-backend Ed25519 verification plus database enforcement that recomputes payload and event hashes; never trust API-supplied verified booleans.
3. Connected Next.js/React production verification surface backed by the authenticated API, registered signing key, and durable database receipt; not implemented end to end yet.
4. AI execution authorization/policy boundary: AI intent cannot authorize itself; bind tenant, actor/agent, run, model/provider, mission, tool, key, expiry, and replay state.
5. Capability-restricted WASM sandbox with resource limits and no ambient filesystem/network/secret access by default.
6. Behavioral model fingerprinting, fixed-suite drift checks, and provenance attestations bound to model/runtime/dependency versions.
7. Defensive canary/deception signals with tenant isolation; no poisoning third-party models, prompt exfiltration, or claims that one canary hit proves compromise.
8. Multi-signature break-glass approval with distinct identities, scoped operation/target, expiry, reason, replay prevention, and append-only audit trail.
9. Merkle-linked evidence, external checkpoint/anchor strategy, and honest proof/SLA language; no “unhackable” or absolute authenticity claims.
10. MCP server/Trust Shield and a developer integration path targeting five minutes, subject to measured onboarding tests.
11. Offline/local-first Edge SDK, SQLite signed journal, checkpointing, anti-rollback strategy, and safe/idempotent sync.
12. Typed ResultContract/SDK with explicit partial_coverage, blocked, and failed states; zero results must not imply clean when sources were unavailable.
13. Relevant customer, developer, and internal Kontrol surfaces backed by the same authorization and evidence contract.
14. Preserve prior branches/PRs, reuse existing trust foundations, and make no merge, deploy, secret, infrastructure, or production changes without explicit approval.

## Verified existing foundations

- GitHub PR #93 (branch feat/local-contract-journal-v1) is open, draft, unmerged. It adds a SQLite local signed hash-chain journal, canonical JSON payload commitments, Ed25519 signatures, immutable UPDATE/DELETE triggers, signed checkpoints, and tests for tampering/truncation. It is not an MMR, has no external anchor service, and has no HSM/TPM/TEE integration. Keep that PR intact; this action-verifier work is stacked separately.
- GitHub PR #91 (branch feat/reference-pack-generator) is open, draft, unmerged. It includes Ed25519 pack sign/verify, dependency-lock validation, a build-time capability-ceiling analyzer, and partial GlobalContext/MessageFormat support. Runtime sandbox enforcement, HSM/key transparency, full ICU/RTL conformance, and runtime ceiling rechecks remain unproven.
- Existing src/cyclothone/ai/execution_gate.py implements a fail-closed gate around signed AI envelopes, tenant/model/provider/mission binding, tool policy, twin simulation, and replay consumption. Existing tests cover invalid signatures and policy/approval behavior. Extend this rather than duplicating it.
- Live Supabase project whcomikcftbousoqzeal contains ai_trust_execution_decisions, ai_trust_execution_identities, ai_trust_subject_bindings, trust_evidence, trust_proofs, trust_attestations, trust_signing_keys, and related routines. RLS is enabled on the inspected AI decision/identity and trust evidence/proof tables.
- The live trust_commit_evidence_verification routine checks the supplied payload hash against the stored evidence hash and checks signer/key bindings and key status, but its inspected body does not call a cryptographic Ed25519 verifier. Do not treat its VERIFIED state as proof that the signature itself was verified by that function.
- Live Supabase has pgcrypto installed; this design avoids pgsodium. The trusted Python backend performs Ed25519 verification using the maintained `cryptography` dependency, and the database RPC is restricted to `service_role` while independently checking payload/event hashes, tenant/run/agent binding, key status, chain sequence, and append-only rules.
- Live Supabase migration history reports latest applied version `20261025065948`. Its applied versions after the repository's last existing production migration `20261017180000` include `20261018132005`, `20261019072813`, `20261019073136`, `20261019073250`, `20261019073406`, `20261019073531`, `20261019073558`, `20261019075433`, `20261019080344`, `20261019083728`, `20261019083736`, `20261019083743`, `20261019084125`, `20261020142712`, `20261020142737`, `20261021064246`, `20261021064301`, `20261021064347`, `20261021064440`, `20261021064504`, `20261021064731`, `20261021064748`, `20261021070050`, `20261021070151`, `20261021070218`, `20261021081258`, `20261025065850`, and `20261025065948`. These migration version files are absent from both the current `main` and this feature branch's migration directory. Do not apply the new AI verifier migration until the missing production migration source is recovered/reconciled.
- Vercel project `barron-dev` has customer/developer/Kontrol domains configured. The latest checked Vercel commit status for the current PR head is success, but this is not proof that this feature is live or deployed. No deployment was promoted or sent to production.

## Ordered implementation plan

### P0 — action receipt integrity (current slice)
- Implement canonical payload parsing with duplicate-key and non-finite-number rejection.
- Recompute payload SHA-256 and a domain-separated, length-framed event hash.
- Verify Ed25519 against a key registry; bind tenant, run, sequence, previous hash, and signer key ID.
- Add a typed result contract that refuses complete when any requested source is incomplete.
- Do not present a browser-local cryptographic exercise as an investor demonstration. The route now displays a truthful BLOCKED state until the real API, production key registry, trusted-backend Ed25519 verification, database receipt enforcement, and durable receipt read-back are connected.
- Add a proposed database RPC/migration that recomputes hashes, checks the active tenant-scoped key, and inserts only after all database checks. The trusted backend verifies Ed25519 before calling the service_role-only RPC. The migration remains unapplied to production.

### P1 — secure runtime/database wiring
- Align migration history; test backend Ed25519 verification and service_role-only RPC grants in an isolated DB; test key purpose/status/revocation, RLS/grants, negative paths, and durable read-back. The isolated PostgreSQL workflow and full Python suite have now passed; authenticated live E2E remains outstanding.
- Connect the backend signer to the RPC, with key custody outside model/browser control.
- Review trust_authorize_ai_run policy-unbound behavior and ensure policy-required workloads fail closed without weakening intentionally optional workloads.
- Add request replay/idempotency, append-only verification records, and a verifier CLI for exported bundles.

### P2 — authorization, sandbox, and resilience
- Enforce runtime capability ceilings at the actual tool/execution boundary.
- Add Wasmtime or another supported WASM runtime with explicit capabilities, CPU/memory/time limits, and deny-by-default I/O.
- Add multi-signature break-glass state machine and audit trail.
- Add local journal sync with idempotency, signed checkpoints, conflict handling, and rollback detection via an independent anchor.

### P3 — model integrity and defensive signals
- The current branch now implements a fixed-suite fingerprint primitive over input/output hashes and model/provider/runtime/dependency bindings, plus Ed25519 provenance attestations. Drift is a measured difference, not proof of malicious behavior. Production model-runner wiring, key-registry/revocation integration, and baseline lifecycle remain outstanding.
- Defensive canary events isolated by tenant, with bounded telemetry and privacy controls remain planned.

### P4 — developer/customer/internal surfaces
- Connect developer API/MCP Trust Shield, typed SDK and partial_coverage ResultContract.
- Connect customer evidence/decision history and internal Kontrol review/approval surfaces.
- Measure the five-minute integration claim with a clean-room developer test; do not publish it as an achieved SLA before measurement.

## Bulk implementation block — durable action receipts

- Added `src/cyclothone/ai/action_receipt_service.py`. It requires a backend-held Ed25519 private key from `CYCLOTHONE_AI_ACTION_SIGNING_PRIVATE_KEY_PEM` and key ID from `CYCLOTHONE_AI_ACTION_SIGNING_KID`; it does not generate ephemeral keys or store private key material in the database.
- Before signing, the service checks the persisted tenant/run/agent binding and confirms that the registered tenant-scoped `AI_ACTION` public key matches the externally supplied private key. It signs the next hash-chain event, calls `commit_ai_action_verification_event`, then verifies the returned event and performs a field-by-field durable database read-back.
- Connected `ResponseOrchestrator` direct dispatch and approved dispatch paths to record a signed `dispatch_authorized` receipt before calling the dispatcher. Missing receipt service, missing external key, absent/incorrect registered public key, RPC rejection, or read-back mismatch blocks dispatch. The service is injected through the orchestrator constructor; production wiring must explicitly inject it after the migration is validated and the key is provisioned.
- Added tests for missing/malformed external key configuration. These are fail-closed unit tests, not database integration proof.
- Runtime wiring is now present in `src/cyclothone/api/routes/response.py` for both playbook execution and approval dispatch. The playbook compiler also carries the canonical `ai_run_id` into `EnvelopeIssueRequest`; a regression test checks that exact binding.
- **Not yet verified:** live RPC availability, trusted-backend Ed25519 verification and service_role-only RPC grants, migration execution, active key registration, a real authenticated execution-to-receipt E2E, and production key provisioning. Live Supabase read-only inspection confirmed that the receipt table/RPC do not exist. The implementation deliberately avoids requiring pgsodium. The migration remains unapplied. Do not treat branch code or a passing unit test as production readiness.

## Current code slice and boundaries

- src/cyclothone/ai/action_verifier.py: cryptographic envelope signing/verification and chain-validation primitives only; these do not establish live service integration.
- src/cyclothone/ai/result_contract.py: typed honest coverage states.
- src/cyclothone/ai/behavioral_fingerprint.py: fixed-suite input/output hashes, provenance-bound fingerprint manifest, drift comparison, and Ed25519 attestation primitive.
- tests/test_ai_action_verifier.py and tests/test_ai_result_contract.py: tamper, binding, chain, and coverage-negative tests.
- supabase/migrations/20261028070000_ai_action_verifier.sql: proposed database enforcement using existing trust_signing_keys and ai_runs; it adds a narrow action-event index, not a replacement trust framework. Must remain unapplied until isolated-database verification and migration-source reconciliation.
- console/app/(dash)/convergence/ai/verification/page.tsx: truthful production-blocked status only. The former browser-local ephemeral-key/synthetic-payload self-test was removed; this page does not claim to verify a production action.

## Proof and release gates

- Fresh Python tests and TypeScript/Next.js build on the new branch.
- Proposed SQL migration executed only in a disposable isolated DB; tests prove the DB recomputes payload/event hashes, enforces active key binding, tenant/run binding, chain predecessor, and append-only rules. The real Python verifier separately proves valid Ed25519 acceptance and forged-signature rejection.
- Wrong key, revoked/expired key, altered payload, altered event metadata, signature mutation, duplicate event/sequence, cross-tenant run, replay, and chain truncation all reject.
- The production verification page must remain BLOCKED until an authenticated end-to-end test proves real API signing/verification, live database enforcement, replay/tenant/run checks, and durable receipt read-back.
- Production acceptance requires authenticated API wiring, database read-back, key rotation/revocation tests, RLS/grant checks, and fresh CI. No production-complete claim before those gates pass.


## Validation performed for this branch (2026-10-29, latest checkpoint)

- GitHub Actions run **3624** for commit `d89c002ed8bc2b51843b1c06906c1176a5527ed9` completed successfully.
- Python test suite: **424 passed, 2 warnings**. This is automated repository test evidence, not live database integration.
- Console build: passed.
- Production image build: passed.
- Vercel check for this branch commit: success; this is not evidence that the PR was merged or that production backend services were deployed.
- Live Supabase read-only preflight: PostgreSQL 17.6; latest applied migration version is `20261025065948`; `ai_action_verification_events` and `commit_ai_action_verification_event` are absent; active and total production `AI_ACTION` key counts are both zero. The new design avoids a `pgsodium` dependency.
- The migration remains unapplied. No production key was provisioned, no merge or deployment was performed, and no authenticated end-to-end receipt test has been completed.
- **Release decision remains BLOCKED** until isolated PostgreSQL validation and the real Python Ed25519 positive/forged-signature checks pass (now passed), followed by authenticated E2E, migration-source reconciliation, key provisioning through an approved secret manager, and explicit production-change approval.

- Additional read-only schema reconciliation completed: the live `ai_runs` identity columns are UUID and `agent_id` is NOT NULL; the existing `trust_register_signing_key(uuid,text,text,text,text,timestamptz,timestamptz)` is SECURITY DEFINER with execution granted only to `service_role`. The proposed migration targets that exact signature and extends its allowed purpose list.
- Live preflight confirmed `extensions.digest(bytea,text)` exists. No production DDL was executed.
- Current CI proof: disposable PostgreSQL migration/ACL/hash-chain validation passed; full Python suite passed with `424 passed`; console build passed; latest checked Vercel commit status is success. The SQL workflow runs the actual Python Ed25519 verifier for valid and forged receipts. These results do not establish production deployment or authenticated live E2E.
