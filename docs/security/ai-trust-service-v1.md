# Cyclothone AI Trust Service v1 — implementation ledger

**State:** feature-branch proposal; not merged, deployed, or applied to production.

## User-request inventory

1. Cryptographic AI Action Verifier: Ed25519 signatures, canonical payloads, SHA-256 payload commitments, hash-linked action receipts, and actual verification.
2. Database enforcement that recomputes payload and event hashes and verifies Ed25519; never trust API-supplied verified booleans.
3. Connected Next.js/React investor demonstration with real signing, verification, and tamper rejection; no success state before checks run.
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
- Live Supabase has pgcrypto installed but does not currently have pgsodium installed. The proposed database-native Ed25519 RPC therefore has a hard dependency/preflight. Do not apply the migration until the extension can be installed and tested in an isolated database.
- Live migration history includes entries through 2026-10-25, while the repository’s visible supabase/migrations directory ends at 2026-10-17. Reconcile repository/production migration-source drift before applying new production migrations.
- Vercel project barron-dev is Next.js and has customer/developer/Kontrol domains configured. Project metadata reported live=false while a latest deployment record was READY; do not claim this feature is live or deployed. No deployment was promoted or sent to production. A preview deployment automatically queued for this feature branch was canceled before build to avoid an unapproved preview/build; the GitHub Vercel check on that head consequently reports failure due to cancellation, not a code-test result.

## Ordered implementation plan

### P0 — action receipt integrity (current slice)
- Implement canonical payload parsing with duplicate-key and non-finite-number rejection.
- Recompute payload SHA-256 and a domain-separated, length-framed event hash.
- Verify Ed25519 against a key registry; bind tenant, run, sequence, previous hash, and signer key ID.
- Add a typed result contract that refuses complete when any requested source is incomplete.
- Add a real browser-local WebCrypto investor demo. It uses an ephemeral key and generated fixture, is explicitly local-only, and does not impersonate production trust.
- Add a proposed database RPC/migration that recomputes hashes, checks the active tenant-scoped key, verifies Ed25519 in PostgreSQL, and inserts only after all checks. This migration is not applied.

### P1 — secure runtime/database wiring
- Align migration history, install/test pgsodium in an isolated DB, test key purpose/status/revocation and RLS/grants, add negative-path DB tests, and read back committed evidence.
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

## Current code slice and boundaries

- src/cyclothone/ai/action_verifier.py: local cryptographic envelope signing/verification and chain validation.
- src/cyclothone/ai/result_contract.py: typed honest coverage states.
- src/cyclothone/ai/behavioral_fingerprint.py: fixed-suite input/output hashes, provenance-bound fingerprint manifest, drift comparison, and Ed25519 attestation primitive.
- tests/test_ai_action_verifier.py and tests/test_ai_result_contract.py: tamper, binding, chain, and coverage-negative tests.
- supabase/migrations/20261028070000_ai_action_verifier.sql: proposed database enforcement using existing trust_signing_keys and ai_runs; it adds a narrow action-event index, not a replacement trust framework. Requires pgsodium, and must remain unapplied until isolated-database verification and migration-source reconciliation.
- console/app/(dash)/convergence/ai/verification/page.tsx: real local WebCrypto self-test and tamper rejection. It is explicitly not connected to production key registry/backend yet.

## Proof and release gates

- Fresh Python tests and TypeScript/Next.js build on the new branch.
- SQL migration applied only in an isolated DB; positive and negative tests prove DB recomputes payload hash, event hash, active key binding, Ed25519 signature, tenant/run binding, and chain predecessor.
- Wrong key, revoked/expired key, altered payload, altered event metadata, signature mutation, duplicate event/sequence, cross-tenant run, replay, and chain truncation all reject.
- The browser demo starts neutral, only shows success after actual Web Crypto checks, and demonstrates rejection after tampering.
- Production acceptance requires authenticated API wiring, database read-back, key rotation/revocation tests, RLS/grant checks, and fresh CI. No production-complete claim before those gates pass.


## Validation performed for this branch (2026-10-28)

- Targeted isolated-workspace Python tests: 20 passed, covering action signing/verification, payload/event tampering, key/signature failure, tenant/run binding, chain order, honest coverage states, fixed-suite drift, provenance attestation, and migration-source assertions.
- Python bytecode compilation completed successfully for the new Python source/tests.
- The new verification page passed a focused TypeScript/JSX syntax/type pass using temporary React/JSX declarations; this is not a full Next.js build.
- Not run: full repository test suite, full Next.js production build, SQL migration execution against PostgreSQL, or CI for this new branch.
- The existing PR #93 head separately has a successful CI run (run 3529 on commit 4a079206c5350d97c36af90cce4a9c7eb9c58ae0). That result does not validate this new branch.
