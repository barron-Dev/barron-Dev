# Regulatory Conflict Engine v1

Status: implementation contract. This specification does not provide legal advice and does not encode universal precedence between laws.

## Purpose
Resolve evidence deletion and retention requests against the versioned obligations applicable to a tenant, evidence class, subject, jurisdiction, and time. The engine records conflicts and presents reviewed decision paths; it must never silently choose a legal interpretation or claim that one regulation always overrides another.

## Canonical model
- Evidence identity: tenant ID + evidence source/table + source record ID + verified content digest. A digest without content-read verification is insufficient.
- Obligation: stable ID, jurisdiction, authority/source citation, source version, effective interval, applicability predicate/version, evidence class, retention start event, retention/deletion rule, authoritative source URL or document hash, review owner, legal-review timestamp, and status.
- Request: authenticated requester, role/authority, subject reference, stated basis, scope, requested operation, received time, applicable context version, and idempotency key.
- Evaluation: matched obligations, unknown applicability, conflicts, evidence used, resolver version, and evaluation time.
- Decision: explicit outcome, reasoning, selected option, evidence references, required independent approvals, verified signer/key identities, timestamps, and appeal/review path.

## Resolution algorithm
1. Authenticate requester and derive tenant scope from authorization context. Reject cross-tenant identifiers and unauthorized roles.
2. Resolve the evidence locator to an existing tenant-owned record and verify its content digest. Never trust a caller-supplied hash alone.
3. Load the versioned country, sector, activity, evidence-class, data-subject, and contract context applicable at collection time and request time.
4. Evaluate every active obligation using deterministic, versioned predicates. Preserve matched and unknown results.
5. Build the conflict set from obligations whose required actions cannot simultaneously be satisfied. Do not encode a global regulation-precedence ranking.
6. If applicability is unknown, sources are stale, or obligations conflict, remain pending; do not delete, alter, or release restricted evidence.
7. Offer only reviewed options applicable to the conflict: minimize/pseudonymize subject reference if legally permitted, restrict access, preserve under legal hold, obtain a joint authorized decision, or seek regulator/counsel guidance. Pseudonymization is not equivalent to erasure.
8. Require independent approvers and cryptographically verify each signature against an active, purpose-scoped key. Two distinct user IDs are necessary but not sufficient.
9. Execute only the exact approved operation through a separate policy-enforcing data lifecycle boundary. The decision record must not bypass storage deletion guards.
10. Emit immutable decision events and a signed receipt with obligation snapshot, versions, source citations, approval proof, and operation receipt. Retain only minimum certificate metadata required by policy.
11. Re-evaluate when obligations change, a legal hold is added, or tenant context changes. Append superseding evaluations; never rewrite prior decisions.

## State machine
received → evidence_verified → obligations_resolved → (no_conflict | conflict_detected | applicability_unknown) → awaiting_authorized_decision → signature_verified → operation_authorized → operation_verified → closed

Any failed verification returns to a blocked state with a typed reason. Closure is forbidden while applicability is unknown, approval is absent, signature verification fails, a legal hold is active, or the lifecycle operation lacks a verified outcome.

## API contract principles
POST /v1/evidence/{hash}/delete-request creates an idempotent request; it is not an instruction to delete. The evidence hash alone is not the authorization key. The subsequent read returns a versioned evaluation, exact source citations, conflicts, and allowed options.

## Legal-data quality rules
- Never hard-code the illustrative 2,555-day retention period or blanket DORA-over-GDPR precedence as universal law.
- Legal source text, effective date, jurisdiction, scope and evidence class require qualified review and maintained provenance.
- Distinguish binding law, regulator guidance, contract retention and internal policy.
- Expired or unreviewed obligation data blocks destructive action where it could apply.
- The platform records a defensible decision process; it does not substitute for the tenant's DPO, legal counsel, or regulator.

## Required tests before release
- no obligations / unknown jurisdiction → blocked, never delete;
- contradictory obligations → conflict surfaced, no silent precedence;
- stale legal source → blocked;
- tenant mismatch and forged subject reference → denied;
- duplicate idempotency key → same request, no duplicate action;
- single approval, same person in both roles, revoked key, wrong key purpose, invalid signature → denied;
- legal hold added between evaluation and execution → execution blocked;
- evidence bytes changed after digest creation → integrity failure;
- failed deletion operation → no success receipt and no closed state;
- tenant reads own history but not another tenant's;
- offline verifier validates decision receipt and signer chain without contacting Cyclothone.
