# Cyclothone Pack Supply-Chain Security Architecture v1

**Status:** Architecture requirement / implementation plan. This document does not claim these controls are implemented, deployed, or verified.

**Scope:** Community-authored and first-party declarative packs, regulatory overlays, service and delivery bindings, tenant installation, Result Sessions, evidence, and MSSP federation. The pack ecosystem remains one compositional platform; do not create per-industry repositories, forks, branches, or hardcoded products.

## Governing invariants

1. Raw YAML is authoring input only. Runtime consumes a versioned compiled bundle, never raw pack YAML.
2. A pack may narrow the platform/tenant capability ceiling, never widen it. No pack-controlled field can raise the ceiling or grant a capability.
3. Pack identity, exact versions, content hashes, compiler identity, and all resolved inputs are bound into the manifest. No floating overlay, service, or binding references.
4. Build/preview, compiled, conformance-passed, signed, published, installed, and revoked are distinct states. A resolved pack is not thereby trusted or conformant.
5. Runtime re-checks the bundle against the current effective ceiling and delegation before every session creation. Drift, revocation, missing inputs, and unsupported controls fail closed with typed reasons.
6. The deterministic journal is the proof source for source attempts, findings, evidence, replay, attestations, pack migration, and revocation. A hash-shaped reference alone is not proof that evidence exists or belongs to the tenant.
7. No pack can bypass tenant isolation, authorization, evidence validation, policy, signed execution, or audit. No marketing claim substitutes for conformance and operational evidence.

## Compiler and bundle contract

The compiler pipeline is: safe YAML parse (duplicate keys rejected) → schema validation → immutable, hash-pinned overlay/service/binding resolution → capability analysis → compliance mapping → conformance suite → deterministic canonical bundle and manifest → signing/attestation. Any missing or ambiguous input remains preview/unresolved and cannot become an installable trusted artifact.

The bundle manifest is versioned and binds at minimum:
- pack ID/version and schema/compiler versions;
- canonical source digest and deterministic bundle digest;
- exact overlay, service, parser, binding, and registry versions plus content hashes;
- tenant/plan/geography ceiling inputs and the capability-analysis result;
- compliance control mappings and explicit gaps;
- locale/jurisdiction coverage;
- conformance suite/version/results;
- author principal, signer key ID, and signature metadata;
- provenance reference and lifecycle state.

Reproducibility means identical normalized inputs and compiler build produce identical bundle bytes and content hash. Keep signatures/provenance as separately described attestations if their encoding includes nondeterministic metadata; do not let signature timestamps contaminate the deterministic bundle digest. Dynamic network resolution is forbidden during compilation. Upgrades require an explicit new compile and adoption event.

The existing `cyclothone pack build` work is an initial generator slice, not evidence that signing, pinned resolution, capability ceilings, conformance, runtime enforcement, or provenance are complete.

## Capability ceiling: narrowing only

The effective ceiling is platform policy intersected with tenant plan, geography/residency, enabled services, delegated authority, and other applicable platform constraints. A pack selects a subset of this ceiling. The schema must not expose a ceiling-raising or capability-creation primitive.

- **Schema gate:** allow only declared fields; reject unknown widening fields.
- **Build gate:** compare every requested value and reference with the authoritative ceiling and resolved capability registry; return typed errors for scope widening, disallowed binding, missing regional service, unsupported control, or unpinned dependency.
- **Runtime gate:** revalidate bundle digest, revocation state, current ceiling, tenant binding, service/binding availability, and delegation at session creation. If a plan or ceiling changes after compilation, fail closed rather than silently downgrade or execute outside the current ceiling.

Examples of restrictive dimensions include maximum retention, allowed residency regions, permitted delivery bindings, minimum disposition floor, and required dual control. A pack can demand stricter behavior but cannot lower a platform-mandated disposition floor or disable required dual control.

## Supply-chain controls

### 1. Provenance and offline verification
Every published bundle should have verifiable build provenance binding the source commit, compiler digest, hermetic build environment, and every input digest. Target SLSA Level 3 only when the build platform and attestations actually satisfy the requirements; do not label a bundle SLSA L3 based on a self-asserted manifest. `cyclothone pack verify-provenance` must verify offline against trusted, versioned verification keys and fail with typed reasons on tampering, missing inputs, or invalid attestations.

### 2. Author identity and reputation
Each author is a verifiable principal; pack signatures bind to that principal and a key ID. Platform-signed reputation attestations are computed from reproducible, published inputs (incident rate, replay pass rate, conformance continuity, and tenant longevity). Reputation can restrict publishing tier; it never replaces signature validation, conformance, or capability enforcement. Key rotation, compromise, revocation, and historical attribution need explicit lifecycle records.

### 3. Runtime capability sandbox
Workflows receive only declared, ceiling-approved capabilities. There is no undeclared network, data-path, or binding access. Attempted access outside the manifest fails closed and is journaled as a policy violation. Sandbox enforcement must be independent of pack-authored workflow code; a pack cannot self-authorize its sandbox.

### 4. Revocation / kill switch
Revocation is a canonical, authorized, append-only event containing pack identity/version/digest, reason code, evidence reference, scope, actor, timestamp, and signature. Runtime checks revocation at the next request/session boundary and suspends affected sessions; notifications use only previously authorized bindings and produce delivery receipts. Verification rejects receipts whose pack or signer was revoked under the applicable trust policy, with a typed reason. The API must report actual affected sessions and notification receipts from durable state; never fabricate success counts or claim instantaneous global propagation without measured evidence.

### 5. Shadow replay before install
Before adoption, replay existing eligible sessions against the candidate pack using the deterministic journal, in shadow mode. Produce a signed divergence report from actual replay results: sessions affected, sessions becoming partial, changed attestations, newly satisfied/unsatisfied controls, source/parser/overlay skew, and remediation windows only where computation supports them. No silent install or implicit policy change.

## Versioned overlays and attestation continuity

Regulatory overlays are immutable, semantically versioned artifacts with content hashes. Every update includes a structured semantic diff covering changed/added/removed controls, evidence mappings, freshness requirements, notification clocks, and breaking impacts.

A tenant upgrade is an explicit preview → shadow replay → review → authorized commit. Attestations bind to exact overlay and pack versions. On adoption, the prior attestation is retained as superseded for its required retention window; a new attestation is computed from the new requirements and journal evidence. Gaps and recheck windows remain explicit. No silent re-derivation or deletion of historical compliance state.

## MSSP federation and delegation

- **Shared pack / distinct tenants:** immutable bundle may be shared, but tenant journals, evidence, receipts, and attestations remain isolated.
- **Tenant override:** MSSP-authored overlays can only narrow the base pack. Bind them to the MSSP principal and delegation chain; verify scope, expiry, and revocation at application/session creation. Overrides are tenant-visible, versioned, auditable, and revocable.
- **Cross-tenant replay:** authorized federation replay reports identify every divergence with a reason code, separating intentional authorized overrides from parser/service/overlay skew. Reports must not disclose one tenant's evidence to another tenant. Signed report is an audit artifact, not proof that untested tenants are identical.

## Evidence localization

Keep canonical machine-readable enums and reason codes language-neutral. Localize display text independently by locale and jurisdiction, with provenance/version for each translation. The compiler rejects packs missing locale coverage required by their jurisdiction overlays. Localized text never changes canonical disposition or policy semantics; regulatory wording must be versioned and reviewable.

## Residency enforcement at the journal writer

Residency is enforced at the storage/write boundary, not merely at the API or pack-config layer. The writer validates tenant, pack, region, and destination partition before persisting any attempt/evidence metadata; cross-region writes fail closed with a typed error and a safe audit record that itself respects residency constraints. Region-specific partitions are a deployment/storage architecture decision and must reflect actual available regions and database capabilities. A YAML region field alone is not proof of residency. Validate backups, logs, queues, replicas, exports, and notifications as part of the same residency boundary.

## Jurisdiction clock engine

Each applicable regulator clock is derived from versioned rules and case/finding timestamps, with deadline, remaining time, status, and notification channel recorded as structured fields. Case closure is blocked while a mandatory clock is open unless a specifically authorized, signed justification references that clock and reason. Clock start/stop/pause semantics, time zones, rule versions, notification delivery evidence, and clock changes are journaled and included in the attestation. Never imply a regulator portal integration exists unless it is implemented and verified.

## Ordered delivery backlog: Items 21–32

- **Item 21 — Pack compiler and signed bundle format.** Implement deterministic bundle and versioned manifest, exact pinned dependencies, capability analysis, signing, and build verification. Done only when independent builds with identical inputs yield identical bundle hashes; widening inputs fail with typed errors; manifest schema is published and tested.
- **Item 22 — Capability ceiling enforcement.** Schema, build, and runtime checks. Done only when schema cannot express widening, out-of-ceiling builds fail, and a runtime ceiling downgrade fails closed.
- **Item 23 — Provenance / offline verification.** Add verifiable build provenance and `cyclothone pack verify-provenance`. Done only when offline verification succeeds on valid artifacts and tampering fails with a typed reason; claim SLSA level only when evidenced.
- **Item 24 — Revocation and kill switch.** Authorized revocation event, request-boundary suspension, tenant notifications/receipts, and verification CLI. Done only when revoked receipts fail verification and propagation is measured in a controlled 400-session test.
- **Item 25 — Shadow replay before install.** Journal-backed replay and signed divergence report. Done only when computed impact and attestation differences are reproducible.
- **Item 26 — Overlay versioning / semantic diff.** Immutable overlays and structured diffs. Done only when a version migration creates a superseded historical attestation and a new attestation with explicit gaps, both verifiable offline.
- **Item 27 — Tenant upgrade protocol.** Preview, shadow, explicit commit, continuity. Done only when no attestation is silently re-derived and old attestations are retained per policy.
- **Item 28 — Federation overrides under delegation.** MSSP narrowing overlay bound to delegation. Done only when revoked/expired/out-of-scope delegation blocks application at the next session creation and history records the result.
- **Item 29 — Cross-tenant federation replay.** Authorized replay with signed divergence report. Done only when every divergence has a reason code and tenant isolation is tested.
- **Item 30 — Evidence localization contract.** Structured canonical values plus localized text and jurisdiction notes. Done only when missing required locale coverage fails compilation and localized text cannot alter machine semantics.
- **Item 31 — Residency enforcement at journal writer.** Storage-boundary validation and region-aware persistence. Done only when cross-region writes fail closed with typed evidence and all relevant data paths are assessed.
- **Item 32 — Jurisdiction clock engine.** Versioned regulator clocks and closure blocking. Done only when an open mandatory clock blocks closure unless a signed, clock-specific justification is accepted and journaled.

## Execution order and dependency gates

Item 21 is the next implementation block. The compiler and bundle contract are foundational, but do not claim the marketplace safe until Items 22–25 and the required runtime/journal integration are verified. Continue the Dark Web Monitoring workstream in parallel where independent; source-attempt journal migration remains unapplied and not wired to the live worker until evidence linkage, tenant ownership, lease fencing, and negative paths are proven. Railway remains blocked pending the user's upgrade. No production deployment, worker activation, or migration is implied by this document.

All implementation follows inspect → implement → test → verify. Tests must cover tampering, dependency pin drift, duplicate YAML keys, unknown/widening fields, ceiling changes, missing/revoked signing keys, revoked bundles, stale delegation, cross-tenant isolation, replay divergence, missing locale, and cross-region write attempts. A failed/unavailable source is not a clean result, and preview is never verified status.
