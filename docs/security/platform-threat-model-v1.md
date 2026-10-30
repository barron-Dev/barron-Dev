# Cyclothone Platform Threat Model v1

Status: normative design baseline; not a certification or proof of deployed controls.
Owner: Cyclothone security architecture. Review on every major release and after a material incident.

## Security objective
Cyclothone must preserve tenant isolation, evidence authenticity, journal confidentiality, and verifiability even when one application component, operator identity, signing key, pack, or integration is compromised. Encryption at rest is necessary but does not substitute for authorization boundaries.

## Assets and trust boundaries
- Tenant-scoped source-attempt journal, evidence payloads and references, coverage state, packs/overlays, Result Contracts, crisis records, delegation chains, and deletion decisions.
- Tenant signing identities and platform signing identities; their purposes must be distinct and non-interchangeable.
- Identity and authorization plane, API/application plane, workers/collectors, storage/journal writer, key service, build/provenance system, support/break-glass path, and external integrations.
- Database service roles and infrastructure administrators are privileged trust boundaries, not assumed trustworthy merely because they are internal.
- Logs, backups, replicas, queues, exports, support systems, telemetry, and notification providers are data paths and must be included in residency and exfiltration analysis.

## TM-01 — Journal exfiltration
Threat: application-node compromise or over-broad database identity reveals asset inventory, source health, coverage gaps, pack state, and customer defensive posture.
Required: tenant/region partitioning where supported; narrow row and column privileges; distinct cross-tenant authorization path; deny-by-default service identities; audited cross-partition reads; production-safe adversarial isolation probes. A single shared service credential with unrestricted journal reads fails this control.
Proof: adversarial cross-tenant read tests, grants/RLS review, query audit samples, and deployment identity inventory.

## TM-02 — Signing-key compromise
Threat: a stolen key forges receipts, attestations, or bundles and retroactively undermines trust.
Required: HSM/KMS-backed private keys where supported; purpose-scoped keys; dual-control ceremony for generation/rotation/revocation; signed key-transparency events; immutable public-key history; verifier checks key purpose, validity interval, revocation and transparency inclusion. Rotation does not make signatures issued during a compromised interval trustworthy; affected artifacts must be marked suspect and re-evaluated.
Proof: ceremony record, key inventory, rotation/revocation drill, independent signature verification, and transparency consistency test. Existing key tables alone do not establish HSM custody.

## TM-03 — Tenant-to-tenant lateral movement
Threat: delegation, federation, MSSP, or shared intelligence paths cross an unauthorized tenant boundary.
Required: explicit capability and tenant scope at every hop; bounded delegation; no ambient tenant context; journaled authorization decisions; replayable chain; continuous production-safe isolation probes using dedicated principals and non-destructive reads.
Proof: negative cross-tenant read/write tests, expired/revoked delegation tests, and per-release isolation report.

## TM-04 — Privileged insider
Threat: support, platform operations, or a contractor reads tenant evidence without a valid purpose.
Required: break-glass with two-person approval, narrow time window and reason; no standing human access; session recording where lawful; every access produces a tenant-visible event; post-hoc review and tenant notification subject to documented lawful exceptions. Audit events must be written independently of the accessed data path.
Proof: denied single-approver test, approved access simulation, tenant-visible event readback, and review SLA.

## TM-05 — Pack/compiler/build supply chain
Threat: malicious pack, dependency, compiler, build environment, or signing path creates an artifact that exceeds declared authority.
Required: raw pack definitions never execute at runtime; deterministic compilation; dependency lock and provenance; capability ceiling enforced at build and runtime; isolated build workers; signed artifact and provenance; independent reproducibility check; revocation and session-boundary enforcement. SLSA L4 is a target and must not be claimed before build isolation, provenance, review, and reproducibility controls are independently evidenced.
Proof: reproducible build comparison, provenance verification, undeclared-capability test, revoked-pack replay test, and dependency inventory.

## Platform-wide invariants
1. Tenant identity comes from authenticated authorization context, never a caller-supplied tenant identifier alone.
2. Missing identity, residency, key status, source availability, legal applicability, or verification evidence fails closed for the dependent operation.
3. A hash-shaped string is not proof that content exists or matches. Verification fetches bytes and recomputes the digest.
4. A document, migration file, passing unit test, or UI state alone is not production proof. Production claims require readback and adversarial verification.
5. Security events are append-only, tenant-scoped, content-addressed where practical, and protected against an operator altering both event and evidence.
6. Cross-tenant aggregate intelligence requires a separately documented controller/processor role, minimization model, and re-identification threat analysis.

## Incident and disclosure process
Material threat-model changes are versioned. Each release records changed threats, controls, unresolved risks, owner, evidence links, and acceptance authority. Publish a redacted version that omits exploitable deployment detail without concealing unresolved controls. After a platform compromise, preserve evidence, revoke affected authority, identify the compromised time interval, mark potentially affected attestations, notify affected tenants as legally required, and publish a post-incident control update.

## Initial gaps to close
- Verify actual database identities and partition-level authorization; RLS alone does not prove protection from a broadly privileged service role.
- Verify signing key custody, purpose separation, rotation and transparency.
- Implement production-safe cross-tenant isolation probes and tenant-visible operator-access events.
- Establish compiler provenance and independent reproducibility before claiming SLSA L4.
- Bind source-attempt journal entries to verified evidence bytes and worker/lease identity before relying on them in crisis or regulatory artifacts.
