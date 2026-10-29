# AI Security ecosystem implementation status

This work is under Service 09 — AI Security, not only Omni-Vision. Watchtower and Omni-Vision remain separate service workstreams while sharing evidence and release boundaries.

## Added in this block
- Signed model-manifest verification: local artifact SHA-256 is checked against an Ed25519-signed manifest from a separately trusted key directory. No network model fetch occurs.
- Evidence-grounded multi-agent threat review: agent narratives remain hypotheses; adjudication validates tenant scope, source verification, coverage and independent source provenance. It never infers a verdict from phrases like "known intruder".
- Privacy-proof verification boundary: accepts public statement hashes and proof bytes only; requires a trusted circuit verification-key hash and a real circuit-specific verifier. Missing verifier returns unavailable, not verified. No raw biometric payload is accepted.
- Physical-response policy: records policy decisions for a small allowlist of safety responses, requires explicit approval for motion-affecting actions, denies pursuit/interception/takeoff/arming/GPS goto, and never dispatches a device command.
- Source-only migration for tenant-scoped model attestations, threat-hunt reviews, privacy-proof verification receipts, and interdiction decisions. All tables are RLS-enabled, not exposed to anon/authenticated, and service-role-only. Review/decision receipts are append-only.

## Critical boundaries
- SHA-256 alone is not publisher authentication; trust depends on the signed manifest and a protected, independently provisioned public key.
- A curve point or embedding hash is not a zero-knowledge proof. No ZK claim is made until an audited circuit, trusted verification key, public-input schema, circuit version, and independent test vectors are supplied.
- GDPR/PDPL compliance cannot be mathematically guaranteed by one proof. Lawful basis, purpose limitation, minimization, retention, data-subject rights, residency, access control, and DPIA/impact assessments remain required.
- Physical security systems must not autonomously pursue, intercept, or physically confront a person. This code does not connect to MAVSDK or robot actuators.
- Migration is source-only until the missing checked-in migration history is reconciled with the live database. Do not apply to production while migration source drift remains unresolved.

## End-to-end release gates
1. Restore authoritative migration sources for the missing historical versions and validate the source/live history match.
2. Provision actual trusted model signing keys and verify artifact manifests using a real locally stored artifact.
3. Bind the evidence adjudicator to server-side, tenant-scoped evidence lookup (not caller-provided trust flags).
4. Provision and audit an actual ZK circuit/verifier and verify it against public test vectors.
5. Bind response decisions to the existing AI kill-switch, AI security decision ledger, device registry, and one-time approval kernel; never bypass those controls.
6. Complete authenticated API/UI integration, test tenant isolation and replay/tamper/failure paths, and verify production runtime with an authorized site.
