# MDI Operational Fabric v1 — deterministic core

Status: source-only engineering foundation. No production migration, device agent, malware feed, legal certification, or enforcement path is claimed.

## Service boundaries and data flow

1. Device Integrity Evaluator (device_integrity.py): normalizes a bounded allowlist of platform observations, applies versioned deterministic rules, and hashes canonical evidence. Client observations are not hardware proof. A trusted server-side attestation verifier must validate hardware claims before promotion.
2. Sovereignty Policy Engine (sovereignty_policy.py): converts trusted jurisdiction evidence into an allowlist and transmission decision. GPS, MCC/MNC, IP geolocation, and a user-supplied country are hints, not authoritative legal jurisdiction. Unverified/conflicting evidence is local-only. This module intentionally does not choose a cloud region; the control plane must map an approved policy to an available residency boundary and verify it before transmission.
3. Threat Hash Registry (threat_hash_registry.py): normalizes SHA-256 package hashes and source identifiers into deterministic evidence records. It does not scan binaries or query external feeds. Unknown is not benign. Source identifiers alone do not prove independence, accuracy, freshness, or signer authority; the pure builder never promotes verdicts to enforcement. A separate trusted provenance verifier and signed registry distribution are release gates.
4. Offline Response Planner (offline_response.py): returns a deterministic, non-destructive plan for a local adapter. It does not itself wipe data, disable radios, kill network traffic, or claim OS-level enforcement. Corporate-container lock and Cyclothone-scoped key invalidation require platform-specific adapters, managed enrollment, and execution receipts.
5. Signed Journal / Contracts (PR #98): contract verification precedes trusted journal writes. Current database RPC is service-role trust-bound and does not independently verify Ed25519; do not claim DB-compromise-resistant immutability until independent signed checkpoints are implemented.
6. Authenticated API and tenant control: device registration, attestation verification, policy resolution, result acceptance, and command delivery must derive tenant from authenticated server-side identity. Never accept a client-supplied tenant ID as authority. Every command requires replay protection, expiry, policy version, audience/device binding, and a verified signer.
7. Customer workspace: risk posture, coverage freshness, active incidents, evidence receipt, jurisdiction-policy status, and permitted response actions. Avoid continuous precise location by default. Do not expose raw telemetry where a summary is sufficient.
8. Developer workspace: SDK versions, API schemas, test vectors, signed policy packs, webhook configuration, replay examples, and delivery/audit status. Webhooks are signed, timestamped, replay-resistant and carry minimal data; receivers must verify them.

## Proposed workflow

native adapter -> bounded local observations -> deterministic policy/risk engine -> signed local event -> offline queue -> authenticated sync -> server-side attestation and tenant authorization -> sovereignty allowlist -> evidence/journal append -> CISO posture view -> authorized response policy -> signed, expiring device command -> platform adapter -> signed execution receipt

Each arrow is a separate trust boundary and needs positive plus negative tests. Offline events must be sequenced and idempotent on sync; stale policy packs must fail closed for sensitive operations. Device time is not trusted for ordering; use monotonic counters plus server receive time and signed checkpoints.

## Legal and platform constraints

- This is technical data minimization, not a claim that geofencing automatically makes a bank GDPR/PDPL compliant. Controller obligations, purpose limitation, retention, lawful basis, transfer mechanisms, and regional hosting require customer legal review.
- Android/iOS consumer apps cannot guarantee arbitrary app enumeration, system-wide VPN termination, hardware-key destruction, or remote wipe. Use supported platform APIs, managed-device enrollment, and corporate-only data/key scopes. Never delete personal data.
- Do not trigger lockdown solely because connectivity disappears. Connectivity loss is ambiguous. Combine independently verified compromise indicators with a tenant-approved local policy; preserve safe emergency access and recovery.
- Malware verdicts must retain source provenance, observation time, expiry, confidence, and review status. Do not upload APK/IPA binaries or personal app inventory by default. Unknown hashes stay unknown.
- No carrier API, carrier credential, carrier control, third-party malware API, or external authority is required by these core modules.

## Commercial product surfaces

- Mobile Threat Defense: deterministic device posture, app-hash evidence, and policy-based access recommendations.
- Executive/VIP Shield: stricter tenant policies, low-disclosure telemetry, high-assurance review and recovery.
- App Integrity API: signed evidence contracts and replay-resistant verification.
- Network Trust Monitor: bounded local observations for TLS/DNS/ARP anomalies; an anomaly is a lead, not proof of interception.
- Sovereignty Guard: jurisdiction evidence, field allowlists, local-only fallback and residency routing audit.
- Offline Resilience: local incident journaling and corporate-container lock plans; actual enforcement only after native adapter verification.

Pricing from the previous concept remains a hypothesis and is not a validated market price.

## Release gates

- Pure deterministic tests and static checks pass.
- Native Android/iOS adapters and managed enrollment tested on real supported devices.
- Signed policy pack verification, rollback prevention and trusted key rotation implemented.
- Tenant authorization, replay defense, evidence chain, and negative cross-tenant tests pass.
- Residency routing is verified against deployment topology; legal review completed.
- Threat intelligence is source-backed, independently reviewed and expiry-aware.
- Authenticated end-to-end tests cover online, offline, stale policy, reconnect, replay, revoked keys, and failed response actions.
- Live migration history and authoritative source/checksums reconciled before any migration-bearing PR is merged or applied.
