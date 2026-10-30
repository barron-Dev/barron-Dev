# Global Supply Chain & Execution Integrity — Phase 3

## Scope
One tenant-scoped principal and device trust boundary for external clients, developers, employees, vendors and system workloads. Principal categories are derived from authenticated Cyclothone identity, not chosen by request bodies.

The live production schema does not currently contain an `mdi_devices` table. It contains `mdi_device_intel`, which is device intelligence rather than an enrolled endpoint registry, and the existing tenant-scoped `public.devices` endpoint-enrollment registry. Global cryptographic attestations are linked to `public.devices` with a composite tenant/device foreign key; MDI intelligence is not treated as endpoint enrollment evidence.

## Cryptographic contract
- Device private keys remain on the endpoint. Cyclothone stores a public key and tenant-scoped device fingerprint.
- Challenges are random, single-use, three-minute nonces bound to principal, device, purpose and canonical context hash.
- Signatures use canonical JSON and Ed25519 in v1.
- A valid signature proves key possession only. It does not prove TPM, Secure Enclave, Android Key Attestation, Apple App Attest, WebAuthn authenticator attestation or workload identity.
- New registrations are always UNVERIFIED / key_possession. Sensitive actions require VERIFIED and fresh attestation; only a trusted platform-specific verifier may promote a device to VERIFIED; without one, sensitive actions fail closed.
- There is no assumed SQL Ed25519 verifier. Signature verification occurs in the API; database rows preserve the decision.

## SBOM and package intelligence
- CycloneDX JSON components are normalized to purl and version and checked against source-backed package intelligence.
- malicious and compromised block; suspicious and unknown require review. Missing intelligence is never called clean.
- No package threat records are seeded. A provenance-checked intelligence ingestion pipeline is still required.
- Customer blast-radius views disclose only that tenant's projects. Cross-tenant graph access is platform-owner-only and is not exposed in v1.
- No automatic global kill switch is triggered. Containment must use existing response authority and human approval.

## Release boundaries
This phase establishes schema, challenge/signature primitives, enrolled-device binding and the gated API. It does not yet integrate browser WebAuthn assertions, Android/Apple/TPM certificate-chain verifiers, mTLS workload attestation, HSM-backed verifier keys, every download/payment/upload endpoint, or an authoritative package-intel feed. Do not market it as universal hardware verification until those adapters and authenticated end-to-end tests are complete.


## Enrolled device binding

The global attestation record is now linked to the existing tenant-scoped `public.devices` registry using a composite tenant/device foreign key. Challenge, key-registration, action-authorization and SBOM routes require a canonical UUID for an active enrolled device; arbitrary client-chosen device labels are rejected. Registration remains `UNVERIFIED` proof-of-possession until a trusted hardware verifier is configured. This does not equate the MDI `mdi_device_intel` intelligence table with an enrolled device registry.


## Production migration verification

The production schema includes the device-binding migration and the follow-up SBOM database guard. The global registration RPC now requires an active row in `public.devices`, and the SBOM commit transaction independently joins that registry and rejects devices that are inactive, stale, future-dated or revoked. Device identity is tenant-bound by a composite foreign key; the earlier unbound registration RPC signature was dropped.


## Sensitive read enforcement

The tenant blast-radius query is a signed POST operation, not an unauthenticated GET. It requires an active enrolled device, a one-time challenge bound to the exact package URL/version query, a valid Ed25519 signature, fresh VERIFIED device state, and a persisted execution receipt before returning tenant-scoped project evidence. Cross-tenant graph results remain unavailable through this endpoint.

## Atomic sensitive-action authorization

The sensitive-action route now delegates its final decision to `global_authorize_execution_atomic`. The database transaction locks the tenant-bound device row, rechecks the linked enrolled device is active, verifies principal lifecycle state, atomically consumes the one-time challenge, rechecks VERIFIED hardware/workload assurance and the five-minute freshness window, and appends the immutable execution receipt in the same transaction. The API still performs Ed25519 signature verification over the canonical challenge envelope and passes only that result to the RPC. A successful key-possession signature alone cannot satisfy the hardware assurance requirement.

This closes the API read/consume/receipt race for the sensitive-action endpoint. It does not yet establish hardware provenance: the trusted platform-specific verifier and its controlled promotion/revocation workflow remain outstanding. The RPC is service-role-only; no authenticated or anonymous caller can invoke it directly.

## Device revocation and re-enrollment lifecycle

The next migration adds tenant-bound append-only device trust events and a service-role-only revocation RPC. Revocation marks the attestation REVOKED, removes hardware assurance, expires the attestation immediately, and consumes every outstanding challenge for that principal/device fingerprint in the same transaction. The API exposes this only to principals with the explicit `global:device:revoke` scope and records a tenant-scoped actor fingerprint rather than raw operator identity.

A database trigger prevents a revoked attestation row from being silently reactivated by clearing `revoked_at`. The existing registration upsert therefore cannot resurrect a revoked key record; a replacement must use a newly enrolled platform device identity and complete fresh proof-of-possession plus a future trusted attestation workflow. This is deliberately not an automatic re-attestation path. The migration is proposed on PR #104 and has not been applied to production.
