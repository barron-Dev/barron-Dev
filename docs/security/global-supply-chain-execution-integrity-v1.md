# Global Supply Chain & Execution Integrity — Phase 3

## Scope
One tenant-scoped principal and device trust boundary for external clients, developers, employees, vendors and system workloads. Principal categories are derived from authenticated Cyclothone identity, not chosen by request bodies.

The live production schema does not currently contain an `mdi_devices` table. It contains `mdi_device_intel`, which is device intelligence rather than an enrolled endpoint registry, and a separate `devices` table. This phase therefore establishes its own universal cryptographic endpoint registry; it does not falsely bind MDI intelligence records to endpoint identities. A later integration must use the authoritative Cyclothone device-enrollment identity and a tenant-bound foreign key.

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
This phase establishes schema, challenge/signature primitives and the gated API. It does not yet integrate browser WebAuthn assertions, Android/Apple/TPM certificate-chain verifiers, mTLS workload attestation, HSM-backed verifier keys, every download/payment/upload endpoint, or an authoritative package-intel feed. Do not market it as universal hardware verification until those adapters and authenticated end-to-end tests are complete.
