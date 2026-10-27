# Cyclothone Local Contract Journal — v1

## Scope

This module provides a small, offline-capable evidence primitive for local Cyclothone Edge execution:

- canonical JSON and SHA-256 payload commitments;
- contiguous, hash-linked events;
- Ed25519 signatures over domain-separated event digests;
- SQLite update/delete guard triggers;
- signed checkpoints that can be exported to an independent trust boundary;
- verification of sequence continuity, event hashes, stored payload hashes, signatures, and checkpoint roots.

It intentionally reuses the repository's existing `cryptography` dependency and the project's established Ed25519 verification approach. It does not introduce a second cloud trust registry.

## Security boundary

This is a local journal primitive, not a claim of an un-bypassable journal.

- SQLite triggers deter ordinary accidental mutation but can be dropped by a process with sufficient database-file privileges.
- A verifier detects event mutation while the original signing keys remain outside the compromised store.
- A signed checkpoint held outside the Edge host is needed to detect deletion/truncation or rollback to an older valid prefix. A local checkpoint alone does not protect against an administrator who can rewrite both the journal and its local checkpoint.
- Signing private keys are supplied by the caller and are never written into SQLite. Production Edge should connect this interface to TPM/HSM-backed signing without exporting private key material.
- The module stores only a payload hash by default. If `persist_payload=True` is used, callers must minimize and classify payload data; this module does not encrypt payloads at rest.
- This version uses a linear hash chain, not a Merkle Mountain Range. MMR inclusion proofs and remote checkpoint transport are later integration work.
- The code does not decide whether an action is authorized. Callers must obtain the canonical Cyclothone execution decision before appending the resulting action/outcome record.

## Offline and sync contract

An Edge node may append locally while disconnected. On reconnection, it should submit signed events plus its latest checkpoint to a cloud verifier. The receiver must validate event signatures, tenant/node binding, sequence continuity, key lifecycle/revocation, checkpoint freshness, and anti-rollback state before accepting a delta. Never merge conflicting authorization histories using a generic CRDT rule: the journal is an ordered evidence stream, while CRDTs should be limited to explicitly mergeable replicated state.

## Not included

No Supabase migration, API route, Railway/Vercel deployment, TEE/SGX/Nitro attestation, TPM integration, HSM integration, remote transparency log, or ZK proof circuit is included in this first slice. These require separate threat-model review and end-to-end verification.
