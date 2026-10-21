# Evidence, processing, entity graph and hostile-content controls

## Execution order and release boundary
The production discovery queue is a custom Postgres queue with lease-fenced claim/complete RPCs. This work does not add pgmq as a competing queue. The schema adds an idempotency/run ledger, health and dead-letter state, but does not replace the existing worker contract or activate jobs.

1. Wire and test idempotency into the existing lease-fenced worker; test a crash after archive write and before DB commit.
2. Add per-source circuit isolation and descriptor health; prove runtime behavior in a disposable Tor instance.
3. Capture WARC 1.1 response records and immutable metadata; the DB trigger serializes evidence inserts and computes a hash chain.
4. Sanitize extracted content before parsers, NER or matching; never execute scripts or auto-fetch embedded resources.
5. Add OpenTimestamps and RFC 3161 integrations, proof persistence and offline verification. Pending is not confirmed.
6. Add tenant-scoped entity graph with deterministic validated anchors; probabilistic links remain candidates or review items.
7. Add language detection, NER and translation provenance without overwriting source evidence.
8. Finish client-auth provisioning and SecureDrop/private-source integration only after earlier gates pass.

## Evidence guarantees and limitations
- A hash chain detects row alteration/reordering when verified from a trusted checkpoint; it alone cannot prevent a privileged database owner rewriting the whole chain. Periodic externally anchored Merkle roots and independent retention are required.
- WARC archives must be stored in immutable/versioned object storage with retention controls. An archive URI alone does not guarantee the object exists or is immutable.
- OTS proof status stays pending until upgraded and independently verified. RFC 3161 receipts remain untrusted until the token signature chain, policy, request digest and TSA trust roots are validated.
- Capture exact response bytes before decompression and preserve actual status/headers as available. HTTP libraries may normalize headers; document that boundary.
- Revisit records must point to a previously archived identical payload; text similarity alone is not enough.
- BTC and PGP normalization requires type-specific checksum/fingerprint validation before accepting canonical anchors.
- Entity matches are tenant-scoped, evidence-linked and reversible. Similarity scores do not establish identity; this slice does not perform automatic union-find merges.
- Hostile content must be parsed in an isolated no-network process. Never run JavaScript; never fetch images, CSS resources, redirects to non-approved hosts or embedded URLs. PDF extraction requires a separate resource-limited sandbox and malware verdict.
- Translation and NER outputs are derived data with model/version/config provenance; the original WARC remains authoritative.

## Remaining before merge
- Implement WARC writer/object-store adapter and verify WARC conformance/replay with fixtures.
- Implement isolated sanitizer and tests for scripts, CSS URLs, event handlers, SVG, data URLs and malformed HTML.
- Integrate the run ledger with existing claim/complete RPCs and test lease fencing, idempotency and dead-letter behavior.
- Implement OTS/TSA clients and offline verification.
- Implement language detection and model registry; named model IDs are not assumed installed.
- Run disposable-database migration-chain acceptance, privilege checks, trigger concurrency tests, graph tenant-isolation tests and CI on final head.
- No production migration, Tor probe, queue activation, timestamp submission or deployment is authorized by this PR.
