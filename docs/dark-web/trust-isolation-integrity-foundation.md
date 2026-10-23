# Dark Web trust and isolation foundation

## Activation boundary
This change adds dormant schema and deterministic, side-effect-free primitives. It does not enable a source, open Tor circuits, fetch onion addresses, decrypt a client key, execute GPG, ingest canaries, or create intelligence findings. Test against a disposable database and runtime before any production migration.

## Controls
- Client auth stores ciphertext and a KMS key reference only. An approved KMS adapter, rotation, and audited decrypt path are required before provisioning.
- Circuit isolation derives an opaque tenant/source HMAC username. Runtime must explicitly enable and verify Tor SOCKS authentication isolation; a distinct username alone is not proof of distinct circuits. Onion services do not use exit nodes.
- Mirror verification consumes an independent OpenPGP verifier result. It does not parse/verify OpenPGP itself. Publisher fingerprint pinning must be authenticated out-of-band.
- Dedup uses SHA-256, normalized text, MinHash, and SimHash as similarity evidence only. Algorithm and shingle versions must be persisted.
- Anomaly scores require a versioned source-specific baseline and are review signals, not findings.
- Honeypot and canary telemetry live in separate tables with no relation to intelligence findings. Canary events require provider signature verification and idempotent provider event IDs.
- HSFETCH descriptor health is separate from HTTP reachability and content inspection.

## Required isolated acceptance gates
1. Apply the full production migration chain plus this migration in a disposable database.
2. Verify RLS enabled and anon/authenticated have no privileges; service-role-only database access.
3. Test tenant authorization and cross-tenant denial in the API before adding decrypt routes.
4. Test Tor SOCKS auth isolation against a disposable Tor runtime; verify circuit evidence, not just usernames.
5. Test valid, invalid, unpinned, wrong-host, and malformed signed mirror fixtures with the real OpenPGP verifier.
6. Verify exact duplicate collapse and near-duplicate candidate generation using labeled fixtures.
7. Prove anomaly and deception events cannot directly create intelligence findings.
8. Test HSFETCH success, timeout, absent descriptor, unavailable control port, and parse failure distinctly.
9. Keep all source monitoring flags off until every gate passes and release approval is recorded.

## Not claimed complete by this slice
KMS adapter, Tor control client, OpenPGP verifier and pin lifecycle, pgvector-backed baseline worker, signed canary provider integration, HSFETCH collector, API authorization endpoints, and customer evidence/history wiring remain integration work. Creating this PR does not authorize a production migration.
