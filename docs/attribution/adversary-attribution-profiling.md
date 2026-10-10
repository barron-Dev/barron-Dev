# Cyclothone DW — Adversary Attribution & Threat Actor Profiling

## Implemented in the feature branch

- Seven-signal probabilistic scoring with the requested weights, explicit missing-signal handling, per-signal explanation and conservative confidence guardrails.
- All four Diamond Model vertices are populated; unknown vertices remain explicit. ATT&CK technique IDs and CAPEC IDs are syntax-validated; both the Cyber Kill Chain and Unified Kill Chain phase mappings are included.
- Cross-source activity-cluster assembly uses source IDs, record IDs, stable tenant-scoped cluster IDs, hashed evidence references, and a bounded evidence record allowlist.
- The dark-web matcher enqueues attribution work for a tenant/watchlist match. The API lifespan starts a worker that claims jobs atomically, reads tenant-owned findings, assembles a cluster, scores it, stores evidence/assessment, and emits a durable alert-outbox event.
- Profiles and assessments are tenant-scoped for provisional/customer-derived data. Public actor profiles are read-only to customer findings; one tenant's provisional profiles and relationship evidence are not visible to another tenant's API.
- Analyst review endpoints, tenant-filtered assessment/actor APIs, relationship listing, ATT&CK catalogue lookup, optional Leiden communities, and encrypted-secret HMAC-signed webhook registration/delivery are implemented.
- MITRE Enterprise ATT&CK STIX catalogue synchronization is implemented behind the environment flag CYCLOTHONE_ATTACK_CATALOG_SYNC_ENABLED=true, with a configurable official STIX URL and database state.
- Added SQL migrations for profile/assessment/evidence tables, tenant-scoped jobs, atomic job claiming/retry, alert outbox, encrypted webhook registrations/delivery ledger, ATT&CK catalogue cache, and idempotency indexes.
- Added focused tests for cluster assembly, evidence provenance, ATT&CK/CAPEC mapping, graph shape, and HMAC signature determinism.

## Runtime configuration required

- Apply sql/20261010170000_dw_attribution_profiling.sql, sql/20261010180000_dw_attribution_execution.sql, sql/20261010185000_dw_attribution_indexes.sql, sql/20261010190000_dw_attack_catalogue.sql, sql/20261010200000_dw_attribution_retention.sql, and sql/20261010210000_dw_attribution_event_fingerprint.sql through the approved migration process.
- Assign developer API keys/OAuth apps the scopes threat-intel:read, threat-intel:review, and threat-intel:manage as appropriate.
- For outbound webhooks set CYCLOTHONE_WEBHOOK_ALLOWED_HOSTS to an explicit comma-separated host allowlist and set CYCLOTHONE_WEBHOOK_ENCRYPTION_KEY to a valid Fernet key. No host is contacted unless allowlisted. Outbound delivery uses HMAC-SHA256 over timestamp.body, timestamp/signature headers and an idempotency key.
- To synchronize MITRE ATT&CK, set CYCLOTHONE_ATTACK_CATALOG_SYNC_ENABLED=true. The worker refreshes the official Enterprise ATT&CK STIX bundle no more than every six hours and records the last success/error. If outbound network access is blocked, it reports failure rather than claiming the catalogue is fresh.
- Leiden community detection runs only when the attribution-graph extra is installed. Without igraph and leidenalg, the API returns status=unavailable and the real bipartite graph; it does not invent communities.
- Set CYCLOTHONE_DW_ATTRIBUTION_ENABLED=true only after all migrations are applied and required scopes exist; the worker is intentionally disabled by default to avoid repeatedly calling missing production RPCs. The worker logs schema/config failures and retries queued jobs with bounded exponential backoff.

## Attribution and privacy controls

- Scores are probabilistic association estimates, never proof of real-world identity. Every assessment stays review-gated. A numerical CONFIRMED tier is not an automatic public allegation.
- Infrastructure overlap has the strongest weight; TTP, malware, behaviour, victimology, identity markers and timing are independently explained. Temporal/behavioural similarities alone never create actor relationships.
- Raw message content and matched identifiers are not copied into the change-event payload. Evidence stores hashes, source provenance, allowlisted metadata and sanitized source URLs; query strings and fragments are removed.
- Public profiles are not enriched with customer watchlist identifiers. Customer-derived provisional profiles, assessments, evidence and relationships are tenant-scoped.
- Third-party feeds/tools (Censys, Flare, VoidAccess, Recorded Future/Mandiant, EUREKHA, Neo4j/APOC, GNN, forum/Telegram tools) are not represented as installed or live without separate verified integration work and credentials. Leiden is optional and is not a GNN; no 91.2% accuracy claim is made.
- These commits are code and unapplied migrations only. No CI, Vercel build/deployment, migration, or production configuration change was run.

## Remaining external release gates

1. Apply migrations and provision runtime environment variables/API scopes.
2. Install the graph extra if Leiden is required in production.
3. Run one consolidated CI/test block and verify worker, tenant isolation, migration constraints, official catalogue sync, webhook signatures and live end-to-end evidence with approved credentials.
4. Validate current ATT&CK technique IDs against the synchronized catalogue before presenting them as recognized techniques.
