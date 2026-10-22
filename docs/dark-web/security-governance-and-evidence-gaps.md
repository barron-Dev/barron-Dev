# Native DW security, evidence, governance, and restore gates

Status: **engineering review / not a release approval**  
Applies to: Cyclothone native Dark Web Monitoring and the queue-worker PR  
Production changes: none authorized by this document

## 1. Current operating boundary (2026-10-22)

- The Railway production service page supplied by the owner shows **Trial expired**, deploys paused, service offline, and no active deployment. A live worker/Tor run, deployment-based test, or production end-to-end claim is therefore blocked until the hosting state is restored. Do not work around this with production credentials in a new runtime.
- PR #73 (`feat/dw-discovery-queue-worker-foundation`) remains draft/unmerged. Its head at this review was `f28745a6c5a02cd9e0c71efa96909622557ff43d`; the Vercel status was successful, but that is not proof that the Python suite ran or that the worker works.
- PR #77 (`feat/dw-source-silence-shadow`) remains draft/unmerged. Its head is `a7fd7093066c4b11f1010e55d169bfadcbc87ec5`; the PR description reports CI in progress. Do not count its tests as passed until a completed run for that exact SHA is observed.
- A read-only Supabase inventory at 2026-10-22 05:08 UTC found `dw_source_discovery_queue`, `dw_onion_seeds`, and `dw_onion_probe_evidence`, plus separate evidence-related tables. It did not return tables named `evidence_log`, `dw_source_observations`, `dw_source_silence_buckets`, or `dw_source_silence_scores`. This is a table-name inventory, not proof about external object storage or every possible evidence mechanism.
- A subsequent read-only queue snapshot in this review found **26,062 legacy jobs already in `deferred`**: 28 `feed_discovery`, 12,696 `official_source_discovery`, and 13,338 `onion_seed_discovery`; the query found no active leases for those rows. It also found 1,023 onion seed rows, all `candidate` with `monitoring_enabled=false`. This is a fresh read-only snapshot, not a worker test.
- The live Supabase migration ledger records the earlier native-onion source, native honeytoken, Reddit-exclusion, discovery-queue lease/RPC, and legacy-backlog-quarantine migrations. Specifically, it contains migration entries for `dw_discovery_queue_lease_columns`, `dw_discovery_queue_claim_complete_rpc`, and `dw_discovery_queue_legacy_backlog_quarantine_forward`. Therefore the quarantine change is **already reflected in live migration history**; do not describe it as merely prepared. The source-silence telemetry migration is not present in the queried migration-name results, and its three telemetry tables were absent from the table inventory.
- Supabase security advisors returned 39 informational `rls_enabled_no_policy` findings overall, including DW tables such as `dw_onion_seeds`, `dw_onion_probe_evidence`, `dw_source_discovery_queue`, `dw_source_discovery_registry`, `dw_source_health_events`, and `dw_canary_tokens`. This does **not alone prove exposure**—RLS with no policies normally denies client-role row access—but effective grants and service-role-only intent must be checked explicitly before release. The same advisor run also reported a `SECURITY DEFINER` function, `public.giril_start_customer_admission(uuid)`, executable by `authenticated`, plus leaked-password protection disabled; these are separate production security follow-ups, not proof of a DW exploit. See the [Supabase RLS advisor](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy), [SECURITY DEFINER advisor](https://supabase.com/docs/guides/database/database-linter?lint=0029_authenticated_security_definer_function_executable), and [password protection guidance](https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection).
- No migration, production write, worker activation, deployment, restart, source activation, or Tor probe was performed as part of this review.

## 2. Secrets and trust-boundary matrix

This is a code-derived inventory, **not** a claim that production secret values, owners, permissions, or rotation dates have been inspected. Never print or copy secret values into this document.

| Asset / configuration | Code evidence or known purpose | Boundary required before release | Current assessment |
|---|---|---|---|
| Supabase server credential: `SUPABASE_SECRET_KEY` or fallback `SUPABASE_SERVICE_ROLE_KEY` | `src/cyclothone/storage/supabase_client.py` creates one privileged server-side client and exposes generic table operations plus RPC calls | Prefer a dedicated worker identity and narrowly granted RPCs; separate API and worker credentials; verify grants/RLS and rotate/revoke in isolation | **High-risk review item**; actual deployed variable presence/value/scope not inspected |
| Supabase URL: `SUPABASE_URL` | Used with the server credential | Record environment/project identity and allowlisted endpoint; never log credentials or authorization headers | Presence/owner not verified |
| Tor proxy: `CYCLOTHONE_DW_ONION_PROXY` | Native crawler defaults to `socks5://127.0.0.1:9050` when unset | Fail closed if the expected Tor route is absent; demonstrate the actual request route and circuit/stream isolation in a disposable runtime; no direct-network fallback | **Unproven**; SOCKS config alone is not route proof |
| Onion seed list: `CYCLOTHONE_DW_ONION_SEEDS` | Explicit seed configuration; candidate/seed URL is not proof of availability or legitimacy | Change-controlled list, URL policy, source authority and tenant/target authorization before any request | Configuration is not itself a secret; integrity/approval trail needed |
| Telegram channel configuration: `CYCLOTHONE_DW_TELEGRAM_CHANNELS` | Public-channel source configuration is part of the declared surface-source path | Treat channel list as scope configuration; any API token used by another collector must be inventoried separately and never logged | Exact runtime variables/credentials not inspected |
| Tor onion client-auth private keys (if required by an authorized source) | No verified key-loading path was established in this review | Store in a dedicated secret manager or equivalent; mount read-only only into the process needing it; restrictive filesystem permissions; named owner; rotation and revocation drill | **Unknown / not demonstrated** |
| Canary webhook signing key | No verified DW-path implementation was established in this review | Separate from DB and Tor credentials; signature verification, timestamp/replay protection, rotation and revocation | **Unknown / not demonstrated** |
| Logs, crash reports, WARC, telemetry, fixtures | Potential accidental exfiltration sinks | Redact headers, tokens, cookies, client-auth material, target PII where unnecessary; prohibit secret values in artifacts and test output; scan before release | Automated leak scan not run |

### Required inventory fields (values stay out of Git)

For every secret/key, record in the approved secret manager or access-controlled inventory: secret identifier (not value), purpose, owning team/person, environment, storage location, authorized principals, last rotation timestamp, rotation procedure, revocation/recovery procedure, audit-log location, and expiry/renewal requirements.

Release tests must prove:
- production DB credentials are not available to local/dev/test workers;
- a worker cannot perform unrelated tenant or schema operations;
- the worker can call only the intended RPCs and required reads;
- revoked credentials fail closed and recovery does not require exposing the old value;
- secret values are absent from logs, exceptions, traces, WARC metadata, and client bundles;
- a compromised worker credential can be revoked without rotating every unrelated key.

Do not rotate or modify production secrets as part of this review.

## 3. Evidence implementation gap review

### What the inspected code actually does

- `src/cyclothone/darkweb/native_onion.py` uses `httpx.AsyncClient(proxy=...)`, bounded response handling, HTML parsing, and SHA-256 response digests. It is an HTTP(S)-over-configured-proxy crawler; the inspected implementation does **not** demonstrate Tor control-protocol circuit isolation or HSFETCH.
- `src/cyclothone/darkweb/scheduler.py` writes probe metadata through `dw_record_onion_probe_result`. It explicitly records `tor_route_verified=false`, `publisher_identity_verified=false`, `customer_matching_allowed=false`, and only labels content inspected when a successful response has a digest and positive byte count. That is appropriately conservative, but it is not the requested end-to-end evidence chain.
- The inspected native-onion path does not demonstrate a durable WARC writer/read-back verifier, sanitizer artifact lineage, OpenTimestamps proof creation/verification, or a Merkle-anchor-aware restore gate. These remain **unproven**, not implicitly implemented by the presence of a SHA-256 field or an evidence table.
- The live table inventory includes `dw_onion_probe_evidence` and other evidence-related tables, but a table name alone does not prove append-only semantics, tenant-scoped retrieval, cryptographic chaining, external timestamp anchoring, or restore safety.
- The queue worker uses a lease token and fenced completion RPC in its proposed migration/code. Those are useful queue controls but do not make source content, Tor routing, WARC durability, or the evidence chain verified.

### Gap closure order

1. **Keep source claims honest.** Until Tor routing is independently validated, report route unverified. A successful HTTP response through a configured proxy must not be labeled verified dark-web coverage.
2. **Prove capture durability.** Add a bounded WARC capture with digest, durable write, independent read-back, structural validation, and explicit failure state. Do not substitute an in-memory body when durable storage fails.
3. **Prove artifact lineage.** Store raw and sanitized artifacts separately, with content digests, sanitizer version, source/job IDs, access policy, and retention metadata. Never serve raw page content directly to customers by default.
4. **Prove target/tenant authorization.** A job must carry an authorized target and tenant identity; matching must not be run against an implicit global watchlist for a customer result. Test cross-tenant denial explicitly.
5. **Prove append-only evidence and anchoring.** Define canonical serialization, hash-link fields, ordering, append authority, and an external anchor strategy. Verify OTS proofs against the exact digest; distinguish pending from verified. Hashes alone do not prove who created content or when.
6. **Prove partial-failure recovery.** Inject failures between queue completion, artifact write, evidence append, timestamp proof, and source-health update. Any incomplete chain must stay visibly incomplete and be safely retried without duplicate success.
7. **Prove independent retrieval.** A separate process, using only the evidence ID and authorized tenant context, must retrieve the artifacts and recompute digests/links/proofs. The original writer process must not be the only verifier.

### Acceptance rule

Do not call the native DW vertical slice complete until the same authorized test job has durable IDs and trace evidence for claim → target authorization → verified Tor route/circuit isolation → HSFETCH or a documented, reviewed equivalent → WARC capture/read-back → sanitization → classification with honest calibration state → authorized target match → append-only evidence → OTS/Merkle verification → source-health outcome → second-process retrieval. If any step is missing, mark the vertical slice **FAIL / INCOMPLETE**, not clean.

## 4. Source governance worksheet (counsel review required)

Complete one row per source and collection method **before enabling collection**. A public URL alone is not sufficient authority to collect or retain all linked content.

| Field | Required entry |
|---|---|
| Source class and named source | E.g. public onion service, public Telegram channel, Pastebin, Bluesky, official directory, historical feed |
| Collection method and exact scope | Seed/channel/endpoint, request types, frequency, pages/bytes limits, redirects policy |
| Authority and purpose | Who authorized monitoring, target owner/tenant, specific security purpose, documented approval date |
| Data categories | Identifiers, account names, contact details, message/page text, credentials or sensitive content that could appear |
| Legal basis and jurisdiction | Applicable basis/authority and jurisdictions; counsel must determine whether GDPR or other privacy/data-protection rules apply |
| Necessity and minimization | Why each category is needed; what is excluded, hashed, redacted, or never collected |
| Retention and deletion | Separate periods for raw WARC, sanitized artifact, finding metadata, evidence hashes, and audit records; deletion and legal-hold process |
| Access and tenant isolation | Roles permitted to view raw/sanitized evidence; tenant-scoped retrieval; break-glass process and audit trail |
| Transfers and processors | Hosting/storage region, subprocessors, cross-border transfer mechanism where relevant |
| Source terms and restrictions | Terms, robots/access controls, licensing, copyright, access restrictions, and restrictions on redistribution |
| Risk review | Personal-data/special-category risk, minors/vulnerable-person risk, criminal-allegation risk, DPIA/impact assessment need |
| Incident and escalation | Data-subject request route, law-enforcement request handling, takedown/retention hold, security contact |
| Approval | Legal reviewer, security owner, product owner, approval timestamp, review/expiry date |

Minimum source-class notes:
- **Native onion:** treat discovered hosts as untrusted candidates. Candidate status is not identity, reachability, criminality, or authorization.
- **Telegram/Pastebin/Bluesky:** surface-web collection remains a separate source class from onion collection. Define public-only scope, rate limits, data minimization, and retention per source.
- **Historical feeds:** label as historical and never represent their records as a fresh live check.
- **Public indexes/directories:** index inclusion is provenance for a candidate, not independent proof of publisher identity or current availability.

This worksheet is an engineering governance template, not legal advice. Qualified counsel must approve the actual source-specific basis, terms, retention, transfer, and data-subject handling before production collection.

## 5. Restore drill: prevent a forked evidence history

Run only in a disposable environment; no production restore or write is authorized here.

1. Freeze the test writer and record the last committed sequence/anchor position.
2. Take a consistent backup of evidence rows, artifact manifests, WARC objects, sanitized objects, OTS proof files/statuses, Merkle roots/anchor metadata, and the schema/version needed to interpret them.
3. Restore into a fresh isolated database and a new object-store prefix. Do not point a writer at the restored copy yet.
4. Recompute each artifact digest and every evidence hash link using the documented canonical encoding. Verify ordering and all available Merkle roots/OTS proofs; pending timestamp proofs must remain pending.
5. Run a negative control: omit one evidence row, one referenced artifact, and one anchor in separate disposable copies. The verifier must fail loudly and identify the missing/mismatched item.
6. Verify from a second process with the same evidence IDs and an ordinary authorized reader identity, not the original writer's privileged client.
7. Only after all historical checks pass, append one test record to the restored chain and verify the old and new chain from a second process.
8. Record RPO, RTO, restore operator, missing-object behavior, anchor reconciliation result, and sign-off.
9. If any anchor or link cannot be reconciled, keep the restored chain read-only; never append and create a plausible-looking fork.

A successful database restore alone is not a successful evidence restore. The artifacts and external anchors are part of the evidence system.

## 6. Defensible product statement

> **Cyclothone records and verifies evidence from explicitly authorized dark-web monitoring jobs, and reports findings only when source availability, target matching, and evidence integrity can be demonstrated.**

This is the narrowest useful promise supported by the intended acceptance criteria, not a statement that the current product has already passed them. Until the vertical slice passes, customer copy must say that the capability is under validation. Do not promise comprehensive dark-web coverage, attribution, calibrated risk scores, or a “clean” result when any source is unavailable, unverified, historical-only, or not checked.

## 7. Release gates

**GO only when**:
- one controlled, authorized vertical slice passes every stage in isolation;
- a restore drill detects omissions and verifies the restored chain before append;
- secret owners, boundaries, rotation/revocation tests, and source-specific legal approvals are recorded;
- tenant isolation and independent evidence retrieval pass;
- CI results are observed for the exact commit SHA and test branch;
- runtime image and migration state are recorded, and production release has separate explicit approval.

**NO-GO when**:
- Railway remains offline or the actual runtime cannot be tested;
- Tor route/circuit isolation or durable WARC read-back is unproven;
- a secret is broadly shared or a worker can exceed its intended authority;
- source authority, tenant, or legal/retention posture is ambiguous;
- a restore can fork the chain or missing evidence can pass verification;
- unavailable sources or zero matches are shown as “clean”; or
- any result relies on mocks, synthetic provider success, or candidate counts as coverage.

## 8. Immediate next steps (non-production)

1. Correct and verify branch-specific test commands; run tests only in a verified isolated environment and record exact SHA/results.
2. Review RPC signatures, effective grants, RLS, and worker privilege scope read-only; validate proposed SQL on a disposable database before any production migration.
3. Add WARC/restore/tenant-fencing tests and an independent verifier before expanding collectors.
4. Complete the source governance worksheet with owners and counsel; do not fill unknowns with assumptions.
5. Revisit live execution only after the Railway trial/hosting issue is resolved or the owner explicitly approves a separate disposable runtime and its cost. Do not use production secrets in that runtime.
