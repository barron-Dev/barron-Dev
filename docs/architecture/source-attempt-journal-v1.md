# Source-Attempt Journal v1 — implementation boundary

Status: additive migration proposal committed for review; **not applied to Supabase**, and not yet called by the live worker. This is not an E2E or production-completion claim.

## Grounded schema choices

- The request relation is `public.service_requests` (plural), with `organization_id`, `service_key`, `attempts`, `processing_state`, and `locked_until`.
- Tenant identity is resolved through `public.customer_organizations.tenant_id`. The writer fails closed if the tenant cannot be resolved.
- The existing worker's lease fence is the request's current `attempts` value plus `processing_state = 'running'` and a future `locked_until`. Both begin and completion RPCs lock and re-check the request row in the same transaction. This is request-scoped fencing, not yet a monotonic per-(asset, source) token.
- No verified generic `session_id` or stable `asset_id` relation was found in the inspected path. V1 does not invent either field. Asset-level fencing and Result Session linkage remain follow-up work after those identities are established.
- The journal is named `source_attempts` to follow the repository's plural-table convention.

## Writer contract

`begin_source_attempt`:
1. Validates parameters and that the request is an active `dark_web_monitoring` lease.
2. Resolves tenant identity from the request's organization.
3. Derives a SHA-256 idempotency key from a canonical JSON array containing tenant, request target, service key, source key, window start, and connector version. JSON array serialization avoids ambiguous delimiter concatenation.
4. Returns the existing row only when its identity fields agree; conflicting reuse fails closed.
5. Creates an incomplete row with `outcome = NULL`. This lifecycle state is deliberate: an in-progress attempt cannot honestly claim a terminal outcome.

`complete_source_attempt`:
1. Locks the attempt and request, and validates the exact request-attempt fencing token and unexpired lease.
2. Rejects stale/expired leases and invalid outcome-specific fields.
3. Validates evidence references as SHA-256-shaped hashes. This checks syntax only; it does **not** yet prove that evidence objects exist or that their contents match those hashes.
4. Sets `completed_at` and outcome in one update. Terminal rows cannot be updated or deleted; corrections must be new rows linked through `supersedes_attempt_id`.

Direct writes are not granted to `service_role`; write access is intended to flow through the fenced RPCs. The table has RLS enabled and no client-role grants.

## Outcome semantics (v1 contract)

| Outcome | Minimum proof | Result contribution |
|---|---|---|
| `succeeded` | Parse succeeded and at least one finding persisted/referenced | Completed source task; not by itself a whole-request success |
| `succeeded_empty` | Parse succeeded and finding count is exactly zero | Completed no-match contribution for this source scope |
| `partial_parse` | Parse succeeded for some content; caller records counts and evidence | Partial coverage |
| `source_unavailable` | A real attempt ended unavailable | Unavailable coverage |
| `source_rate_limited` | Provider throttling evidence, typically HTTP 429 | Unavailable coverage |
| `source_auth_failed` | Authentication/authorization failure | Platform/configuration incident; never a customer exposure claim |
| `parser_drift` | Selector/schema mismatch with `selector_miss = true` | Partial/unavailable coverage; never clean |
| `poisoned_input` | A defined detector classified input as adversarial | Policy/security incident; no unsupported findings promoted |
| `aborted_by_policy` | Explicit policy exclusion | Blocked, not partial coverage |
| `aborted_by_lease` | Lease was lost before useful completion | Does not count as completed coverage |

Attempt outcome is not the Result Contract disposition. A later contract aggregator must combine all declared source tasks, policy decisions, verified evidence and tenant authorization before it emits a customer-facing disposition.

## Important limits before merge/proof

- The live worker does not yet call these RPCs. Do not label the journal wired until every source execution path records an attempt and the request result is derived from read-back rows.
- The existing lease model does not issue a unique lease UUID. Do not fabricate one. A future lease migration should introduce a real lease identifier and monotonic fence if asset/source-level concurrency requires it.
- The idempotency key deliberately uses the request target as the current asset surrogate. Stable asset IDs and canonical target normalization must be resolved before making a cross-request asset-level idempotency claim.
- `evidence_refs` hashes are shape-checked only in this first slice. A subsequent evidence-binding RPC must verify referenced evidence records, tenant binding, content hashes and finding linkage before Result Contract issuance.
- `connector_version` and `parser_version` are caller-supplied identifiers at this stage. The runtime must bind them to the executing code/build before they can be considered attested.
- No historical attempts are backfilled from request JSON or logs. Those sources do not reliably establish a complete source-attempt history.
- No Phase 6–12 feature may claim a proven dependency until a registry records the exact test/run/evidence reference and its status.

## Required verification before production application

1. Apply the migration in an isolated database matching current migrations.
2. Exercise duplicate begin, mismatched idempotency, valid completion, duplicate completion, stale request attempt, expired lease, tenant resolution failure, forbidden direct write, terminal update/delete, and each outcome-specific constraint.
3. Confirm the journal table has no client-role privileges and that function execution is limited to the worker service role.
4. Wire one real source through worker → journal RPC → persisted finding/evidence → read-back → Result Contract, with authenticated tenant isolation.
5. Run Supabase security/performance advisors and retain the actual outputs.
6. Only then consider production migration approval and coordinated worker release. This PR does not apply the migration, deploy services, or activate collectors.
