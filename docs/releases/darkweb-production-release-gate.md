# Cyclothone Dark Web — production release gate

This is the single release checklist for the request → provider → evidence → customer-result path. It does not authorize a production release by itself.

## Required coordinated release

1. Review the request lifecycle, attempt fencing, source policy, collector and customer-result changes together. Do not deploy the worker independently.
2. Verify the live migration chain and apply only after explicit production-release approval:
   - `20261009190000_darkweb_service_request_execution.sql`
   - `20261009200000_darkweb_completion_lease_guard.sql`
   - `20261010004200_darkweb_paste_feed_replacement.sql`
   - `20261010010000_darkweb_release_contract.sql`
   - `20261017120000_native_onion_source.sql`
   - `20261017150000_native_dw_honeytokens.sql`
   - `20261017180000_exclude_reddit_source.sql`
3. Confirm the live RPC catalog exposes exactly the fenced signature:
   `complete_service_request(uuid, integer, text, text, jsonb, text) returns boolean`.
   The unfenced five-argument signature must not remain.
4. Deploy the API/worker build containing the same `p_attempt` completion contract only after the migration chain has been reviewed and scheduled as one release.
5. Confirm the live worker can claim and sweep requests, collect from real configured sources, persist tenant-scoped findings/evidence, and complete requests through the fenced RPC using service-role credentials.
6. Confirm the deployed API source branch and commit match the approved release commit. A merge to GitHub `main` alone does not prove Railway is running it.
7. Submit one authorized test request for a target controlled by the tester. Verify state transitions, per-provider outcomes, tenant-scoped persisted evidence, and result retrieval by the same authenticated tenant.
8. Test successful zero-match, partial coverage, and all-sources-unavailable separately. Failed or unavailable sources must never be reported as clean.
9. Verify a stale worker attempt cannot overwrite a newer attempt, and a persistence failure cannot produce `succeeded`.
10. Capture request ID, migration versions, deployment SHA, source outcomes, finding/evidence IDs, and the authenticated customer-visible result. Never include secrets or exposed credentials.

## Approved source policy

- **Native Dark Web:** `native_onion` is the native dark-web collector. It is limited to explicitly configured public `.onion` URLs routed through a reachable Tor SOCKS proxy. It does not represent universal dark-web coverage.
- **Public surface web:** `telegram_public`, `pastebin_public`, and `bluesky_public` are public surface-web sources, not native dark-web sources.
- **Historical only:** `ransomwatch` historical records may inform review but never count as a fresh source check or current reachability.
- **Unavailable/planned:** `github_code` is not counted unless an actual supported search succeeds. A configured token does not prove the provider works.
- **Excluded:** Reddit and Have I Been Pwned (HIBP) are not approved collectors. Do not enable them, require their credentials, or count them in coverage. Preserve historical evidence without polling them.

## Server-side configuration

Values belong only in the hosting secret/configuration store; never commit or print secret values.

- `CYCLOTHONE_DW_ONION_SEEDS` — comma-separated, reviewed public `.onion` URLs. Invalid/non-onion URLs are rejected.
- `CYCLOTHONE_DW_ONION_PROXY` — reachable Tor SOCKS proxy URL. The default is `socks5://127.0.0.1:9050`; this only works when a Tor service is actually reachable at that address.
- `CYCLOTHONE_DW_TELEGRAM_CHANNELS` — reviewed public channel handles/previews; public previews do not require a Telegram token.
- Supabase URL and service-role key must be available to the worker under the existing platform variable names.
- Do not add HIBP variables. Do not rely on legacy `SENTINEL_*` configuration or branding.

Missing seeds, unavailable Tor, missing channel configuration, unsupported target types, provider errors, and timeouts must be recorded as unavailable/failed—not as checked.

## Source and result integrity

- Provider outcomes are request-specific: checked, unavailable, or failed. Historical-only and excluded sources never count as checked.
- `succeeded` means at least one approved source completed and every matched finding was durably persisted. It does not mean full coverage.
- Coverage is partial while any configured source is unavailable or failed. Show the actual source outcomes and real checked counts; never infer counts from global historical findings/alerts.
- A zero-match result is valid only for sources that actually completed a real check. It is not proof that the target has no exposure elsewhere.
- Every displayed finding must be backed by tenant-scoped persisted data with source attribution and observation time. Retain hashes/metadata as appropriate; do not retain raw page bodies or exposed credential material.
- A match is not proof of compromise. Present evidence and recommend human review.

## Release decision

Do not release while required CI is red, migration/RPC compatibility is unverified, Tor and source configuration are unknown, the API is on an unapproved branch, or authenticated customer E2E has not produced durable evidence. This checklist does not itself apply migrations, change secrets, merge code, or deploy/restart services.
