# Cyclothone Dark Web — production release gate

This document is the single release checklist for the request → provider → evidence → customer-result path. It does not authorize a production release by itself.

## Required coordinated release

1. Review the open Dark Web lifecycle/fencing/source changes together; do not cherry-pick or deploy the worker independently.
2. Verify the migration chain in order:
   - `20261009190000_darkweb_service_request_execution.sql`
   - `20261009200000_darkweb_completion_lease_guard.sql`
   - `20261010004200_darkweb_paste_feed_replacement.sql`
   - `20261010010000_darkweb_release_contract.sql`
3. Confirm the live RPC catalog exposes exactly the fenced signature:
   `complete_service_request(uuid, integer, text, text, jsonb, text) returns boolean`.
   The unfenced five-argument signature must not remain.
4. Deploy the API/worker build containing the same `p_attempt` completion contract only after the migration has been reviewed and scheduled as one release.
5. Confirm the long-running worker is alive and can call `claim_service_requests`, `sweep_expired_service_requests`, `record_dw_finding`, and the fenced completion RPC using service-role credentials.
6. Submit one authorized test request for a target controlled by the tester. Verify request state transitions, each provider's real status, persisted tenant-scoped findings/evidence, and customer result retrieval using the same authenticated tenant.
7. Test a successful zero-match case separately from all-sources-unavailable and partial-coverage cases. Never convert failed/unavailable source checks into a clean result.
8. Verify a stale worker attempt cannot overwrite a newer attempt; verify a provider persistence error cannot result in `succeeded`.
9. Capture the request ID, migration version, deployment SHA, source status rows, finding/evidence IDs, and customer-visible result as release evidence. Do not include provider secrets or exposed credentials.

## Provider configuration

Required server-side environment variable names (values are managed only in the hosting secret store):
- `CYCLOTHONE_HIBP_KEY` — Have I Been Pwned API key.
- `CYCLOTHONE_GITHUB_TOKEN` — GitHub token for code search, with only the required read/search scope.
- `CYCLOTHONE_DW_TELEGRAM_CHANNELS` — comma-separated public channel names; no token is required for public previews.
- Supabase service-role URL/key must be available to the worker using the existing platform's secret names.

Legacy `SENTINEL_*` fallbacks are temporary compatibility only. Prefer the `CYCLOTHONE_*` names and remove legacy branding/config after migration. Never commit secrets or print their values in logs. If a provider credential is absent, report `unavailable: missing_key`; do not represent that provider as checked.

## Source and result integrity

- Provider status is per request: checked, unavailable (disabled/missing key/missing channel/unsupported target), or failed (request error/timeout).
- `succeeded` means at least one provider returned successfully and all matched findings were durably persisted. It does not mean full coverage.
- `coverage` must not be described as complete while any configured provider was unavailable or failed.
- A successful zero-match result is valid only if at least one source was actually checked.
- Every displayed finding must be backed by tenant-scoped persisted data. Evidence shows source, observation time, source URL when provided, and content hash; no paste body or credential secret is retained.
- A match is not proof of account compromise. Present provider attribution and evidence and recommend human review.

## Release decision

Do not release while required CI is red, the live migration/RPC signature is unverified, provider configuration is unknown, or an authenticated customer E2E test has not produced durable evidence. This checklist does not itself apply migrations, change secrets, merge code, or deploy services.
