# DW discovery queue RPC acceptance tests

These checks are release gates for the migration in this PR. They are not represented as passed until run against a disposable database with the same migrations and grants.

## Schema and permissions
- Apply both migrations to a disposable database.
- Verify the new lease columns and partial indexes exist.
- Verify queue CHECK constraints allow the new discovery kinds and the `completed` / `dead_letter` terminal states.
- Verify invalid/null outcomes, null job/token, non-object metadata, and metadata larger than 64 KiB are rejected.
- Verify expired leases at the retry cap are dead-lettered and cannot be reclaimed forever.
- Verify only `service_role` can execute `claim_dw_source_discovery_jobs` and `complete_dw_source_discovery_job`; `anon`, `authenticated`, and `public` must not execute them.
- Confirm the deployment's Postgres role has `gen_random_uuid()` available.

## Claim concurrency
1. Insert a small, uniquely tagged set of queued jobs in a disposable database.
2. Start two concurrent claims with small limits.
3. Assert no job ID appears in both claim responses.
4. Assert each claimed job has a distinct token, an expiry in the future, and incremented attempt count.
5. Assert invalid limits and lease durations are rejected.

## Fencing and retry
1. Claim one job and save its token.
2. Complete with the correct token while the lease is valid; expect true.
3. Attempt a second completion with the old token; expect false.
4. Claim another job, allow its lease to expire, reclaim it, and assert the first token cannot complete it.
5. Retry a job below the attempt limit; assert it returns to queued with a future retry time.
6. Retry at the attempt limit; assert dead_letter and a terminal timestamp.
7. Assert malformed/null outcomes, null identifiers/tokens, invalid retry settings, and oversized/non-object metadata are rejected.
8. Let a claimed job expire six times; assert the final expired lease becomes terminal `dead_letter` and is no longer claimed.

## Worker behavior
- A failed provider attempt must not be marked completed just because a page returned HTTP 200.
- Every outcome must include a bounded error code or provenance metadata, with secrets and raw personal data excluded.
- Redirects must be revalidated; public clearnet fetches must block private, loopback, link-local, and metadata addresses.
- Onion fetches must fail closed unless the configured Tor proxy is reachable and the hostname is a valid onion address.
- A retryable source error is retried with backoff; policy-excluded sources are never scheduled.
- Tenant evidence is written only by the authorized service path and remains tenant-scoped.
- Queue rows and candidate sources alone never increase live coverage metrics.

## Release result template
Record migration commit, database version, test command, test output, role used, and timestamp. If any check was not run, mark it NOT RUN rather than PASS.
