# Kontrol engineering console and Railway recovery runbook

## Scope
The feature branch adds a read-only console at `/kontrol/engineering` and an API at `/api/kontrol/state`. It does not deploy, restart, change environment variables, apply migrations, or mutate production. Railway checks are intentionally deferred until the operator confirms the trial upgrade is complete.

## Server environment
Configure these on the console server runtime (Vercel project root `console`), never in `NEXT_PUBLIC_*` variables:

- `KONTROL_CONSOLE_TOKEN`: long random secret for the read-only console endpoint.
- `VERCEL_API_TOKEN`: least-privilege token able to inspect the existing project and deployments.
- `SUPABASE_ACCESS_TOKEN`: minimum Management API permissions needed to read project and migration metadata.
- `GITHUB_READ_TOKEN` (optional): read-only token to avoid anonymous API rate limits.

The page requests the console token for each session and does not persist it in browser storage. Do not reuse a provider credential as the console token. Rotate any token that has been exposed.

## Provider semantics and limitations
- GitHub: reads repository metadata and open PRs. The API's repository `pushed_at` is not a main branch SHA and must not be displayed as one.
- Vercel: reads up to five recent deployment records.
- Supabase: reads project metadata and migration records. Migration history alone does not establish schema parity.
- Railway: returned as `blocked`, source `operator_report`, and `liveChecked: false`, until the trial is upgraded. This is not a live health result.
- Provider checks are uncached and have an eight-second timeout. Missing credentials or errors result in `unknown`, never healthy.

## Railway verification after upgrade
Do not run this sequence until the operator confirms the plan is active and Railway access is restored.

1. Confirm project, production environment, and `cyclothone-api` service identity against the saved project handoff.
2. Read current service status and deployment history. Identify the latest successful deployment and active deployment separately.
3. Read build/deploy logs and runtime logs for the latest failed deployment. Preserve the original error and timestamp before proposing repair.
4. Check required environment variable names/presence without printing secret values.
5. Query the configured health endpoint with a short timeout and record status, response body (redacted if sensitive), and timestamp.
6. Correlate the running deployment commit with GitHub main and the Vercel deployment. Do not assume they share a commit.
7. Compare production migration history and schema/RPC/policy inventory against repository migrations. A migration ledger is not a full schema diff.
8. Propose a repair plan with rollback and verification criteria. No restart, redeploy, variable edit, or migration without explicit approval.

## Recovery release gate
Recovery is only verified when the service has a successful active deployment, the real health endpoint responds as expected, required dependencies are reachable, and logs show no continuing startup/runtime failure. A READY frontend deployment is not proof of API recovery.
