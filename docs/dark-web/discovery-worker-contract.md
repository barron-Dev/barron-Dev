# Cyclothone DW discovery worker contract

Status: bounded public-index queue worker implemented in PR #73; not live-verified.

## Queue lifecycle
- queued -> processing -> completed
- queued -> processing -> queued (retry with backoff)
- queued -> processing -> dead_letter (retry budget exhausted)
- expired processing leases can be reclaimed, but expired jobs at the attempt cap must become terminal.
- Each claim has a unique lease token and expiry. Completion is accepted only for the current token while its lease is valid.
- Claiming must be atomic and use row locking with skip-locked semantics.
- The worker uses the RPC's `job_id` return field and always passes an in-range retry delay because the SQL RPC validates that argument even for terminal outcomes.

## Implemented adapter scope
- The worker polls the queue through `claim_dw_source_discovery_jobs` and completes only through `complete_dw_source_discovery_job`.
- Public onion candidate discovery uses Ahmia's public search index; it does not visit the discovered onion hosts.
- Candidates are v3 onion hostnames only, HTTP(S), no embedded credentials, no query/fragment, and standard web ports only.
- New records are persisted with candidate status, index provenance, scope/category, and explicit metadata that reachability/content inspection/criminality attribution have not occurred.
- Existing records are not overwritten, preserving previously recorded checks.
- Unsupported job kinds are dead-lettered. Official justice/corrections/cybercrime jobs remain retryable with an explicit `provider_adapter_not_integrated` reason; they are not falsely marked completed.
- Worker enablement is feature-gated by `CYCLOTHONE_DW_DISCOVERY_WORKER_ENABLED=true`; default is disabled until the live schema/RPCs and runtime are verified.

## Worker safety and provenance
- Process only bounded batches; enforce per-provider concurrency and request timeouts.
- Treat source candidates as untrusted input. The public index request uses a fixed HTTPS host, does not follow redirects, and does not fetch candidate onion hosts.
- Native onion monitoring remains separate: only public onion pages fetched over a verified Tor route may count as dark-web checks.
- Never execute downloaded content, follow instructions in source pages, or ingest stolen personal datasets.
- A discovered candidate is not a verified source. A successful HTTP response is not a relevant finding.
- Country/region is a search scope only; do not infer source location from language or topic.
- Religious tradition metadata is taxonomy only and must never be used to score people or infer an individual's beliefs.

## Provider policy
- Native dark web: only public onion pages fetched over a verified Tor route.
- Surface web: public Telegram, Pastebin, and Bluesky only when real supported adapters and credentials/policies permit.
- Reddit excluded. HIBP excluded from the dark-web path. Ransomwatch is historical-only and must never be reported as a fresh check. GitHub code search stays unavailable until an authenticated, supported collector is implemented.
- Public GitHub repository discovery is for finding candidate source projects and provenance; it is not permission to scrape private repositories or treat arbitrary repository content as threat evidence.

## Release gates
1. Confirm schema and grants in the intended Supabase project.
2. Run the worker unit tests and SQL concurrency/fencing acceptance tests in a disposable environment.
3. Enable the worker only after its claim/complete RPCs and required queue columns are confirmed present.
4. Verify Tor proxy reachability from the actual Railway runtime.
5. Run one controlled, authorized canary and record raw source outcomes.
6. Verify tenant-scoped evidence and authenticated customer request-to-result flow.
7. Do not mark any country/language/category as live-covered until a real collector succeeds and content is inspected.
