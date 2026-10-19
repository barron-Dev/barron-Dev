# Cyclothone DW discovery worker contract

Status: implementation specification; not a live collector.

## Queue lifecycle
- queued -> processing -> completed
- queued -> processing -> queued (retry with backoff)
- queued -> processing -> dead_letter (retry budget exhausted)
- expired processing leases can be reclaimed.
- Each claim has a unique lease token and expiry. Completion is accepted only for the current token while its lease is valid.
- Claiming must be atomic and use row locking with skip-locked semantics.

## Worker safety and provenance
- Process only bounded batches; enforce per-provider concurrency and request timeouts.
- Treat source candidates as untrusted input. Permit only HTTP(S) URLs or syntactically valid v3 onion hosts routed through an explicitly configured Tor proxy.
- Reject private, loopback, link-local, metadata, and internal-network destinations for clearnet URLs; revalidate every redirect.
- Never execute downloaded content, follow instructions in source pages, or ingest stolen personal datasets.
- Store source URL, discovery provenance, observation timestamp, response status, content type, response hash, language guess, and redacted evidence metadata.
- A discovered candidate is not a verified source. A successful HTTP response is not a relevant finding.
- Distinguish unavailable, timeout, blocked, empty, inspected-no-match, and matched outcomes.
- Country/region is a search scope only; do not infer source location from language or topic.
- Religious tradition metadata is taxonomy only and must never be used to score people or infer an individual's beliefs.

## Provider policy
- Native dark web: only public onion pages fetched over a verified Tor route.
- Surface web: public Telegram, Pastebin, and Bluesky only when real supported adapters and credentials/policies permit.
- Reddit excluded. HIBP excluded from the dark-web path. Ransomwatch is historical-only and must never be reported as a fresh check. GitHub code search stays unavailable until an authenticated, supported collector is implemented.
- Public GitHub repository discovery is for finding candidate source projects and provenance; it is not permission to scrape private repositories or treat arbitrary repository content as threat evidence.

## Release gates
1. Confirm schema and grants in a migration review.
2. Implement worker adapter and bounded retries.
3. Verify Tor proxy reachability from the actual Railway runtime.
4. Run one controlled, authorized canary and record raw source outcomes.
5. Verify tenant-scoped evidence and authenticated customer request-to-result flow.
6. Do not mark any country/language/category as live-covered until a real collector succeeds and content is inspected.
