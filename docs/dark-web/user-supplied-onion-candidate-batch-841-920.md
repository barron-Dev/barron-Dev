# User-supplied onion candidate batch (IDs 841–920)

Status: staged intake assessment only. This is not a live-source registry, not a verified threat finding, and not a production import.

## Batch summary

- Batch IDs: 841–920 inclusive (80 supplied rows).
- Rows with a title: 63.
- Rows with a reported fetch/connection error and no title: 17 (including connection failures, HTTP 403, and an SSL error).
- Reported BTC address arrays: empty in all supplied rows.
- BTC totals, transaction counts, and related numeric fields: blank in all supplied rows.
- Several entries repeat the same marketplace title across different onion hostnames. They must not be assumed to be distinct operators, active mirrors, or independently verified services.
- Titles/topics include alleged narcotics markets, stolen-funds/credential marketplaces, generic services, a search index, and other pages. Titles and topic labels are untrusted source metadata, not independently corroborated facts.

## Narcotics relevance

The supplied titles explicitly describe drug sales in at least two rows (IDs 843 and 897). These are candidate leads only. The provided data has no page-body evidence, capture timestamp, source citation, corroborating observation, or proof the sites are currently reachable. Do not raise a verified narcotics alert from a title alone.

## Integrity and evidence requirements

For every candidate retained in a private staging store, preserve:
- original row ID and source dataset/provenance;
- supplied title/topic as untrusted metadata;
- source collection time if available (not provided in this pasted batch);
- observed fetch outcome exactly as supplied;
- content hash and bounded, redacted evidence only after an authorized source check;
- validation status (candidate, unavailable, checked_no_match, match_unverified, or corroborated_match) with explicit semantics;
- last-checked time and collector/version for any future live check.

Never interpret a connection error, HTTP 403, or TLS error as a clean result or evidence that the host is malicious. Never infer BTC activity from empty address arrays or blank totals.

## Storage and release boundary

The repository is public. To avoid publishing a reusable list of potentially illicit-market endpoints or exposing operational targeting data, this document intentionally does not reproduce the onion URLs. Keep the raw batch in access-controlled private staging storage, with a documented lawful purpose, retention period, and authorized tenant/case mapping before any operational use. Do not add these candidates to a production queue, probe them, notify customers, or export findings to law enforcement until the owner has approved the specific authorized workflow and source policy.

## Next validation step

Validate the batch's provenance and collection timestamp; deduplicate exact hostnames and apparent mirrors in private staging; check whether the source's license permits this use; and then decide whether an authorized, bounded collector can perform current checks. A candidate record is not a completed source integration and does not count toward live dark-web coverage.
