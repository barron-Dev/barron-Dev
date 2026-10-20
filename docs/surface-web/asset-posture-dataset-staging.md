# Surface-web asset-posture dataset staging

## Purpose

The uploaded dataset is a candidate input for surface-web asset inventory and posture analysis. It is **not** an onion-source list and does not prove that Cyclothone performed a live check. The parser creates a normalized staging envelope only; it does not write to Supabase, create tenants, trigger scans, or deploy anything.

## Accepted data

The CSV must include the schema used by the uploaded asset-posture export: country, sector, organization ID, hashed domain, collection date, certificate/DNS/host/IP/mail observations, finding counts, and posture score. Country and sector are treated as supplied taxonomy labels, not proof of geographic or sector coverage. Organization IDs and domain hashes are retained as supplied; raw hostnames, URLs and IPs are neither required nor emitted.

## Safe staging command

From the repository root, after checking out this branch:

```bash
python scripts/stage_asset_posture_csv.py /path/to/dataset.csv --output /tmp/cyclothone-asset-posture-staging.json
```

Keep both the source CSV and generated output in an access-controlled local workspace. Do not commit customer or asset-level observations to the repository. The JSON envelope includes a content fingerprint for provenance and an identity fingerprint for deduplication/audit; it is not a signature or proof of source authenticity.

## Required review before operational integration

1. Confirm the dataset owner, collection method, permission to process it, and whether organization IDs map to real organizations or are anonymized.
2. Confirm the meaning and units of each count and posture score; independently validate any derived findings.
3. Treat certificate fallback rows as lower-confidence observations. The source-availability flags and collection date do not prove current reachability.
4. Map rows to a tenant only through an independently authorized mapping. Never infer tenant identity from country, sector, or IDs.
5. Store records in a dedicated tenant-scoped staging table with least-privilege access, provenance, retention, and audit fields before enabling any product workflow.
6. A separate authenticated live scan must create fresh evidence before the UI can claim an asset is currently checked or protected.

## Status vocabulary

- `staged_candidate`: parser accepted the row for review.
- `unverified_observation`: imported observation only; not a live check.
- `fallback_observation`: certificate lookup used a fallback path.
- `production_written=false`, `live_checks_claimed=false`, `coverage_claimed=false`: intentionally explicit until a separately reviewed persistence and verification path exists.
