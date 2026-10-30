# Controlled Protective Intelligence — Phase 2

Phase 2 adds an assignment-bound protective-intelligence workflow inside Cyclothone. It does not create a standalone surveillance service.

## Security model

- Every assignment has a tenant, named purpose, region code, start/end timestamps, authorization reference hash, consent-evidence SHA-256, and pseudonymous subject-reference hash.
- Assignments are limited to 14 days and require two-person approval: the approver must be a different actor from the creator.
- No data is collected before approval and the assignment start time.
- Raw subject references, authorization references, and consent evidence are never persisted; only SHA-256 digests are stored.
- All data tables have RLS enabled and no direct `anon` or `authenticated` grants. Access is through authenticated API scopes and the server-side service client.
- Assignment events are append-only.
- Closing an assignment immediately deletes its regional threat matches and redacts assignment name, purpose, region and reference digests.
- An hourly `pg_cron` job runs `purge_expired_vip_data()` to delete regional matches and redact records after the assignment end time. This gives an hourly retention backstop; it is not a claim of sub-second deletion at the end timestamp.

## Correlation boundary

The correlation endpoint accepts IDs of tenant-owned Dark Web findings and reads their stored `source_metadata`. A finding qualifies only when its metadata contains:
- `region_code`: exact match to the approved assignment region;
- `observed_at`: timezone-aware ISO-8601 timestamp;
- `source_type`: one of `public_event`, `authorized_socmint`, or `adsb_flight`;
- `content_hash`: a valid SHA-256 hash from the existing finding record.

The time window is the assignment window expanded by 48 hours on either side. A match means only that an eligible public-source threat record and an authorized assignment share a region and time window. It does not prove targeting, intent, actor identity, proximity, or a physical threat. The API explicitly returns `confidence: not_assigned` and `intent_inference: false`.

This implementation deliberately does **not** ingest or retain precise personal coordinates, live GPS, flight paths, hotel check-ins, family associations, advertising IDs, private social content, or device location history. It does not use Haversine or a 50 km personal-location radius. Those would turn the service into an individual pattern-of-life tracker, which is outside the approved privacy boundary. Public threat intelligence remains source-bound and tenant-scoped.

## SOS boundary

`POST /api/v1/vip-protection/assignments/{id}/sos` creates a P1 incident record for an active assignment. It does not dispatch law enforcement, send a push notification, unlock/lock doors, or change cameras. It returns `dispatch_status: not_dispatched` and requires a human responder. Any future physical response must go through the existing response execution authority, explicit human approval, and device-side safety checks.

## API

All endpoints require a tenant-bound Cyclothone API credential and the indicated scope.

| Endpoint | Scope | Purpose |
|---|---|---|
| `POST /api/v1/vip-protection/assignments` | `vip:manage` | Create a pending assignment |
| `POST /api/v1/vip-protection/assignments/{id}/approve` | `vip:approve` | Independent second-person approval |
| `GET /api/v1/vip-protection/assignments` | `vip:read` | List tenant assignments |
| `POST /api/v1/vip-protection/assignments/{id}/correlate` | `vip:correlate` | Match tenant-owned public findings by region/time |
| `POST /api/v1/vip-protection/assignments/{id}/sos` | `vip:sos` | Raise a P1 human-response incident |
| `POST /api/v1/vip-protection/assignments/{id}/close` | `vip:manage` | Synchronously delete matches and redact assignment fields |
| `GET /api/v1/vip-protection/assignments/{id}/incidents` | `vip:read` | List assignment incidents |

## Deployment status

The migration is a proposal on the feature branch. It has not been applied to Supabase production. The hourly cron job, database tables, and RPCs are therefore not active yet. No external source ingestion, mobile push delivery, physical camera/door action, or law-enforcement dispatch is claimed as implemented.
