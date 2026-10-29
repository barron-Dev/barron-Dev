# Omni-Vision Watchtower — Implementation Status

## Product identity

- Core service: **Service 09 — AI Security**
- Commercial sub-service: **Omni-Vision Watchtower**
- Parent product/workstream: **Omni-Vision remains separate and continues independently** (CAM, FILE, AUDIO, DOC, ENV evidence modalities).
- Watchtower is a consumer of trusted edge observations and Omni-Vision evidence primitives, not a replacement for the existing Omni-Vision work.

## Initial real implementation block

The first code block adds deterministic loitering evaluation over timestamped tracker observations, explicit stream-coverage outcomes, and a data-only report contract. The rule code does not pretend to ingest RTSP, discover ONVIF devices, run YOLO/ByteTrack/MediaPipe, query other Cyclothone services, or deliver reports. Those paths must be connected to real runtimes and tested against authorized infrastructure before being called operational.

## Non-negotiable correctness rules

1. Only authenticated, tenant-bound edge observations may enter the production pipeline.
2. A source outage, frame gap, missing detector, or missing provider produces unavailable / partial coverage, never a clean bill of health.
3. Every finding must retain the original frame/media hash and traceable detector/runtime/configuration versions.
4. Report text is generated from versioned deterministic templates and validated variables, not free-form model narration.
5. Cross-service fusion must use authorized service APIs and preserve each source's provenance, timestamp, access decision, and coverage status. A lookup result is not proof of identity or guilt.
6. Face/plate matching, watchlists, law-enforcement queries, PTZ actions, and any high-impact escalation require explicit customer authorization, lawful source access, audit trails, and human review. No autonomous accusation or enforcement action.
7. No camera credentials in client code, source control, logs, or report payloads. RTSP/ONVIF network access must be scoped to configured camera networks; do not accept arbitrary user-provided URLs from public APIs (SSRF boundary).
8. Report delivery, storage, and scheduling must be idempotent, tenant-isolated, retention-controlled, and evidence-signed before production use.

## Not yet production-ready

- ONVIF discovery and profile negotiation against real camera hardware.
- Credential-safe RTSP ingest and bounded producer/consumer frame queue.
- Actual detector/model artifact provisioning, license review, and hardware benchmarks.
- ByteTrack continuity and modality-specific pose/behavior evaluation with measured false-positive/negative rates.
- Durable tenant-scoped camera/site/zone/observation/event/report schema and restricted RPC/API path.
- Integration with the existing Omni-Vision signed evidence contract and AI Action Verifier.
- Real weather/ambient sensor providers; no guessed context values.
- Authorized, source-specific surface-web / dark-web / threat-intelligence fusion; no unsupported Interpol or police-database access claims.
- ICU MessageFormat localization catalog and tested RTL/timezone/locale rendering.
- PDF/CSV report rendering, optional local speech output, and authenticated delivery adapters.
- Customer/Developer/Kontrol UI, observability, retention, deletion, failover and recovery.
- Real authenticated end-to-end tests with an authorized camera/site and independently reviewed safety/privacy controls.

## Release gates

Do not merge, deploy, provision production keys, change production schema, or enable camera/network access solely because the pure rule tests pass. Release requires recovered migration history, tenant authorization review, live camera/provider validation, durable evidence and reports, cross-tenant and replay tests, operational alerts, and explicit deployment approval.
