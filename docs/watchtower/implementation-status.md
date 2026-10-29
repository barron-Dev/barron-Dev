# Omni-Vision Watchtower — Implementation Status

## Product identity

- Core service: **Service 09 — AI Security**
- Commercial sub-service: **Omni-Vision Watchtower**
- Parent product/workstream: **Omni-Vision remains separate and continues independently** (CAM, FILE, AUDIO, DOC, ENV evidence modalities).
- Watchtower is a consumer of trusted edge observations and Omni-Vision evidence primitives, not a replacement for the existing Omni-Vision work.

## Real code currently present on the draft branch

- Deterministic loitering evaluation over timestamped tracker observations, with zone-change and missing-frame-gap resets.
- Explicit source coverage outcomes; missing source data cannot imply a clean result.
- Structured report payload contract that prohibits inferring a threat-free result from an empty event list.
- An FFmpeg RTSP/RTSPS reader that yields actual JPEG frames, hashes the original JPEG bytes, uses a one-frame latest-value queue, and bounds network I/O waits.
- Camera endpoint validation requiring RTSP/RTSPS, exact host allowlisting, and forbidding credentials/query tokens in endpoint URLs.
- Shutdown handling that avoids blocking forever when the bounded queue is full.

## Honest runtime boundary

The RTSP reader is code, not proof that a camera is connected. It has not been exercised against a client-authorized live camera in this change. It intentionally does not support credentials embedded in RTSP URLs. Production authenticated cameras require a reviewed credential broker/local proxy, plus network egress controls enforcing the camera allowlist. FFmpeg must be installed on the edge node. The stream reader is not yet wired to a camera registry, detector, durable persistence, authenticated API, or evidence journal.

This code does not yet perform ONVIF discovery/profile negotiation, detector/ByteTrack/pose inference, durable tenant-scoped persistence, signed event journaling, cross-service fusion, weather/sensor enrichment, report scheduling/rendering/delivery, or customer/developer/Kontrol UI integration.

## Non-negotiable correctness and safety rules

1. Only authenticated, tenant-bound edge observations may enter the production pipeline.
2. A source outage, frame gap, missing detector, or missing provider produces unavailable / partial coverage, never a clean bill of health.
3. Every finding must retain the original frame/media hash and traceable detector/runtime/configuration versions.
4. Report text is generated from versioned deterministic templates and validated variables, not free-form model narration.
5. Cross-service fusion must use authorized service APIs and preserve each source's provenance, timestamp, access decision, and coverage status. A lookup result is not proof of identity or guilt.
6. Face/plate matching, watchlists, law-enforcement queries, PTZ actions, and high-impact escalation require explicit customer authorization, lawful source access, audit trails, and human review. No autonomous accusation or enforcement action.
7. Camera credentials must remain out of client code, source control, logs, and command-line arguments. Camera network access must be restricted at the network layer; URL allowlisting alone is not a complete SSRF defense.
8. Report delivery, storage, and scheduling must be idempotent, tenant-isolated, retention-controlled, and evidence-signed before production use.

## Not yet production-ready

- Real-camera validation of FFmpeg ingest and authenticated camera credential brokering.
- ONVIF discovery and profile negotiation against real camera hardware.
- Actual detector/model artifact provisioning, license review, and hardware benchmarks.
- ByteTrack continuity and modality-specific pose/behavior evaluation with measured false-positive/negative rates.
- Durable tenant-scoped camera/site/zone/observation/event/report schema and restricted RPC/API path.
- Integration with existing Omni-Vision signed evidence contract and AI Action Verifier.
- Real weather/ambient sensor providers; no guessed context values.
- Authorized, source-specific surface-web / dark-web / threat-intelligence fusion; no unsupported Interpol or police-database access claims.
- ICU MessageFormat localization catalog and tested RTL/timezone/locale rendering.
- PDF/CSV report rendering, optional local speech output, and authenticated delivery adapters.
- Customer/Developer/Kontrol UI, observability, retention, deletion, failover and recovery.
- Real authenticated end-to-end tests with an authorized camera/site and independently reviewed safety/privacy controls.

## Release gates

Do not merge, deploy, provision production keys, change production schema, or enable camera/network access solely because unit tests pass. Release requires recovered migration history, tenant authorization review, live camera/model/provider validation, durable evidence and reports, cross-tenant and replay tests, operational alerts, and explicit deployment approval.
