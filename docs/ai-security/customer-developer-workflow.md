# AI Security workflow integration — bulk block

## Product boundary
AI Security is the parent service. It hosts existing AI-assisted security capabilities and dedicated AI services; it does not replace their data planes or authorization checks. Customer and developer experiences use the same tenant-bound API contracts, with developer diagnostics restricted by the backend's developer role/scope.

## Current branch integration
- Customer workflow entry: `/customer/services/ai-security`
- Developer workflow entry: `/developer/services/ai-security`
- Both entries show the same AI Security capability map and link to the same authenticated Watchtower camera registry/probe/history API. They do not synthesize camera state, detections, models, provider availability, or results.
- Watchtower API is mounted under `/api/v1/watchtower`; routes enforce `watchtower:read` / `watchtower:manage` and tenant filters.
- Live capability status is presented as **not verified** until a real API call proves it. A missing route, missing scope, empty response, or unavailable provider must not be represented as healthy/clean.
- AI Action Verifier (#94) and Omni-Vision (#95) remain separate workstreams. This page links to the capabilities conceptually but does not claim those PRs are deployed or production-wired.

## Capability map
1. AI security governance and model/provider routing
2. AI execution and orchestration
3. AI Action Verification and signed action evidence
4. Watchtower physical/visual security — camera registry, probe evidence and history
5. Omni-Vision media evidence (separate PR/workstream)
6. Threat attribution and scam/brand/dark-web correlation through existing services
7. Evidence journal, provenance, audit and tenant isolation
8. Security investigation and human-approved response

## Release boundary
This block is source-code wiring only. It does not merge or deploy, apply Supabase migrations, provision provider keys, invent a detector/model, or claim real camera/model E2E. Production activation requires reconciled migration history, validated schema, real provider/model configuration, authorized camera testing, durable evidence/key custody, role/tenant isolation tests, and authenticated end-to-end verification.
